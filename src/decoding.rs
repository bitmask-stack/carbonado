use std::io::Cursor;

use log::{debug, info, trace, warn};

pub use crate::stream::compress::decompress_buffer as decompress;
pub use crate::stream::decode::{stream_decode_buffer, stream_decode_outboard_buffer};

use crate::{
    constants::{Format, FEC_K, FEC_M},
    encoding,
    error::CarbonadoError,
    stream::{extract_slice_inboard_for_scrub, map_decode_error, verify_slice_inboard_seekable},
    structs::EncodeInfo,
    utils::decode_bao_hash,
};

// Keep zfec_chunks and bao helpers used by scrub + outboard verify
use bao_tree::{
    io::{outboard::EmptyOutboard, sync::keyed_decode_ranges},
    ChunkRanges,
};
use reed_solomon_erasure::galois_8::Field;
use reed_solomon_erasure::ReedSolomon;

use crate::constants::{BAO_BLOCK_SIZE, SLICE_LEN};

fn zfec_chunks(chunked_bytes: &[(usize, &[u8])], padding: u32) -> Result<Vec<u8>, CarbonadoError> {
    let data_shards = FEC_K;
    let parity_shards = FEC_M - FEC_K;
    let total_shards = FEC_M;

    let shard_size = if let Some((_, first)) = chunked_bytes.iter().find(|(_, c)| !c.is_empty()) {
        first.len()
    } else if !chunked_bytes.is_empty() {
        chunked_bytes[0].1.len()
    } else {
        return Err(CarbonadoError::UnevenZfecChunks);
    };

    let mut shards: Vec<Option<Vec<u8>>> = vec![None; total_shards];
    for &(idx, data) in chunked_bytes {
        if idx < total_shards && !data.is_empty() {
            shards[idx] = Some(data.to_vec());
        }
    }
    for d in shards.iter().flatten() {
        if d.len() != shard_size {
            return Err(CarbonadoError::UnevenZfecChunks);
        }
    }

    let rs = ReedSolomon::<Field>::new(data_shards, parity_shards)?;
    rs.reconstruct(&mut shards)?;

    let mut decoded = vec![];
    for sh in shards.iter().take(data_shards) {
        if let Some(ref s) = sh {
            decoded.extend_from_slice(s);
        } else {
            decoded.resize(decoded.len() + shard_size, 0);
        }
    }

    if padding as usize > decoded.len() {
        return Err(CarbonadoError::ScrubbedLengthMismatch(
            decoded.len(),
            padding as usize,
        ));
    }
    decoded.truncate(decoded.len() - padding as usize);
    Ok(decoded)
}

pub fn bao_with_outboard(
    bare: &[u8],
    outboard: &[u8],
    hash: &[u8],
    format: u8,
) -> Result<Vec<u8>, CarbonadoError> {
    trace!("verifying bare data with outboard sidecar (keyed 4KB bao-tree)");
    if bare.is_empty() && outboard.is_empty() {
        return Ok(vec![]);
    }
    crate::stream::bao::stream_bao_outboard_verify(
        bare,
        bare.len() as u64,
        outboard,
        hash,
        format,
    )?;
    Ok(bare.to_vec())
}

pub fn zfec_with_parity(
    input: &[u8],
    parity: &[u8],
    padding: u32,
) -> Result<Vec<u8>, CarbonadoError> {
    trace!("forward error correcting from bare + parity sidecar (reed-solomon outboard)");
    if input.is_empty() && parity.is_empty() {
        return Ok(vec![]);
    }
    let parity_shards = FEC_M - FEC_K;
    if !parity.len().is_multiple_of(parity_shards) {
        return Err(CarbonadoError::UnevenZfecChunks);
    }
    let shard_len = parity.len() / parity_shards;
    let padded_total = shard_len * FEC_K;
    let pad = padding as usize;
    if pad > padded_total {
        return Err(CarbonadoError::ScrubbedLengthMismatch(padded_total, pad));
    }
    // Logical length from parity stripe geometry + encode-time padding (not truncated main len).
    let logical_len = padded_total - pad;

    // Stripe geometry comes from the parity sidecar (encode-time chunk_len), not truncated main len.
    let mut padded = vec![0u8; padded_total];
    let copy = input.len().min(logical_len);
    padded[..copy].copy_from_slice(&input[..copy]);

    let mut shards: Vec<Option<Vec<u8>>> = vec![None; FEC_M];
    for (i, sh) in shards.iter_mut().enumerate().take(FEC_K) {
        let start = i * shard_len;
        let end = start + shard_len;
        if end <= copy {
            *sh = Some(padded[start..end].to_vec());
        } else {
            // Truncated or missing data column — erasure; RS reconstructs from parity.
            *sh = None;
        }
    }
    for j in 0..parity_shards {
        let start = j * shard_len;
        let end = start + shard_len;
        shards[FEC_K + j] = Some(parity[start..end].to_vec());
    }

    let rs = ReedSolomon::<Field>::new(FEC_K, FEC_M - FEC_K)?;
    rs.reconstruct(&mut shards)?;

    let mut decoded = vec![];
    for sh in shards.iter().take(FEC_K) {
        if let Some(ref s) = sh {
            decoded.extend_from_slice(s);
        } else {
            decoded.resize(decoded.len() + shard_len, 0);
        }
    }

    if decoded.len() < logical_len {
        return Err(CarbonadoError::ScrubbedLengthMismatch(
            decoded.len(),
            logical_len,
        ));
    }
    decoded.truncate(logical_len);
    Ok(decoded)
}

pub fn zfec(input: &[u8], padding: u32) -> Result<Vec<u8>, CarbonadoError> {
    trace!("forward error correcting (reed-solomon)");
    if input.is_empty() {
        return Ok(vec![]);
    }
    let input_len = input.len();
    #[allow(clippy::manual_is_multiple_of)]
    if input_len % FEC_M != 0 {
        return Err(CarbonadoError::UnevenZfecChunks);
    }
    let chunk_len = input_len / FEC_M;
    let chunks: Vec<(usize, &[u8])> = input.chunks_exact(chunk_len).enumerate().collect();
    zfec_chunks(&chunks, padding)
}

pub fn bao(input: &[u8], hash: &[u8], format: u8) -> Result<Vec<u8>, CarbonadoError> {
    trace!("verifying (bao-tree 4KB keyed)");
    if input.len() < 8 {
        return Err(CarbonadoError::InvalidHeaderLength);
    }
    let clen_bytes: [u8; 8] = input[0..8]
        .try_into()
        .map_err(|_| CarbonadoError::InvalidHeaderLength)?;
    let content_len = u64::from_le_bytes(clen_bytes);
    let response = &input[8..];
    let root = decode_bao_hash(hash)?;
    let tree = bao_tree::BaoTree::new(content_len, BAO_BLOCK_SIZE);
    let key = crate::crypto::carbonado_bao_key(format);
    let mut ob = EmptyOutboard { tree, root };
    let mut decoded = Vec::new();
    keyed_decode_ranges(
        Cursor::new(response),
        &ChunkRanges::all(),
        &mut decoded,
        &mut ob,
        &key,
    )
    .map_err(map_decode_error)?;
    Ok(decoded)
}

pub fn decode(
    master_key: &[u8],
    hash: &[u8],
    input: &[u8],
    padding: u32,
    format: u8,
) -> Result<Vec<u8>, CarbonadoError> {
    stream_decode_buffer(master_key, hash, input, padding, format)
}

pub fn decode_outboard(
    master_key: &[u8],
    hash: &[u8],
    main: &[u8],
    bao_outboard: Option<&[u8]>,
    fec_parity: Option<&[u8]>,
    padding: u32,
    format: u8,
) -> Result<Vec<u8>, CarbonadoError> {
    stream_decode_outboard_buffer(
        master_key,
        hash,
        main,
        bao_outboard,
        fec_parity,
        padding,
        format,
        None,
    )
}

pub fn extract_slice(
    encoded: &[u8],
    index: u32,
    hash: &[u8],
    format: u8,
) -> Result<Vec<u8>, CarbonadoError> {
    verify_slice(encoded, index, 1, hash, format)
}

pub fn verify_slice(
    input: &[u8],
    index: u32,
    count: u32,
    hash: &[u8],
    format: u8,
) -> Result<Vec<u8>, CarbonadoError> {
    trace!("verify_slice seekable index={index} count={count} format=0x{format:02x}");
    verify_slice_inboard_seekable(input, index, count, hash, format)
}

pub fn scrub(
    input: &[u8],
    hash: &[u8],
    encode_info: &EncodeInfo,
    format: u8,
) -> Result<Vec<u8>, CarbonadoError> {
    let fmt = Format::from(format);
    if !fmt.contains(Format::Bao) {
        return Err(CarbonadoError::ScrubRequiresBao);
    }
    let hash = decode_bao_hash(hash)?;
    let chunk_size = encode_info.chunk_len;
    let padding = encode_info.padding_len;
    let slices_per_chunk = chunk_size / SLICE_LEN;

    match bao(input, hash.as_bytes(), format) {
        Ok(_decoded) => Err(CarbonadoError::UnnecessaryScrub),
        Err(e) => {
            warn!("Data failed to verify with error: {e}. Scrubbing...");
            let mut chunks: Vec<(usize, Vec<u8>)> = vec![];

            for i in 0..FEC_M {
                let slice_index = (i as u32) * slices_per_chunk;
                match extract_slice_inboard_for_scrub(input, slice_index, slices_per_chunk) {
                    Ok(chunk) if chunk.len() == chunk_size as usize => chunks.push((i, chunk)),
                    Ok(_) => debug!("Chunk {i} wrong length after seekable slice extract"),
                    Err(e) => {
                        debug!("At least one chunk was bad, at chunk index {i}. Error was: {e}.")
                    }
                }
            }

            info!(
                "{} candidate chunks extracted, of {FEC_K} needed.",
                chunks.len()
            );

            let mut recovered: Option<Vec<u8>> = None;
            let n = chunks.len();
            for mask in 0..(1usize << n) {
                if mask.count_ones() < FEC_K as u32 {
                    continue;
                }
                let mut sel: Vec<(usize, &[u8])> = vec![];
                for (j, c) in chunks.iter().enumerate().take(n) {
                    if (mask & (1 << j)) != 0 {
                        sel.push((c.0, &c.1));
                    }
                }
                if let Ok(cand_inner) = zfec_chunks(&sel, padding) {
                    let (scrubbed, sp, _) = encoding::encode_inboard_buffer(&cand_inner)?;
                    if sp != padding {
                        continue;
                    }
                    if let Ok((verif, got_h)) = encoding::bao_inboard_buffer(&scrubbed, format) {
                        if got_h == hash && verif.len() == input.len() {
                            recovered = Some(verif);
                            break;
                        }
                    }
                }
            }

            match recovered {
                Some(v) => Ok(v),
                None => Err(CarbonadoError::InvalidScrubbedHash),
            }
        }
    }
}

pub fn scrub_outboard(
    bare: &[u8],
    bao_outboard: Option<&[u8]>,
    fec_parity: Option<&[u8]>,
    encode_info: &EncodeInfo,
    format: u8,
    hash: &[u8],
) -> Result<Vec<u8>, CarbonadoError> {
    let fmt = Format::from(format);
    if !fmt.contains(Format::Bao) {
        return Err(CarbonadoError::ScrubRequiresBao);
    }

    let good = if let Some(ob) = bao_outboard {
        bao_with_outboard(bare, ob, hash, format).is_ok()
    } else {
        return Err(CarbonadoError::MissingBaoOutboard);
    };

    if good {
        return Err(CarbonadoError::UnnecessaryScrub);
    }

    let padding = encode_info.padding_len;
    let recovered_bare = if fmt.contains(Format::Zfec) {
        let Some(ob) = bao_outboard else {
            return Err(CarbonadoError::MissingBaoOutboard);
        };
        let Some(par) = fec_parity else {
            return Err(CarbonadoError::MissingFecParity);
        };

        // Encode-time geometry (parity sidecar + EncodeInfo), not calc_padding_len(bare.len()).
        let shard_len = encode_info.chunk_len as usize;
        if shard_len == 0 {
            return Err(CarbonadoError::UnevenZfecChunks);
        }
        let parity_shards = FEC_M - FEC_K;
        if !par.len().is_multiple_of(shard_len) || par.len() / shard_len != parity_shards {
            return Err(CarbonadoError::UnevenZfecChunks);
        }
        let padded_total = shard_len * FEC_K;
        let pad = padding as usize;
        if pad > padded_total {
            return Err(CarbonadoError::ScrubbedLengthMismatch(padded_total, pad));
        }
        let logical_len = padded_total - pad;
        let copy = bare.len().min(logical_len);

        let mut padded = vec![0u8; padded_total];
        padded[..copy].copy_from_slice(&bare[..copy]);

        let mut chunks: Vec<(usize, Vec<u8>)> = vec![];
        for i in 0..FEC_K {
            let start = i * shard_len;
            let end = start + shard_len;
            if end <= copy {
                chunks.push((i, padded[start..end].to_vec()));
            }
        }
        for j in 0..parity_shards {
            let start = j * shard_len;
            chunks.push((FEC_K + j, par[start..start + shard_len].to_vec()));
        }

        let n = chunks.len();
        let mut recovered: Option<Vec<u8>> = None;
        for mask in 0..(1usize << n) {
            if mask.count_ones() < FEC_K as u32 {
                continue;
            }
            let mut sel: Vec<(usize, &[u8])> = vec![];
            for (j, c) in chunks.iter().enumerate().take(n) {
                if (mask & (1 << j)) != 0 {
                    sel.push((c.0, &c.1));
                }
            }
            if let Ok(cand_inner) = zfec_chunks(&sel, padding) {
                if bao_with_outboard(&cand_inner, ob, hash, format).is_ok() {
                    recovered = Some(cand_inner);
                    break;
                }
            }
        }

        match recovered {
            Some(v) => v,
            None => return Err(CarbonadoError::InvalidScrubbedHash),
        }
    } else {
        return Err(CarbonadoError::InvalidScrubbedHash);
    };

    Ok(recovered_bare)
}
