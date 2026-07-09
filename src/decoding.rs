use std::io::Cursor;

use log::{debug, info, trace, warn};

pub use crate::stream::compress::decompress_buffer as decompress;
pub use crate::stream::decode::{stream_decode_buffer, stream_decode_outboard_buffer};

use crate::{
    constants::{Format, FEC_K, FEC_M},
    encoding,
    error::CarbonadoError,
    stream::{extract_slice_inboard_for_scrub, verify_slice_inboard_seekable},
    structs::EncodeInfo,
    utils::decode_bao_hash,
};

use reed_solomon_erasure::galois_8::Field;
use reed_solomon_erasure::ReedSolomon;

use crate::constants::SLICE_LEN;

fn fec_chunks(chunked_bytes: &[(usize, &[u8])], padding: u32) -> Result<Vec<u8>, CarbonadoError> {
    let data_shards = FEC_K;
    let parity_shards = FEC_M - FEC_K;
    let total_shards = FEC_M;

    let shard_size = if let Some((_, first)) = chunked_bytes.iter().find(|(_, c)| !c.is_empty()) {
        first.len()
    } else if !chunked_bytes.is_empty() {
        chunked_bytes[0].1.len()
    } else {
        return Err(CarbonadoError::UnevenFecChunks);
    };

    let mut shards: Vec<Option<Vec<u8>>> = vec![None; total_shards];
    for &(idx, data) in chunked_bytes {
        if idx < total_shards && !data.is_empty() {
            shards[idx] = Some(data.to_vec());
        }
    }
    for d in shards.iter().flatten() {
        if d.len() != shard_size {
            return Err(CarbonadoError::UnevenFecChunks);
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

pub fn verification_with_outboard(
    bare: &[u8],
    outboard: &[u8],
    hash: &[u8],
    format: u8,
) -> Result<Vec<u8>, CarbonadoError> {
    trace!("verifying bare data with outboard sidecar (keyed 4KB bao-tree)");
    if bare.is_empty() && outboard.is_empty() {
        return Ok(vec![]);
    }
    crate::stream::bao::stream_verification_outboard_verify(
        bare,
        bare.len() as u64,
        outboard,
        hash,
        format,
    )?;
    Ok(bare.to_vec())
}

/// Outboard FEC recovery from bare main + `.par` parity (public API).
#[allow(dead_code)] // integration tests + direct callers; streaming path uses `stream::fec`
pub fn fec_with_parity(
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
        return Err(CarbonadoError::UnevenFecChunks);
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

pub fn fec(input: &[u8], padding: u32) -> Result<Vec<u8>, CarbonadoError> {
    trace!("forward error correcting (reed-solomon)");
    if input.is_empty() {
        return Ok(vec![]);
    }
    let input_len = input.len();
    #[allow(clippy::manual_is_multiple_of)]
    if input_len % FEC_M != 0 {
        return Err(CarbonadoError::UnevenFecChunks);
    }
    let chunk_len = input_len / FEC_M;
    let chunks: Vec<(usize, &[u8])> = input.chunks_exact(chunk_len).enumerate().collect();
    fec_chunks(&chunks, padding)
}

pub fn verification(input: &[u8], hash: &[u8], format: u8) -> Result<Vec<u8>, CarbonadoError> {
    trace!("verifying (bao-tree 4KB keyed)");
    let content_len = crate::stream::bao::inboard_bao_content_len_prefix(input)?;
    let mut logical = crate::stream::fec::LogicalBufferWriteAt::new(content_len);
    crate::stream::bao::stream_verification_inboard_decode_with_len(
        Cursor::new(&input[8..]),
        content_len,
        hash,
        format,
        &mut logical,
    )?;
    logical.into_inner()
}

/// S5 scrub-entry oracle (integration-test hook).
#[doc(hidden)]
pub fn verify_inboard_keyed_oracle(
    input: &[u8],
    hash: &[u8],
    format: u8,
) -> Result<(), CarbonadoError> {
    crate::stream::bao::verify_inboard_keyed(input, hash, format)
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
    verification_outboard: Option<&[u8]>,
    fec_parity: Option<&[u8]>,
    padding: u32,
    format: u8,
) -> Result<Vec<u8>, CarbonadoError> {
    stream_decode_outboard_buffer(
        master_key,
        hash,
        main,
        verification_outboard,
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

/// Recover a damaged inboard Bao+FEC archive via RS subset search and re-encode oracle.
///
/// **Scrub entry:** all [`verify_inboard_keyed`] failures (`AuthenticationFailed`,
/// `InvalidHeaderLength`, `BaoResponseTruncated`, `StdIoError`, etc.) route into combinatorial
/// FEC recovery — the API does not distinguish tamper from truncation before attempting recovery.
/// Pristine archives return [`CarbonadoError::UnnecessaryScrub`].
pub fn scrub(
    input: &[u8],
    hash: &[u8],
    encode_info: &EncodeInfo,
    format: u8,
) -> Result<Vec<u8>, CarbonadoError> {
    let fmt = Format::from(format);
    if !fmt.contains(Format::Verification) {
        return Err(CarbonadoError::ScrubRequiresVerification);
    }
    let hash = decode_bao_hash(hash)?;
    let chunk_size = encode_info.chunk_len;
    let padding = encode_info.padding_len;
    let slices_per_chunk = chunk_size / SLICE_LEN;

    // S5: slice-bounded keyed Bao verify oracle — no O(decoded) body staging on scrub entry.
    match crate::stream::bao::verify_inboard_keyed(input, hash.as_bytes(), format) {
        Ok(()) => Err(CarbonadoError::UnnecessaryScrub),
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
                if let Ok(cand_inner) = fec_chunks(&sel, padding) {
                    let (scrubbed, sp, _) = encoding::encode_inboard_buffer(&cand_inner)?;
                    if sp != padding {
                        continue;
                    }
                    if let Ok((verif, got_h)) =
                        encoding::verification_inboard_buffer(&scrubbed, format)
                    {
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
    verification_outboard: Option<&[u8]>,
    fec_parity: Option<&[u8]>,
    encode_info: &EncodeInfo,
    format: u8,
    hash: &[u8],
) -> Result<Vec<u8>, CarbonadoError> {
    let fmt = Format::from(format);
    if !fmt.contains(Format::Verification) {
        return Err(CarbonadoError::ScrubRequiresVerification);
    }

    let good = if let Some(ob) = verification_outboard {
        crate::stream::bao::stream_verification_outboard_verify(
            bare,
            bare.len() as u64,
            ob,
            hash,
            format,
        )
        .is_ok()
    } else {
        return Err(CarbonadoError::MissingVerificationOutboard);
    };

    if good {
        return Err(CarbonadoError::UnnecessaryScrub);
    }

    let padding = encode_info.padding_len;
    let recovered_bare = if fmt.contains(Format::Fec) {
        let Some(ob) = verification_outboard else {
            return Err(CarbonadoError::MissingVerificationOutboard);
        };
        let Some(par) = fec_parity else {
            return Err(CarbonadoError::MissingFecParity);
        };

        // Encode-time geometry (parity sidecar + EncodeInfo), not calc_padding_len(bare.len()).
        let shard_len = encode_info.chunk_len as usize;
        if shard_len == 0 {
            return Err(CarbonadoError::UnevenFecChunks);
        }
        let parity_shards = FEC_M - FEC_K;
        if !par.len().is_multiple_of(shard_len) || par.len() / shard_len != parity_shards {
            return Err(CarbonadoError::UnevenFecChunks);
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
            if let Ok(cand_inner) = fec_chunks(&sel, padding) {
                if verification_with_outboard(&cand_inner, ob, hash, format).is_ok() {
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
