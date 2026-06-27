use std::io::{Cursor, Read};

// ecies removed (clean break from ECIES v1)
use bao_tree::{
    io::{outboard::EmptyOutboard, sync::keyed_decode_ranges},
    iter::BaoChunk,
    ChunkRanges,
};
use log::{debug, info, trace, warn};
use reed_solomon_erasure::galois_8::Field;
use reed_solomon_erasure::ReedSolomon;


use crate::{
    constants::{Format, BAO_BLOCK_SIZE, FEC_K, FEC_M, SLICE_LEN},
    encoding,
    error::CarbonadoError,
    structs::EncodeInfo,
    utils::decode_bao_hash,
};

fn zfec_chunks(
    chunked_bytes: Vec<(usize, Vec<u8>)>,
    padding: u32,
) -> Result<Vec<u8>, CarbonadoError> {
    // RS path (deterministic): use provided (index, data) for good shards.
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
    for (idx, data) in chunked_bytes {
        if idx < total_shards && !data.is_empty() {
            shards[idx] = Some(data);
        }
    }
    // Uniform length pre-check (mixed partial extracts from scrub could otherwise reach RS).
    for d in shards.iter().flatten() {
        if d.len() != shard_size {
            return Err(CarbonadoError::UnevenZfecChunks);
        }
    }

    let rs = ReedSolomon::<Field>::new(data_shards, parity_shards)?; // uses From for FecError

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

/// Zfec forward error correction decoding (reed-solomon-erasure)
pub fn zfec(input: &[u8], padding: u32) -> Result<Vec<u8>, CarbonadoError> {
    trace!("forward error correcting (reed-solomon)");
    if input.is_empty() {
        // 0-len FEC body (from empty input) -> empty after trim
        return Ok(vec![]);
    }
    let input_len = input.len();

    #[allow(clippy::manual_is_multiple_of)]
    if input_len % FEC_M != 0 {
        return Err(CarbonadoError::UnevenZfecChunks);
    }

    let chunks: Vec<(usize, Vec<u8>)> = input
        .chunks_exact(input_len / FEC_M)
        .enumerate()
        .map(|(i, c)| (i, c.to_owned()))
        .collect();

    let decoded = zfec_chunks(chunks, padding)?;

    Ok(decoded)
}

/// Bao stream extraction (verified) using bao-tree 4KB keyed groups.
///
/// `input` must be the Carbonado bao wrapper: [u64le content_len | response_bytes]
/// The root `hash` is verified via keyed decode using format-derived key.
pub fn bao(input: &[u8], hash: &[u8], format: u8) -> Result<Vec<u8>, CarbonadoError> {
    trace!("verifying (bao-tree 4KB keyed)");
    if input.len() < 8 {
        return Err(CarbonadoError::StdIoError(std::io::Error::other(
            "bao input too short",
        )));
    }
    let clen_bytes: [u8; 8] = input[0..8]
        .try_into()
        .map_err(|_| CarbonadoError::InvalidHeaderLength)?;
    let content_len = u64::from_le_bytes(clen_bytes);
    let response = &input[8..];
    let root = decode_bao_hash(hash)?;
    let tree = bao_tree::BaoTree::new(content_len, BAO_BLOCK_SIZE);
    let key = bao_tree::blake3::derive_key("carbonado-v2/bao", &[format]);
    let mut ob = EmptyOutboard { tree, root };
    let mut decoded = Vec::new();
    keyed_decode_ranges(
        Cursor::new(response),
        &ChunkRanges::all(),
        &mut decoded,
        &mut ob,
        &key,
    )
    .map_err(|e| {
        // bao-tree DecodeError (hash mismatch/truncation etc.) mapped here.
        // (Legacy BaoDecodeError variant is from pre-fork bao crate; not produced by v2 paths.)
        CarbonadoError::StdIoError(std::io::Error::other(format!("bao-tree decode: {}", e)))
    })?;
    Ok(decoded)
}

// The old ecies() function was removed (clean cryptographic break to v2).
// Decryption is now performed via crate::crypto::symmetric_decrypt (or _with_nonce).
// The Format::Encrypted bit still controls whether symmetric decryption (AES-256-CTR + HMAC) is applied.

/// Decompression using zstd
pub fn decompress(input: &[u8]) -> Result<Vec<u8>, CarbonadoError> {
    trace!("decompressing");
    let decompressed = zstd::decode_all(input).map_err(|err| CarbonadoError::ZstdError(err.to_string()))?;
    Ok(decompressed)
}

/// Decode data from Carbonado format in reverse order: `bao -> zfec -> symmetric_decrypt (internal nonce) -> decompress(zstd)`
///
/// The first parameter is the 32-byte symmetric master key (not a secret key in the asymmetric sense — this is the v2 symmetric design).
pub fn decode(
    master_key: &[u8],
    hash: &[u8],
    input: &[u8],
    padding: u32,
    format: u8,
) -> Result<Vec<u8>, CarbonadoError> {
    let format = Format::from(format);

    let verified = if format.contains(Format::Bao) {
        bao(input, hash, format.bits())?
    } else {
        input.to_owned()
    };

    let decoded = if format.contains(Format::Zfec) {
        zfec(&verified, padding)?
    } else {
        verified
    };

    let decrypted = if format.contains(Format::Encrypted) {
        crate::crypto::symmetric_decrypt(master_key, &decoded)?
    } else {
        decoded
    };

    let decompressed = if format.contains(Format::Snappy) {
        decompress(&decrypted)?
    } else {
        decrypted
    };

    Ok(decompressed)
}

/// Extract a 1KB slice of a Bao stream at a specific index.
///
/// This helps for periodic verification.
/// Delegates to verify_slice (which uses BAO_BLOCK_SIZE + pre-order traversal to
/// extract logical data by skipping parent hash pairs in the 4KB-group response).
/// Returns *raw logical inner data bytes* (the pre-bao content at offset), **not**
/// a self-contained verifiable bao sub-proof. Callers must use only on blobs
/// produced with Bao bit set; no key/format validation performed here (see scrub too).
pub fn extract_slice(encoded: &[u8], index: u32) -> Result<Vec<u8>, CarbonadoError> {
    // Use the shared logic so extract also correctly handles 4KB groups keyed bao responses.
    // Returns raw logical inner data bytes at the slice offset (not a self-contained bao proof).
    verify_slice(encoded, index, 1)
}

/// Verify a number of 1KB slices of a Bao stream starting at a specific index.
///
/// With u32 indices this is now limited only by the u32 `bytes_verifiable` / `encoded_len`
/// fields (and available memory), removing the previous artificial ~64 MiB cap for
/// FEC-protected segments.
///
/// Uses the BaoTree at BAO_BLOCK_SIZE (4KB groups) + pre-order nodes to skip parent
/// hash pairs (64B) and extract only leaf data groups at logical byte offsets (no
/// validation here; unkeyed walk). Enables scrub recovery of good zfec chunks.
/// Call only on blobs produced under Bao (format-unaware; see scrub for format param).
/// Full verified decode via bao() uses keyed path. 1KB slices sit on top of the groups.
///
/// NOTE: this always performs a full pre-order walk and materializes the logical
/// content bytes up to the requested range (O(N) alloc for small slice on large
/// input). scrub calls it per-chunk (8x). Not smallest change to optimize; see
/// TODO(perf) and plan for future seek.
pub fn verify_slice(input: &[u8], index: u32, count: u32) -> Result<Vec<u8>, CarbonadoError> {
    let slice_start = (index as u64) * (SLICE_LEN as u64);
    let slice_len = (count as u64) * (SLICE_LEN as u64);
    trace!("Verify slice start: {slice_start} len: {slice_len}");

    // Use pre_order nodes + chunk sizes to read only data groups at the BAO_BLOCK_SIZE
    // leaf level, skip parents (always 64B). Collects leaf data in order -> linear zfec
    // bytes for scrub recovery. This correctly supports 4KB groups (block log=2) on top
    // of which 1KB SLICE_LENs sit.
    // NOTE: full walk materializes (see fn doc). scrub rescans per chunk. TODO(perf) seek.
    if input.len() < 8 {
        return Err(CarbonadoError::InvalidHeaderLength);
    }
    let clen_bytes: [u8; 8] = input[0..8]
        .try_into()
        .map_err(|_| CarbonadoError::InvalidHeaderLength)?;
    let content_len = u64::from_le_bytes(clen_bytes);
    let response = &input[8..];
    let tree = bao_tree::BaoTree::new(content_len, BAO_BLOCK_SIZE);
    let mut cursor = Cursor::new(response);
    let mut content = vec![];
    // Use the exact same chunks iter as encode (authoritative for response byte order/layout):
    // Parents always 64B; Leaves give exact data size (group or partial).
    let ranges = ChunkRanges::all();
    for item in tree.ranges_pre_order_chunks_iter_ref(&ranges, 0) {
        match item {
            BaoChunk::Parent { .. } => {
                let mut skip = [0u8; 64];
                let _ = cursor.read_exact(&mut skip);
            }
            BaoChunk::Leaf { size, .. } => {
                let mut sz = size as u64;
                let remain = content_len.saturating_sub(content.len() as u64);
                if sz > remain {
                    sz = remain;
                }
                let mut d = vec![0u8; sz as usize];
                if cursor.read_exact(&mut d).is_err() {
                    break;
                }
                content.extend(d);
                if content.len() as u64 >= content_len {
                    break;
                }
            }
        }
    }
    // Do not fallback to response (would mix 64B parent hashes into data for caller/scrub)
    // Trim any partial over-read from last group on truncated blobs.
    if (content.len() as u64) > content_len {
        content.truncate(content_len as usize);
    }
    let start = slice_start as usize;
    let end = (start + slice_len as usize).min(content.len());
    if start < content.len() {
        return Ok(content[start..end].to_vec());
    }
    Ok(vec![])
}

/// Scrub zfec-encoded data (requires Bao bit for slice-based candidate extraction + recovery; Zfec-only formats return ScrubRequiresBao).
/// Returns an error when either valid data cannot be provided, or data is already valid.
///
/// If data is already valid, the error message "Data does not need to be scrubbed." is returned.
/// This helps nodes prevent unnecessary writes for periodic scrubbing.
///
/// Recovery uses Reed-Solomon (4 data + 4 parity) over the 8 shards. To tolerate
/// corruption (including distributed "chaos" affecting some shards' data areas), we
/// try subsets of extracted candidate shards (via bao slice extraction) until we find
/// a reconstruction whose re-encode (zfec+keyed-bao) matches the known hash. This makes
/// scrub fully deterministic (RS has no rand) and reliable for >8KB.
/// `format` must match the one used at encode (for keyed bao); caller responsible (see EncodeInfo + Format).
pub fn scrub(
    input: &[u8],
    hash: &[u8],
    encode_info: &EncodeInfo,
    format: u8,
) -> Result<Vec<u8>, CarbonadoError> {
    let fmt = Format::from(format);
    if !fmt.contains(Format::Bao) {
        // scrub recovery uses Bao slice extraction for candidate shards; not applicable/supported for pure Zfec (levels 8/10, which have no verifiability for scrub).
        return Err(CarbonadoError::ScrubRequiresBao);
    }
    let hash = decode_bao_hash(hash)?;
    let chunk_size = encode_info.chunk_len;
    let padding = encode_info.padding_len;
    let slices_per_chunk = chunk_size / SLICE_LEN as u32;

    // Use caller-supplied format (the bits for the Bao+Zfec pipeline that produced this
    // verifiable blob) so that keyed bao() and re-bao use the matching key (format-derived).
    // Callers must pass the same format used at encode time for the bao step.
    match bao(input, hash.as_bytes(), format) {
        Ok(_decoded) => Err(CarbonadoError::UnnecessaryScrub),
        Err(e) => {
            warn!("Data failed to verify with error: {e}. Scrubbing...");
            let mut chunks: Vec<(usize, Vec<u8>)> = vec![];

            for i in 0..FEC_M {
                let slice_index = (i as u32) * slices_per_chunk;
                match verify_slice(input, slice_index, slices_per_chunk) {
                    Ok(chunk) => chunks.push((i, chunk)),
                    Err(e) => {
                        debug!("At least one chunk was bad, at chunk index {i}. Error was: {e}.");
                    }
                }
            }

            info!(
                "{} candidate chunks extracted, of {FEC_K} needed.",
                chunks.len()
            );

            // Robust recovery: search subsets (C(<=8, >=4) is tiny) of candidates.
            // Only correct clean shards will lead to re-encode producing the target hash.
            // Fixes cases where >4 extracted but some leaf-data tainted (num==total no-op avoided).
            let mut recovered: Option<Vec<u8>> = None;
            let n = chunks.len();
            for mask in 0..(1usize << n) {
                if mask.count_ones() < FEC_K as u32 {
                    continue;
                }
                let mut sel: Vec<(usize, Vec<u8>)> = vec![];
                for (j, c) in chunks.iter().enumerate().take(n) {
                    if (mask & (1 << j)) != 0 {
                        sel.push(c.clone());
                    }
                }
                if let Ok(cand_inner) = zfec_chunks(sel, padding) {
                    let (scrubbed, sp, _) = encoding::zfec(&cand_inner)?;
                    if sp != padding {
                        continue;
                    }
                    if let Ok((verif, got_h)) = encoding::bao(&scrubbed, format) {
                        if got_h == hash && verif.len() == input.len() {
                            recovered = Some(verif);
                            break;
                        }
                    }
                }
            }

            let verifiable = match recovered {
                Some(v) => v,
                None => {
                    // Could not find a viable set of >=4 good shards among candidates.
                    return Err(CarbonadoError::InvalidScrubbedHash);
                }
            };

            Ok(verifiable)
        }
    }
}
