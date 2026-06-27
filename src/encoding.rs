use std::io::Write;

use bao::Hash;
// ecies removed (clean break from ECIES v1)
use bao_tree::{
    io::{outboard::PostOrderMemOutboard, sync::keyed_encode_ranges_validated},
    ChunkRanges,
};
use log::{debug, trace};
use reed_solomon_erasure::galois_8::Field;
use reed_solomon_erasure::ReedSolomon;
use snap::write::FrameEncoder;

use crate::{
    constants::{Format, BAO_BLOCK_SIZE, FEC_K, FEC_M, SLICE_LEN},
    error::CarbonadoError,
    structs::{EncodeInfo, Encoded},
    utils::calc_padding_len,
};

/// Snappy compression
pub fn snap(input: &[u8]) -> Result<Vec<u8>, CarbonadoError> {
    trace!("compressing");
    let buffer: &[u8] = input;
    let output = vec![];
    let mut writer = FrameEncoder::new(output);
    writer.write_all(buffer)?;
    let compressed = writer
        .into_inner()
        .map_err(|err| CarbonadoError::SnapWriteIntoInnerError(err.to_string()))?;

    Ok(compressed)
}

// The old ecies() function was removed (clean cryptographic break to v2).
// Encryption is now performed via crate::crypto::symmetric_encrypt (or _with_nonce).
// The Format::Encrypted bit still controls whether symmetric encryption (AES-256-CTR + HMAC) is applied.

/// Bao stream encoding using the local bao-tree fork.
///
/// Uses 4KB chunk groups (BAO_BLOCK_SIZE) and keyed BLAKE3 so the root hash
/// commits to the Format bitmask (multi-dimensional content addressing).
/// The returned verifiable blob is prefixed with a LE u64 of the pre-bao content length
/// (to allow decode to construct the BaoTree geometry).
pub fn bao(input: &[u8], format: u8) -> Result<(Vec<u8>, Hash), CarbonadoError> {
    trace!("verifiabilitifying (bao-tree, 4KB groups, keyed on format)");
    let key = bao_tree::blake3::derive_key("carbonado-v2/bao", &[format]);
    let outboard = PostOrderMemOutboard::create_keyed(input, BAO_BLOCK_SIZE, &key);
    let ranges = ChunkRanges::all();
    let mut response = Vec::new();
    keyed_encode_ranges_validated(input, &outboard, &ranges, &mut response, &key)
        .map_err(|e| CarbonadoError::StdIoError(std::io::Error::other(e.to_string())))?;
    // prefix for size (used on decode side)
    let content_len = input.len() as u64;
    let mut verifiable = Vec::with_capacity(8 + response.len());
    verifiable.extend_from_slice(&content_len.to_le_bytes());
    verifiable.extend_from_slice(&response);
    Ok((verifiable, outboard.root))
}

/// Zfec forward error correction encoding (implemented via reed-solomon-erasure 4/8 RS)
/// Returns a tuple of encoded bytes, the amount of padding used, and the length of each chunk.
///
/// Deterministic (same input+params -> identical output bytes). Tolerates loss of any 4 of 8
/// shards (arbitrary 50% of the FEC body if aligned to shards). Used after encrypt, before bao.
pub fn zfec(input: &[u8]) -> Result<(Vec<u8>, u32, u32), CarbonadoError> {
    trace!("forward error correctionifying (reed-solomon-erasure during v2.0 FEC overhaul)");
    if input.is_empty() {
        return Ok((vec![], 0, 0));
    }
    let input_len = input.len();
    let (padding_len, chunk_len) = calc_padding_len(input_len);

    let mut padding_bytes = vec![0u8; padding_len as usize];
    let mut padded_input = Vec::from(input);
    padded_input.append(&mut padding_bytes);
    debug!(
        "After padding has been added, input is now: {} bytes",
        padded_input.len()
    );

    // Use RS with same 4/8 to preserve user model and alignment.
    let data_shards = FEC_K;
    let parity_shards = FEC_M - FEC_K;
    let total_shards = FEC_M;
    let shard_len = chunk_len as usize;

    let rs = ReedSolomon::<Field>::new(data_shards, parity_shards)?; // uses From for FecError

    let mut shards: Vec<Vec<u8>> = (0..total_shards)
        .map(|i| {
            if i < data_shards {
                padded_input[i * shard_len..(i + 1) * shard_len].to_vec()
            } else {
                vec![0u8; shard_len]
            }
        })
        .collect();

    rs.encode(&mut shards)?;

    // Return concatenated shards (same shape as before)
    let mut encoded = vec![];
    for s in &shards {
        if s.len() as u32 != chunk_len {
            return Err(CarbonadoError::EncodeInvalidChunkLength(chunk_len, s.len()));
        }
        encoded.extend_from_slice(s);
    }

    // Padding added by us (not passed from zfec layer); contract preserved for FEC.
    Ok((encoded, padding_len, chunk_len))
}

/// Encode data into Carbonado format, performing compression, encryption, adding error correction codes, and stream verification encoding, in that order.
///
///  `snap -> symmetric_encrypt (internal nonce) -> zfec (RS FEC) -> bao`
///
/// The first parameter is the 32-byte symmetric master key (not a public key — this is the v2 symmetric design).
pub fn encode(master_key: &[u8], input: &[u8], format: u8) -> Result<Encoded, CarbonadoError> {
    let input_len = input.len() as u32;
    let format = Format::from(format);

    let compressed;
    let encrypted;
    let encoded;
    let padding_len;
    let chunk_len;
    let verifiable_slice_count;
    let chunk_slice_count;
    let verifiable;
    let hash;

    let bytes_compressed;
    let bytes_encrypted;
    let bytes_ecc;
    let bytes_verifiable;

    if format.contains(Format::Snappy) {
        compressed = snap(input)?;
        bytes_compressed = compressed.len() as u32;
    } else {
        compressed = input.to_owned();
        bytes_compressed = 0;
    }

    if format.contains(Format::Encrypted) {
        encrypted = crate::crypto::symmetric_encrypt(master_key, &compressed)?;
        bytes_encrypted = encrypted.len() as u32;
    } else {
        encrypted = compressed;
        bytes_encrypted = 0;
    }

    if format.contains(Format::Zfec) {
        (encoded, padding_len, chunk_len) = zfec(&encrypted)?;
        bytes_ecc = encoded.len() as u32;
        verifiable_slice_count = bytes_ecc / SLICE_LEN as u32;
        // u32 (post-widening) capped in practice by Header.encoded_len u32 (~4GiB/segment);
        // no extra saturating here (see Header + AGENTS "theoretical max").
        debug!(
            "FEC post-encode: bytes_ecc={}, slice_count={}, chunk_len={}",
            bytes_ecc, verifiable_slice_count, chunk_len
        );
        if verifiable_slice_count % 8 != 0 {
            return Err(CarbonadoError::InvalidVerifiableSliceCount(
                verifiable_slice_count,
            ));
        }
        chunk_slice_count = verifiable_slice_count / 8;
    } else {
        encoded = encrypted;
        padding_len = 0;
        chunk_len = 0;
        bytes_ecc = 0;
        verifiable_slice_count = 0;
        chunk_slice_count = 0;
    }

    if format.contains(Format::Bao) {
        (verifiable, hash) = bao(&encoded, format.bits())?;
        bytes_verifiable = verifiable.len() as u32;
    } else {
        verifiable = encoded;
        hash = Hash::from([0; 32]);
        bytes_verifiable = 0;
    }

    // Calculate totals
    let compression_factor = bytes_compressed as f32 / input_len as f32;
    let amplification_factor = bytes_verifiable as f32 / input_len as f32;
    let output_len = verifiable.len() as u32;

    Ok(Encoded(
        verifiable,
        hash,
        EncodeInfo {
            input_len,
            output_len,
            bytes_compressed,
            bytes_encrypted,
            bytes_ecc,
            bytes_verifiable,
            compression_factor,
            amplification_factor,
            padding_len,
            chunk_len,
            verifiable_slice_count,
            chunk_slice_count,
        },
    ))
}
