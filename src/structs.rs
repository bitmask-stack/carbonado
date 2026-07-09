use serde::{Deserialize, Serialize};

/// Information from the encoding step, some of which is needed for decoding.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EncodeInfo {
    /// How many bytes input into the encoding step.
    pub input_len: u32,
    /// How many bytes total were encoded by any applicable steps for the supplied Carbonado level.
    pub output_len: u32,
    /// How large the data is after Zstd (level 20) compression.
    pub bytes_compressed: u32,
    /// Compression factor.
    ///
    /// Values below 1.0 are desirable; 0.2 is typical of contracts, and 0.8 is typical of code.
    ///
    /// A value above 1.0 indicates the file grew in size, which occurs when used on incompressible file formats.
    pub compression_factor: f32,
    /// How large the data was after the symmetric encryption step
    /// (AES-256-CTR + full HMAC-SHA512 EtM in the v2 format).
    ///
    /// This is not expected to add much overhead (nonce + 64-byte tag).
    pub bytes_encrypted: u32,
    /// How large the data is after adding FEC (reed-solomon 4/8) error correction codes.
    pub bytes_ecc: u32,
    /// How large the data is after Bao encoding, for remote slice verification and integrity-checking.
    pub bytes_verifiable: u32,
    /// The total amount of file amplification. 2.0x is typical for 4/8 FEC (RS) encoding, the others are pretty minimal, at roughly 1.1x.
    pub amplification_factor: f32,
    /// The amount of padding added to input data in order to align it with Bao slice size (4 KiB, `SLICE_LEN`) and 4/8 FEC chunk size.
    /// One slice equals one 4 KiB Bao leaf (`BAO_BLOCK_SIZE`).
    pub padding_len: u32,
    /// How many bytes are in each FEC chunk.
    pub chunk_len: u32,
    /// How many slices are there, total.
    pub verifiable_slice_count: u32,
    /// How many slices there are per chunk.
    pub chunk_slice_count: u32,
}

/// Tuple of verifiable bytes, bao hash, and encode info struct
/// i.e., Encoded(encoded_bytes, bao_hash, encode_info)
///
/// The bao hash (when Bao bit set) is now a keyed blake3 root (via bao-tree 4KB groups)
/// that commits to the format byte used during encoding.
pub struct Encoded(pub Vec<u8>, pub bao::Hash, pub EncodeInfo);

/// Result of outboard encoding (for public non-Encrypted formats requesting outboard storage).
/// main: bare bytes (post-compress if any; the primary on-disk artifact for outboard)
/// verification_outboard: optional sidecar for streaming verification (e.g. `<hash>.cXX.out`)
/// fec_parity: optional sidecar for FEC outboard recovery
/// hash: keyed bao root (commits to exact format/c number)
/// info: encode stats (note bytes_verifiable reflects bare size in outboard)
///
/// Encrypted outboard uses the same artifact split (bare ciphertext main + sidecars). See AGENTS §11.2.
pub struct OutboardEncoded {
    pub main: Vec<u8>,
    pub verification_outboard: Option<Vec<u8>>,
    pub fec_parity: Option<Vec<u8>>,
    pub hash: bao::Hash,
    pub info: EncodeInfo,
}
