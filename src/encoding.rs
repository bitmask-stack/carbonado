use log::trace;

use crate::{error::CarbonadoError, structs::Encoded};

use crate::stream::ZstdEncode;
use crate::stream::encode::stream_encode_buffer_with_nonce;
use crate::stream::encode::stream_encode_outboard_buffer;

/// Encode data into Carbonado format (delegates to the streaming pipeline).
///
/// Encrypted formats use a CSPRNG nonce (embedded layout). For deterministic encrypted
/// bodies (G9 fixtures), use [`encode_with_nonce`]. Compression requires
/// [`encode_with_zstd`] with an explicit level.
pub fn encode(master_key: &[u8], input: &[u8], format: u8) -> Result<Encoded, CarbonadoError> {
    encode_with_zstd(master_key, input, format, None, &ZstdEncode::default())
}

/// Encode with explicit zstd parameters (required when the Compression bit is set).
pub fn encode_with_zstd(
    master_key: &[u8],
    input: &[u8],
    format: u8,
    explicit_nonce: Option<[u8; 16]>,
    zstd: &ZstdEncode,
) -> Result<Encoded, CarbonadoError> {
    encode_with_nonce_and_zstd(master_key, input, format, explicit_nonce, zstd)
}

/// Low-level body encode with optional fixed nonce for encrypted formats.
///
/// When `explicit_nonce` is `Some(n)` and Encryption is set, the blob uses `n` in
/// embedded layout `[nonce|tag|ct]` (including all-zero).
/// When `None`, encrypted formats draw a CSPRNG nonce (production default). Public
/// formats ignore it.
///
/// # Safety / intended use
///
/// Fixed nonces are for **tests and determinism only** (e.g. G9 goldens). Prefer
/// [`encode`] for production. AES-CTR requires the nonce to be unique per
/// `(master_key, encryption operation)` — **reuse is catastrophic** (keystream reuse).
/// See AGENTS.md §2.1.4.
pub fn encode_with_nonce(
    master_key: &[u8],
    input: &[u8],
    format: u8,
    explicit_nonce: Option<[u8; 16]>,
) -> Result<Encoded, CarbonadoError> {
    encode_with_nonce_and_zstd(
        master_key,
        input,
        format,
        explicit_nonce,
        &ZstdEncode::default(),
    )
}

fn encode_with_nonce_and_zstd(
    master_key: &[u8],
    input: &[u8],
    format: u8,
    explicit_nonce: Option<[u8; 16]>,
    zstd: &ZstdEncode,
) -> Result<Encoded, CarbonadoError> {
    let (verifiable, hash, info) =
        stream_encode_buffer_with_nonce(master_key, input, format, explicit_nonce, zstd)?;
    Ok(Encoded(verifiable, hash, info))
}

/// Outboard variant for public and encrypted formats. Compression requires
/// [`encode_outboard_with_zstd`].
pub fn encode_outboard(
    master_key: &[u8],
    input: &[u8],
    format: u8,
) -> Result<crate::structs::OutboardEncoded, CarbonadoError> {
    encode_outboard_with_zstd(master_key, input, format, None, &ZstdEncode::default())
}

/// Outboard encode with explicit zstd parameters.
pub fn encode_outboard_with_zstd(
    master_key: &[u8],
    input: &[u8],
    format: u8,
    explicit_nonce: Option<[u8; 16]>,
    zstd: &ZstdEncode,
) -> Result<crate::structs::OutboardEncoded, CarbonadoError> {
    trace!("encode_outboard format=0x{format:02x}");
    stream_encode_outboard_buffer(master_key, input, format, explicit_nonce, zstd)
}

// Scrub recovery re-exports
pub use crate::stream::bao::verification_inboard_buffer;
pub use crate::stream::fec::encode_inboard_buffer;
