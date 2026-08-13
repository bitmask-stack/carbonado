use log::trace;

use crate::{error::CarbonadoError, structs::Encoded};

use crate::stream::encode::stream_encode_buffer_with_nonce;
#[cfg(feature = "backend-rust")]
use crate::stream::encode::stream_encode_outboard_buffer;

/// Encode data into Carbonado format (delegates to streaming pipeline, or Lean AOT).
///
/// Under `backend-lean`, uses C ABI `carbonado_encode`. See [`crate::backend::lean`]
/// for EncodeInfo stage counters (R3: compress/encrypt + FEC/Bao geometry).
///
/// Encrypted formats use a CSPRNG nonce (embedded layout). For deterministic encrypted
/// bodies (G9 fixtures), use [`encode_with_nonce`].
pub fn encode(master_key: &[u8], input: &[u8], format: u8) -> Result<Encoded, CarbonadoError> {
    encode_with_nonce(master_key, input, format, None)
}

/// Low-level body encode with optional fixed nonce for encrypted formats.
///
/// When `explicit_nonce` is `Some(n)` and Encryption is set, the blob uses `n` in
/// embedded layout `[nonce|tag|ct]` (including all-zero — dual-backend identical).
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
    let (verifiable, hash, info) =
        stream_encode_buffer_with_nonce(master_key, input, format, explicit_nonce)?;
    Ok(Encoded(verifiable, hash, info))
}

/// Outboard variant for public and encrypted formats.
///
/// Under `backend-lean`, uses C ABI `carbonado_encode_outboard`.
pub fn encode_outboard(
    master_key: &[u8],
    input: &[u8],
    format: u8,
) -> Result<crate::structs::OutboardEncoded, CarbonadoError> {
    trace!("encode_outboard format=0x{format:02x}");
    #[cfg(feature = "backend-lean")]
    {
        // Low-level path: embedded-nonce when encrypted (header_path = false).
        let nonce = if format & 1 != 0 {
            let mut n = [0u8; 16];
            getrandom::getrandom(&mut n).map_err(|_| CarbonadoError::RandomnessError)?;
            Some(n)
        } else {
            None
        };
        crate::backend::lean::encode_outboard(master_key, input, format, nonce.as_ref(), false)
    }
    #[cfg(feature = "backend-rust")]
    {
        stream_encode_outboard_buffer(master_key, input, format, None)
    }
}

// Scrub recovery re-exports (Rust scrub path; lean scrub is in-engine)
#[cfg(feature = "backend-rust")]
pub use crate::stream::bao::verification_inboard_buffer;
#[cfg(feature = "backend-rust")]
pub use crate::stream::fec::encode_inboard_buffer;
