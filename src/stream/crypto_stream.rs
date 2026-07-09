//! AES-256-CTR + HMAC-SHA512 EtM streaming over [`Read`] / [`Write`].
//!
//! This module mirrors the buffer symmetric paths in [`crate::crypto`] for large payloads:
//!
//! - Subkeys: `derive_subkey(master, "aes-ctr")` and `derive_subkey(master, "etm-hmac")`.
//! - EtM domain: `b"carbonado-v2-etm" || nonce || ciphertext` (same as
//!   [`crate::crypto::symmetric_encrypt_with_nonce`] / [`crate::crypto::symmetric_decrypt_with_nonce`]).
//! - Header-path encrypt (`stream_encrypt_with_nonce`) outputs `[tag(64) | ct]` with an explicit nonce.
//! - Low-level path (`stream_encrypt`) prepends the random nonce: `[nonce(16) | tag(64) | ct]`.
//!
//! Payload EtM uses the `carbonado-v2-etm` string because the ciphertext blob has no natural
//! Carbonado header prefix (unlike header MAC, which binds via leading `MAGICNO` in `auth_data`).
//! See AGENTS.md §2.1.2 (Payload EtM) and §2.2 (Header MAC).

use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};

use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes256;
use ctr::Ctr128BE;
use hmac::{Hmac, Mac};
use sha2::Sha512;

use crate::{
    constants::SLICE_LEN, crypto::derive_subkey, error::CarbonadoError,
    stream::spool::SeekableSpool,
};

type HmacSha512 = Hmac<Sha512>;

const TAG_LEN: usize = 64;
const NONCE_LEN: usize = 16;
const ETM_AAD: &[u8] = b"carbonado-v2-etm";
const READ_BUF: usize = SLICE_LEN as usize;

fn aes_key_from_master(master_key: &[u8]) -> Result<[u8; 32], CarbonadoError> {
    if master_key.len() < 32 {
        return Err(CarbonadoError::InvalidKeyLength);
    }
    let enc_material = derive_subkey(master_key, "aes-ctr")?;
    enc_material[..32].try_into().map_err(|_| {
        CarbonadoError::InternalStateError("derive_subkey must yield 64 bytes".to_string())
    })
}

fn mac_key_from_master(master_key: &[u8]) -> Result<[u8; 64], CarbonadoError> {
    if master_key.len() < 32 {
        return Err(CarbonadoError::InvalidKeyLength);
    }
    derive_subkey(master_key, "etm-hmac")
}

fn new_hmac(mac_key: &[u8; 64], nonce: &[u8; 16]) -> Result<HmacSha512, CarbonadoError> {
    let mut mac =
        HmacSha512::new_from_slice(mac_key).map_err(|_| CarbonadoError::InvalidKeyLength)?;
    mac.update(ETM_AAD);
    mac.update(nonce);
    Ok(mac)
}

fn map_read_err(err: std::io::Error) -> CarbonadoError {
    if err.kind() == ErrorKind::UnexpectedEof {
        CarbonadoError::InvalidCiphertextLength
    } else {
        CarbonadoError::StdIoError(err)
    }
}

fn read_exact_crypto<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<(), CarbonadoError> {
    reader.read_exact(buf).map_err(map_read_err)
}

fn excess_ct_error(declared: u64) -> CarbonadoError {
    CarbonadoError::CiphertextExceedsDeclaredLength { declared }
}

/// Header path: explicit nonce; output layout `[tag(64) | ciphertext]`.
///
/// Streams ciphertext to `output` without buffering the full blob (seek-placeholder tag).
pub fn stream_encrypt_with_nonce<R: Read, W: Write + Seek>(
    master_key: &[u8],
    nonce: [u8; 16],
    input: R,
    output: &mut W,
) -> Result<u64, CarbonadoError> {
    stream_encrypt_with_nonce_at(master_key, nonce, input, output, 0)
}

/// Seekable variant — alias for [`stream_encrypt_with_nonce`] (same seek-placeholder layout).
pub fn stream_encrypt_with_nonce_seek<R: Read, W: Write + Seek>(
    master_key: &[u8],
    nonce: [u8; 16],
    input: R,
    output: &mut W,
) -> Result<u64, CarbonadoError> {
    stream_encrypt_with_nonce(master_key, nonce, input, output)
}

/// Low-level path: random nonce embedded in output `[nonce(16) | tag(64) | ct]`.
pub fn stream_encrypt<R: Read, W: Write + Seek>(
    master_key: &[u8],
    input: R,
    output: &mut W,
) -> Result<(u64, [u8; 16]), CarbonadoError> {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|_| CarbonadoError::RandomnessError)?;
    output
        .write_all(&nonce)
        .map_err(CarbonadoError::StdIoError)?;
    let tag_offset = output
        .stream_position()
        .map_err(CarbonadoError::StdIoError)?;
    let inner = stream_encrypt_with_nonce_at(master_key, nonce, input, output, tag_offset)?;
    Ok((NONCE_LEN as u64 + inner, nonce))
}

/// Header-path encrypt with tag placeholder at `tag_offset` (not necessarily 0).
fn stream_encrypt_with_nonce_at<R: Read, W: Write + Seek>(
    master_key: &[u8],
    nonce: [u8; 16],
    mut input: R,
    output: &mut W,
    tag_offset: u64,
) -> Result<u64, CarbonadoError> {
    let aes_key = aes_key_from_master(master_key)?;
    let mac_key = mac_key_from_master(master_key)?;
    let mut mac = new_hmac(&mac_key, &nonce)?;
    let mut cipher = Ctr128BE::<Aes256>::new(&aes_key.into(), &nonce.into());

    output
        .write_all(&[0u8; TAG_LEN])
        .map_err(CarbonadoError::StdIoError)?;
    let mut ct_len = 0u64;
    let mut buf = [0u8; READ_BUF];
    loop {
        let n = input.read(&mut buf).map_err(CarbonadoError::StdIoError)?;
        if n == 0 {
            break;
        }
        let chunk = &mut buf[..n];
        cipher.apply_keystream(chunk);
        mac.update(chunk);
        output
            .write_all(chunk)
            .map_err(CarbonadoError::StdIoError)?;
        ct_len += n as u64;
    }
    let tag = mac.finalize().into_bytes();
    output
        .seek(SeekFrom::Start(tag_offset))
        .map_err(CarbonadoError::StdIoError)?;
    output.write_all(&tag).map_err(CarbonadoError::StdIoError)?;
    output
        .seek(SeekFrom::End(0))
        .map_err(CarbonadoError::StdIoError)?;
    Ok(TAG_LEN as u64 + ct_len)
}

/// CTR decrypt pass reading ciphertext from `input` and writing plaintext to `output`.
fn decrypt_ct_stream<R: Read, W: Write>(
    aes_key: &[u8; 32],
    nonce: &[u8; 16],
    input: &mut R,
    output: &mut W,
    ct_len: Option<u64>,
) -> Result<u64, CarbonadoError> {
    let mut cipher = Ctr128BE::<Aes256>::new(aes_key.into(), nonce.into());
    let mut buf = [0u8; READ_BUF];
    let mut pt_len = 0u64;
    let mut remaining = ct_len;
    loop {
        let cap = remaining
            .map(|r| READ_BUF.min(r as usize))
            .unwrap_or(READ_BUF);
        if cap == 0 {
            break;
        }
        let n = input.read(&mut buf[..cap]).map_err(map_read_err)?;
        if n == 0 {
            if let Some(r) = remaining {
                if r > 0 {
                    return Err(CarbonadoError::InvalidCiphertextLength);
                }
            }
            break;
        }
        let chunk = &mut buf[..n];
        cipher.apply_keystream(chunk);
        output
            .write_all(chunk)
            .map_err(CarbonadoError::StdIoError)?;
        pt_len += n as u64;
        if let Some(ref mut r) = remaining {
            *r = r.saturating_sub(n as u64);
        }
    }
    Ok(pt_len)
}

/// Decrypt `[tag(64) | ct]` with explicit nonce; verifies MAC before writing plaintext.
///
/// Non-seekable inputs are spooled to a temp file during the MAC pass (O(chunk) RAM).
pub fn stream_decrypt_with_nonce<R: Read, W: Write>(
    master_key: &[u8],
    nonce: [u8; 16],
    input: R,
    output: W,
) -> Result<u64, CarbonadoError> {
    stream_decrypt_with_nonce_bounded(master_key, nonce, input, output, None)
}

/// Bounded decrypt: `ct_len` is ciphertext length **excluding** the 64-byte tag.
pub fn stream_decrypt_with_nonce_bounded<R: Read, W: Write>(
    master_key: &[u8],
    nonce: [u8; 16],
    mut input: R,
    mut output: W,
    ct_len: Option<u64>,
) -> Result<u64, CarbonadoError> {
    let aes_key = aes_key_from_master(master_key)?;
    let mac_key = mac_key_from_master(master_key)?;

    let mut tag = [0u8; TAG_LEN];
    read_exact_crypto(&mut input, &mut tag)?;

    let mut mac = new_hmac(&mac_key, &nonce)?;
    let mut spool = SeekableSpool::new()?;
    let mut buf = [0u8; READ_BUF];
    let mut total = 0u64;
    loop {
        let cap = ct_len
            .map(|limit| READ_BUF.min((limit - total) as usize))
            .unwrap_or(READ_BUF);
        if cap == 0 {
            break;
        }
        let n = input.read(&mut buf[..cap]).map_err(map_read_err)?;
        if n == 0 {
            break;
        }
        if let Some(limit) = ct_len {
            if total.saturating_add(n as u64) > limit {
                return Err(excess_ct_error(limit));
            }
        }
        mac.update(&buf[..n]);
        spool
            .write_all(&buf[..n])
            .map_err(CarbonadoError::StdIoError)?;
        total += n as u64;
    }
    if let Some(limit) = ct_len {
        if total != limit {
            return Err(CarbonadoError::InvalidCiphertextLength);
        }
        reject_trailing_ciphertext(&mut input, limit)?;
    }
    mac.verify_slice(&tag)
        .map_err(|_| CarbonadoError::AuthenticationFailed)?;

    spool.rewind()?;
    decrypt_ct_stream(&aes_key, &nonce, &mut spool, &mut output, Some(total))
}

/// Seekable-input variant: two-pass MAC verify then CTR decrypt without spooling.
pub fn stream_decrypt_with_nonce_seek<R: Read + Seek, W: Write>(
    master_key: &[u8],
    nonce: [u8; 16],
    mut input: R,
    mut output: W,
    ct_len: Option<u64>,
) -> Result<u64, CarbonadoError> {
    let aes_key = aes_key_from_master(master_key)?;
    let mac_key = mac_key_from_master(master_key)?;

    let mut tag = [0u8; TAG_LEN];
    read_exact_crypto(&mut input, &mut tag)?;

    let ct_start = input
        .stream_position()
        .map_err(CarbonadoError::StdIoError)?;

    let mut mac = new_hmac(&mac_key, &nonce)?;
    let mut buf = [0u8; READ_BUF];
    let mut total = 0u64;
    loop {
        let cap = ct_len
            .map(|limit| READ_BUF.min((limit - total) as usize))
            .unwrap_or(READ_BUF);
        if cap == 0 {
            break;
        }
        let n = input.read(&mut buf[..cap]).map_err(map_read_err)?;
        if n == 0 {
            break;
        }
        if let Some(limit) = ct_len {
            if total.saturating_add(n as u64) > limit {
                return Err(excess_ct_error(limit));
            }
        }
        mac.update(&buf[..n]);
        total += n as u64;
    }
    if let Some(limit) = ct_len {
        if total != limit {
            return Err(CarbonadoError::InvalidCiphertextLength);
        }
        reject_trailing_ciphertext(&mut input, limit)?;
    }
    mac.verify_slice(&tag)
        .map_err(|_| CarbonadoError::AuthenticationFailed)?;

    input
        .seek(SeekFrom::Start(ct_start))
        .map_err(CarbonadoError::StdIoError)?;
    decrypt_ct_stream(&aes_key, &nonce, &mut input, &mut output, Some(total))
}

fn reject_trailing_ciphertext<R: Read>(input: &mut R, declared: u64) -> Result<(), CarbonadoError> {
    let mut extra = [0u8; 1];
    match input.read(&mut extra) {
        Ok(0) => Ok(()),
        Ok(_) => Err(excess_ct_error(declared)),
        Err(e) => Err(CarbonadoError::StdIoError(e)),
    }
}

/// Decrypt embedded-nonce blob `[nonce(16) | tag(64) | ct]`.
pub fn stream_decrypt<R: Read, W: Write>(
    master_key: &[u8],
    mut input: R,
    output: W,
) -> Result<u64, CarbonadoError> {
    let mut nonce = [0u8; NONCE_LEN];
    read_exact_crypto(&mut input, &mut nonce)?;
    stream_decrypt_with_nonce_bounded(master_key, nonce, input, output, None)
}

/// Decrypt embedded-nonce blob with seekable input (two-pass MAC without spool).
pub fn stream_decrypt_seek<R: Read + Seek, W: Write>(
    master_key: &[u8],
    mut input: R,
    output: W,
    ct_len: Option<u64>,
) -> Result<u64, CarbonadoError> {
    let mut nonce = [0u8; NONCE_LEN];
    read_exact_crypto(&mut input, &mut nonce)?;
    stream_decrypt_with_nonce_seek(master_key, nonce, input, output, ct_len)
}
