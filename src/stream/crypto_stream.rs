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

use crate::{crypto::derive_subkey, error::CarbonadoError};

type HmacSha512 = Hmac<Sha512>;

const TAG_LEN: usize = 64;
const NONCE_LEN: usize = 16;
const ETM_AAD: &[u8] = b"carbonado-v2-etm";
const READ_BUF: usize = 64 * 1024;

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

/// Header path: explicit nonce; output layout `[tag(64) | ciphertext]`.
///
/// Reads `input` in chunks (no `read_to_end`).
pub fn stream_encrypt_with_nonce<R: Read, W: Write>(
    master_key: &[u8],
    nonce: [u8; 16],
    mut input: R,
    mut output: W,
) -> Result<u64, CarbonadoError> {
    let aes_key = aes_key_from_master(master_key)?;
    let mac_key = mac_key_from_master(master_key)?;
    let mut mac = new_hmac(&mac_key, &nonce)?;
    let mut cipher = Ctr128BE::<Aes256>::new(&aes_key.into(), &nonce.into());

    let mut ct = Vec::new();
    let mut buf = [0u8; READ_BUF];
    loop {
        let n = input.read(&mut buf).map_err(CarbonadoError::StdIoError)?;
        if n == 0 {
            break;
        }
        let chunk = &mut buf[..n];
        cipher.apply_keystream(chunk);
        mac.update(chunk);
        ct.extend_from_slice(chunk);
    }
    let tag = mac.finalize().into_bytes();
    output.write_all(&tag).map_err(CarbonadoError::StdIoError)?;
    output.write_all(&ct).map_err(CarbonadoError::StdIoError)?;
    Ok((TAG_LEN + ct.len()) as u64)
}

/// Seekable variant: streams ciphertext to `output` without buffering the full blob.
pub fn stream_encrypt_with_nonce_seek<R: Read, W: Write + Seek>(
    master_key: &[u8],
    nonce: [u8; 16],
    mut input: R,
    output: &mut W,
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
        .seek(SeekFrom::Start(0))
        .map_err(CarbonadoError::StdIoError)?;
    output.write_all(&tag).map_err(CarbonadoError::StdIoError)?;
    output
        .seek(SeekFrom::End(0))
        .map_err(CarbonadoError::StdIoError)?;
    Ok(TAG_LEN as u64 + ct_len)
}

/// Low-level path: random nonce embedded in output `[nonce(16) | tag(64) | ct]`.
pub fn stream_encrypt<R: Read, W: Write>(
    master_key: &[u8],
    input: R,
    mut output: W,
) -> Result<(u64, [u8; 16]), CarbonadoError> {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|_| CarbonadoError::RandomnessError)?;
    output
        .write_all(&nonce)
        .map_err(CarbonadoError::StdIoError)?;
    let inner = stream_encrypt_with_nonce(master_key, nonce, input, &mut output)?;
    Ok((NONCE_LEN as u64 + inner, nonce))
}

/// Decrypt `[tag(64) | ct]` with explicit nonce; verifies MAC before writing plaintext.
pub fn stream_decrypt_with_nonce<R: Read, W: Write>(
    master_key: &[u8],
    nonce: [u8; 16],
    mut input: R,
    mut output: W,
) -> Result<u64, CarbonadoError> {
    let aes_key = aes_key_from_master(master_key)?;
    let mac_key = mac_key_from_master(master_key)?;

    let mut tag = [0u8; TAG_LEN];
    read_exact_crypto(&mut input, &mut tag)?;

    let mut mac = new_hmac(&mac_key, &nonce)?;
    let mut ct = Vec::new();
    let mut buf = [0u8; READ_BUF];
    loop {
        let n = input.read(&mut buf).map_err(map_read_err)?;
        if n == 0 {
            break;
        }
        mac.update(&buf[..n]);
        ct.extend_from_slice(&buf[..n]);
    }
    mac.verify_slice(&tag)
        .map_err(|_| CarbonadoError::AuthenticationFailed)?;

    let mut cipher = Ctr128BE::<Aes256>::new(&aes_key.into(), &nonce.into());
    let mut pt_len = 0u64;
    for chunk in ct.chunks_mut(READ_BUF) {
        cipher.apply_keystream(chunk);
        output
            .write_all(chunk)
            .map_err(CarbonadoError::StdIoError)?;
        pt_len += chunk.len() as u64;
    }
    Ok(pt_len)
}

/// Decrypt embedded-nonce blob `[nonce(16) | tag(64) | ct]`.
pub fn stream_decrypt<R: Read, W: Write>(
    master_key: &[u8],
    mut input: R,
    output: W,
) -> Result<u64, CarbonadoError> {
    let mut nonce = [0u8; NONCE_LEN];
    read_exact_crypto(&mut input, &mut nonce)?;
    stream_decrypt_with_nonce(master_key, nonce, input, output)
}
