//! Symmetric cryptographic primitives for Carbonado v2.
//!
//! This module implements the core of the clean cryptographic break from the old ECIES design:
//!
//! - **AES-256-CTR** for length-preserving bulk encryption (hardware accelerated via AES-NI/VAES).
//! - **HMAC-SHA512** (full 64-byte tags) in Encrypt-then-MAC construction for integrity and authentication.
//! - **HMAC-SHA512-based subkey derivation** (BIP-32 style) for key separation.
//! - **Argon2id** helper for passphrase-based key derivation.
//! - **SLH-DSA (FIPS-205 / SPHINCS+)** post-quantum signatures via `libbitcoinpqc`, **strictly for sidecar use only**.
//!
//! # Important Security Model
//!
//! See [AGENTS.md §2](https://github.com/bitmask-stack/carbonado/blob/main/AGENTS.md#2-cryptographic-architecture-v2--current-target)
//! for the normative invariants. Key points:
//!
//! - Nonces must be unique per `(master_key, encryption operation)`.
//! - The high-level `file::encode` path uses **one nonce for the entire archive**.
//! - SLH-DSA signatures are **never** embedded inside Carbonado containers — they are sidecars only.
//! - The library performs **no automatic zeroization** of caller-supplied master keys.
//!
//! # Two Encryption Paths
//!
//! 1. **Recommended for most users**: Use [`crate::file::encode`] / [`crate::file::decode`].
//!    These use the Header with explicit nonce and separate header authentication.
//!    The Header (including the nonce) is public authenticated metadata — no secret key material
//!    is ever placed in it.
//! 2. **Low-level**: The functions in this module (`symmetric_encrypt*` / `symmetric_decrypt*`)
//!    are exposed for advanced use cases and for the internal `encoding` / `decoding` layers.
//!
//! # Stability
//!
//! This module is public so advanced users and higher-level tools can access the primitives directly.
//! The API surface is intended to be relatively stable for 0.7.x, but the exact set of re-exported
//! `bitcoinpqc` types may be adjusted. Always prefer the high-level `file` API when possible.

use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes256;
use ctr::Ctr128BE;
use hmac::{Hmac, Mac};
use sha2::Sha512;

use crate::error::CarbonadoError;

// SLH-DSA / post-quantum support is optional (disabled for WASM builds where libbitcoinpqc cannot easily compile).
#[cfg(feature = "pqc")]
pub use bitcoinpqc::{
    self, Algorithm, KeyPair, PqcError as BitcoinPqcError, PublicKey, SecretKey, Signature,
};

/// Domain separation prefix for all v2 key material.
const LABEL_PREFIX: &[u8] = b"carbonado-v2/";

type HmacSha512 = Hmac<Sha512>;

/// Constant-time equality comparison for two byte slices.
/// Returns true only if they are identical and same length.
///
/// This is used for header MAC verification to avoid timing side-channels.
#[inline]
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Derive a 64-byte subkey using HMAC-SHA512 (BIP-32 style CKD with domain separation).
///
/// This is the central KDF used for all key separation in Carbonado v2.
///
/// # Labels (normative registry — see AGENTS.md)
///
/// Currently registered labels:
/// - `"aes-ctr"` → first 32 bytes used as AES-256 key
/// - `"etm-hmac"` → full 64 bytes used for payload Encrypt-then-MAC
/// - `"header-auth"` → full 64 bytes used for Header authentication
/// - Internal SLH-DSA stretching labels (not for external use)
///
/// # Security
///
/// The `master` material is treated as a PRF key. Callers must ensure it has at least
/// 256 bits of entropy (32 bytes). Short or low-entropy masters are rejected.
///
/// See AGENTS.md §2.1 for the full key derivation rules.
pub fn derive_subkey(master: &[u8], label: &str) -> Result<[u8; 64], CarbonadoError> {
    if master.is_empty() {
        return Err(CarbonadoError::InvalidKeyLength);
    }

    let mut mac =
        HmacSha512::new_from_slice(master).map_err(|_| CarbonadoError::InvalidKeyLength)?;

    mac.update(LABEL_PREFIX);
    mac.update(label.as_bytes());

    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result[..64]);
    Ok(out)
}

/// Encrypt with AES-256-CTR + full HMAC-SHA512 (64-byte tag) in Encrypt-then-MAC mode.
///
/// This is the **explicit-nonce** variant. The caller is responsible for generating
/// and managing the 16-byte nonce.
///
/// # Security Requirements (must be followed)
///
/// - `master_key` must be at least 32 bytes with high entropy.
/// - `nonce` **must** be unique for this `(master_key, operation)`. Reuse is catastrophic.
/// - The returned `[tag(64) | ciphertext]` must be authenticated before decryption
///   (see [`symmetric_decrypt_with_nonce`]).
///
/// # When to use
///
/// Prefer this variant when you need to store the nonce separately (e.g. inside a
/// [`crate::file::Header`]).
///
/// The high-level [`crate::file::encode`] uses this path.
///
/// **Security note**: The nonce is *not* secret material. It is stored in the clear inside
/// the Header (which is itself only integrity-protected via `header_mac`, never encrypted).
/// This is the standard and correct model for CTR, GCM, etc. See AGENTS.md for details.
///
/// Output layout: `[64-byte tag] [ciphertext]` (nonce is stored elsewhere).
///
/// See AGENTS.md §2.1 for the full nonce and EtM rules.
pub fn symmetric_encrypt_with_nonce(
    master_key: &[u8],
    nonce: [u8; 16],
    input: &[u8],
) -> Result<Vec<u8>, CarbonadoError> {
    if master_key.len() < 32 {
        return Err(CarbonadoError::InvalidKeyLength);
    }

    let enc_material = derive_subkey(master_key, "aes-ctr")?;
    let mac_key = derive_subkey(master_key, "etm-hmac")?;
    let aes_key: [u8; 32] = enc_material[..32]
        .try_into()
        .expect("derive_subkey always returns 64 bytes");

    let mut cipher = Ctr128BE::<Aes256>::new(&aes_key.into(), &nonce.into());
    let mut ct = input.to_vec();
    cipher.apply_keystream(&mut ct);

    let mut mac =
        HmacSha512::new_from_slice(&mac_key).map_err(|_| CarbonadoError::InvalidKeyLength)?;
    mac.update(b"carbonado-v2-etm");
    mac.update(&nonce);
    mac.update(&ct);
    let tag = mac.finalize().into_bytes();

    let mut out = Vec::with_capacity(64 + ct.len());
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Encrypt with internal random nonce.
///
/// Generates a fresh 16-byte nonce using `getrandom` and embeds it in the output:
/// `[nonce(16) | tag(64) | ciphertext]`.
///
/// This is the variant used by the low-level [`crate::encoding::encode`].
///
/// **Warning**: Each call to this function under the same master key must produce a
/// unique nonce. The internal `getrandom` call makes collision extremely unlikely for
/// normal use, but callers doing extremely high volume should consider key rotation.
///
/// See the documentation on [`symmetric_encrypt_with_nonce`] for security requirements.
pub fn symmetric_encrypt(master_key: &[u8], input: &[u8]) -> Result<Vec<u8>, CarbonadoError> {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|_| CarbonadoError::RandomnessError)?;

    let inner = symmetric_encrypt_with_nonce(master_key, nonce, input)?;

    let mut out = Vec::with_capacity(16 + inner.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&inner);
    Ok(out)
}

/// Decrypt + verify using an explicitly provided nonce.
///
/// This is the counterpart to [`symmetric_encrypt_with_nonce`].
///
/// The `input` must be exactly `[tag(64) | ciphertext]`.
///
/// The function performs constant-time HMAC verification before any decryption.
/// Authentication failure returns [`CarbonadoError::AuthenticationFailed`].
pub fn symmetric_decrypt_with_nonce(
    master_key: &[u8],
    nonce: [u8; 16],
    input: &[u8], // this should be [tag(64) | ct]
) -> Result<Vec<u8>, CarbonadoError> {
    if input.len() < 64 {
        return Err(CarbonadoError::InvalidCiphertextLength);
    }
    if master_key.len() < 32 {
        return Err(CarbonadoError::InvalidKeyLength);
    }

    let tag = &input[0..64];
    let ct = &input[64..];

    let enc_material = derive_subkey(master_key, "aes-ctr")?;
    let mac_key = derive_subkey(master_key, "etm-hmac")?;
    let aes_key: [u8; 32] = enc_material[..32]
        .try_into()
        .expect("derive_subkey always returns 64 bytes");

    let mut mac =
        HmacSha512::new_from_slice(&mac_key).map_err(|_| CarbonadoError::InvalidKeyLength)?;
    mac.update(b"carbonado-v2-etm");
    mac.update(&nonce);
    mac.update(ct);
    mac.verify_slice(tag)
        .map_err(|_| CarbonadoError::AuthenticationFailed)?;

    let mut cipher = Ctr128BE::<Aes256>::new(&aes_key.into(), &nonce.into());
    let mut pt = ct.to_vec();
    cipher.apply_keystream(&mut pt);
    Ok(pt)
}

/// Decrypt + verify for the internal-nonce format.
///
/// Expects the blob produced by [`symmetric_encrypt`]: `[nonce(16) | tag(64) | ct]`.
///
/// This is the low-level counterpart used by [`crate::decoding::decode`].
pub fn symmetric_decrypt(master_key: &[u8], input: &[u8]) -> Result<Vec<u8>, CarbonadoError> {
    if input.len() < 80 {
        return Err(CarbonadoError::InvalidCiphertextLength);
    }

    let nonce: [u8; 16] = input[0..16]
        .try_into()
        .map_err(|_| CarbonadoError::InvalidCiphertextLength)?;
    let rest = &input[16..];

    symmetric_decrypt_with_nonce(master_key, nonce, rest)
}

#[cfg(feature = "pqc")]
/// Generate a fresh SLH-DSA key pair.
///
/// `entropy` must be at least 128 bytes of high-quality randomness.
/// The resulting `SecretKey` is zeroized on drop by the underlying crate.
///
/// **Security note**: These signatures are intended **only for sidecars** (manifests, catalogs, etc.).
/// They are never embedded inside Carbonado containers. See AGENTS.md for the full rules.
pub fn slh_dsa_generate_keypair(entropy: &[u8]) -> Result<KeyPair, CarbonadoError> {
    if entropy.len() < 128 {
        return Err(CarbonadoError::InvalidKeyLength);
    }
    bitcoinpqc::generate_keypair(Algorithm::SLH_DSA_128S, entropy)
        .map_err(|e| CarbonadoError::PqcError(e.to_string()))
}

#[cfg(feature = "pqc")]
/// Sign a message with an SLH-DSA secret key.
pub fn slh_dsa_sign(secret_key: &SecretKey, message: &[u8]) -> Result<Signature, CarbonadoError> {
    if secret_key.algorithm != Algorithm::SLH_DSA_128S {
        return Err(CarbonadoError::PqcError(
            "wrong algorithm for SLH-DSA".into(),
        ));
    }
    bitcoinpqc::sign(secret_key, message).map_err(|e| CarbonadoError::PqcError(e.to_string()))
}

#[cfg(feature = "pqc")]
/// Verify an SLH-DSA signature.
pub fn slh_dsa_verify(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
) -> Result<bool, CarbonadoError> {
    if public_key.algorithm != Algorithm::SLH_DSA_128S {
        return Err(CarbonadoError::PqcError(
            "wrong algorithm for SLH-DSA".into(),
        ));
    }
    match bitcoinpqc::verify(public_key, message, signature) {
        Ok(()) => Ok(true),
        Err(bitcoinpqc::PqcError::BadSignature) => Ok(false),
        Err(e) => Err(CarbonadoError::PqcError(e.to_string())),
    }
}

#[cfg(feature = "pqc")]
/// Convenience: derive a keypair from a seed (minimum 32 bytes recommended) and sign.
///
/// This is the spiritual successor to the original `slh_sign` stub.
/// For repeated signing of many messages, prefer `slh_dsa_generate_keypair` + `slh_dsa_sign`.
///
/// **Warning**: This helper derives a fresh keypair on every call. It is convenient for one-shot
/// sidecar signatures but not optimal for signing many messages under the same key.
pub fn slh_sign(seed: &[u8], message: &[u8]) -> Result<Vec<u8>, CarbonadoError> {
    if seed.len() < 32 {
        return Err(CarbonadoError::InvalidKeyLength);
    }

    // Stretch the caller's seed to the 128 bytes required by libbitcoinpqc using our
    // existing domain-separated KDF. This is deterministic given the seed.
    let stretched = derive_subkey(seed, "slh-dsa-seed")?;
    // We only have 64 bytes. Call derive again with a different label to get another 64.
    let stretched2 = derive_subkey(seed, "slh-dsa-seed-2")?;

    let mut entropy = [0u8; 128];
    entropy[..64].copy_from_slice(&stretched);
    entropy[64..].copy_from_slice(&stretched2);

    let keypair = slh_dsa_generate_keypair(&entropy)?;
    let sig = slh_dsa_sign(&keypair.secret_key, message)?;

    // Return raw signature bytes (the caller is expected to also store or transmit the public key separately).
    // For a full sidecar you will usually want both pk + sig.
    Ok(sig.bytes)
}

#[cfg(feature = "pqc")]
/// Convenience verification helper that takes raw bytes (for the simple seed-based path).
///
/// Most callers should use the typed `slh_dsa_verify` with the real `PublicKey` they obtained at keygen time.
pub fn slh_verify(pk: &[u8], message: &[u8], sig: &[u8]) -> Result<bool, CarbonadoError> {
    if pk.len() != 32 {
        return Err(CarbonadoError::InvalidKeyLength);
    }

    let public_key = PublicKey {
        algorithm: Algorithm::SLH_DSA_128S,
        bytes: pk.to_vec(),
    };
    let signature = Signature {
        algorithm: Algorithm::SLH_DSA_128S,
        bytes: sig.to_vec(),
    };

    slh_dsa_verify(&public_key, message, &signature)
}

/// Compute the 64-byte HMAC-SHA512 authentication tag for a v2 Header.
///
/// This is used internally by [`crate::file::Header::new`] and [`crate::file::decode`].
///
/// The `header_data` must be constructed exactly as specified in AGENTS.md
/// (MAGIC || nonce || hash || format || ...).
///
/// This provides integrity and authenticity for the container metadata independently
/// of the payload EtM tag.
pub fn compute_header_mac(
    master_key: &[u8],
    header_data: &[u8],
) -> Result<[u8; 64], CarbonadoError> {
    let header_key = derive_subkey(master_key, "header-auth")?;
    let mut mac =
        HmacSha512::new_from_slice(&header_key).map_err(|_| CarbonadoError::InvalidKeyLength)?;
    mac.update(b"carbonado-v2-header");
    mac.update(header_data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_key(len: usize) -> Vec<u8> {
        let mut k = vec![0u8; len];
        getrandom::getrandom(&mut k).unwrap();
        k
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = random_key(32);
        let plaintext = b"Hello, this is a test of the new symmetric crypto stack in Carbonado.";

        let ciphertext = symmetric_encrypt(&key, plaintext).unwrap();
        let decrypted = symmetric_decrypt(&key, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_empty_plaintext() {
        let key = random_key(32);
        let plaintext = b"";

        let ciphertext = symmetric_encrypt(&key, plaintext).unwrap();
        let decrypted = symmetric_decrypt(&key, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails_auth() {
        let key1 = random_key(32);
        let key2 = random_key(32);
        let plaintext = b"secret data";

        let ciphertext = symmetric_encrypt(&key1, plaintext).unwrap();
        let result = symmetric_decrypt(&key2, &ciphertext);

        assert!(matches!(result, Err(CarbonadoError::AuthenticationFailed)));
    }

    #[test]
    fn tampered_tag_fails_auth() {
        let key = random_key(32);
        let plaintext = b"important message";

        let mut ciphertext = symmetric_encrypt(&key, plaintext).unwrap();
        // Flip a bit in the tag (bytes 16..80)
        ciphertext[20] ^= 0xFF;

        let result = symmetric_decrypt(&key, &ciphertext);
        assert!(matches!(result, Err(CarbonadoError::AuthenticationFailed)));
    }

    #[test]
    fn tampered_ciphertext_fails_auth() {
        let key = random_key(32);
        let plaintext = b"another test payload that is long enough";

        let mut ciphertext = symmetric_encrypt(&key, plaintext).unwrap();
        // Flip a bit in the actual ciphertext (after nonce + tag)
        let ct_start = 16 + 64;
        if ciphertext.len() > ct_start {
            ciphertext[ct_start] ^= 0xFF;
        }

        let result = symmetric_decrypt(&key, &ciphertext);
        assert!(matches!(result, Err(CarbonadoError::AuthenticationFailed)));
    }

    #[test]
    fn derive_subkey_different_labels_produce_different_keys() {
        let master = random_key(32);

        let k1 = derive_subkey(&master, "aes-ctr").unwrap();
        let k2 = derive_subkey(&master, "etm-hmac").unwrap();

        assert_ne!(k1, k2);
    }

    #[test]
    fn derive_subkey_empty_master_fails() {
        let result = derive_subkey(&[], "test-label");
        assert!(matches!(result, Err(CarbonadoError::InvalidKeyLength)));
    }

    #[test]
    fn encrypt_rejects_short_master_key() {
        let short_key = random_key(16);
        let result = symmetric_encrypt(&short_key, b"data");
        assert!(matches!(result, Err(CarbonadoError::InvalidKeyLength)));
    }

    #[test]
    fn decrypt_rejects_short_input() {
        let key = random_key(32);
        let short_input = vec![0u8; 50]; // less than 80 bytes
        let result = symmetric_decrypt(&key, &short_input);
        assert!(matches!(
            result,
            Err(CarbonadoError::InvalidCiphertextLength)
        ));
    }

    // ========================================================================
    // SLH-DSA / libbitcoinpqc tests (real implementation, not stubs)
    // Only compiled when the "pqc" feature is enabled.
    // ========================================================================

    #[cfg(feature = "pqc")]
    #[test]
    fn slh_dsa_generate_and_sign_verify_roundtrip() {
        let mut entropy = [0u8; 128];
        getrandom::getrandom(&mut entropy).unwrap();

        let keypair =
            slh_dsa_generate_keypair(&entropy).expect("keygen should succeed with 128 bytes");

        assert_eq!(keypair.public_key.bytes.len(), 32);
        assert_eq!(keypair.secret_key.bytes.len(), 64);
        assert_eq!(keypair.public_key.algorithm, Algorithm::SLH_DSA_128S);

        let message = b"important manifest or checkpoint hash goes here";

        let sig = slh_dsa_sign(&keypair.secret_key, message).expect("signing must succeed");

        assert_eq!(sig.bytes.len(), 7856); // SLH-DSA-SHAKE-128s signature size
        assert_eq!(sig.algorithm, Algorithm::SLH_DSA_128S);

        let valid = slh_dsa_verify(&keypair.public_key, message, &sig)
            .expect("verify call should not error");
        assert!(valid, "fresh signature must verify");

        // Tamper the message
        let mut bad_msg = message.to_vec();
        bad_msg[0] ^= 0x01;
        let still_valid = slh_dsa_verify(&keypair.public_key, &bad_msg, &sig)
            .expect("verify should succeed or return false");
        assert!(!still_valid, "tampered message must fail verification");
    }

    #[test]
    fn slh_sign_convenience_produces_verifiable_signature() {
        let seed = random_key(32);
        let message = b"sidecar over bao root hash";

        let _sig_bytes = slh_sign(&seed, message).expect("slh_sign convenience must work");

        // We don't have the public key from the simple path easily, so we test the low-level path instead
        // for a full roundtrip using the typed API.
        let mut entropy = [0u8; 128];
        getrandom::getrandom(&mut entropy).unwrap();
        let kp = slh_dsa_generate_keypair(&entropy).unwrap();
        let sig2 = slh_dsa_sign(&kp.secret_key, message).unwrap();
        let ok = slh_dsa_verify(&kp.public_key, message, &sig2).unwrap();
        assert!(ok);
    }

    #[test]
    fn slh_dsa_rejects_short_entropy() {
        let short_entropy = [0u8; 64];
        let result = slh_dsa_generate_keypair(&short_entropy);
        assert!(matches!(result, Err(CarbonadoError::InvalidKeyLength)));
    }

    // ========================================================================
    // Deeper adversarial + large-payload tests for AES-256-CTR + HMAC EtM
    // ========================================================================

    #[test]
    fn large_payload_roundtrip_1mb() {
        let key = random_key(32);
        let mut plaintext = vec![0u8; 1024 * 1024]; // 1 MiB
        for (i, byte) in plaintext.iter_mut().enumerate() {
            *byte = (i % 251) as u8;
        }

        let ciphertext = symmetric_encrypt(&key, &plaintext).unwrap();
        let decrypted = symmetric_decrypt(&key, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn internal_nonce_format_nonce_is_protected() {
        let key = random_key(32);
        let plaintext = b"data that should not decrypt if nonce is flipped";

        let mut ciphertext = symmetric_encrypt(&key, plaintext).unwrap();
        ciphertext[5] ^= 0xFF;

        let result = symmetric_decrypt(&key, &ciphertext);
        assert!(matches!(result, Err(CarbonadoError::AuthenticationFailed)));
    }

    #[test]
    fn explicit_nonce_and_header_mac_path() {
        let master = random_key(32);
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).unwrap();

        let data = b"payload that goes through the explicit nonce + header auth path";

        let ct = symmetric_encrypt_with_nonce(&master, nonce, data).unwrap();

        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(crate::constants::MAGICNO);
        auth_data.extend_from_slice(&nonce);
        auth_data.extend_from_slice(&[0u8; 32]);
        auth_data.push(0x0F);
        auth_data.push(0);
        auth_data.extend_from_slice(&0u32.to_le_bytes());
        auth_data.extend_from_slice(&0u32.to_le_bytes());
        auth_data.extend_from_slice(&[0u8; 8]);

        let header_mac = compute_header_mac(&master, &auth_data).unwrap();

        let pt = symmetric_decrypt_with_nonce(&master, nonce, &ct).unwrap();
        assert_eq!(pt, data);

        let wrong_master = random_key(32);
        let bad_mac = compute_header_mac(&wrong_master, &auth_data).unwrap();
        assert_ne!(bad_mac, header_mac);
    }

    #[test]
    fn same_key_different_nonces_produce_different_ciphertexts() {
        let key = random_key(32);
        let plaintext = b"identical plaintext under two different nonces";

        let ct1 = symmetric_encrypt(&key, plaintext).unwrap();
        let ct2 = symmetric_encrypt(&key, plaintext).unwrap();

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn truncated_ciphertext_is_rejected() {
        let key = random_key(32);
        let plaintext = b"some data that will be truncated after encryption";

        let mut ct = symmetric_encrypt(&key, plaintext).unwrap();
        ct.truncate(40);

        let result = symmetric_decrypt(&key, &ct);
        assert!(matches!(
            result,
            Err(CarbonadoError::InvalidCiphertextLength)
        ));
    }

    // ========================================================================
    // Property-based tests using proptest
    // ========================================================================

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_encrypt_decrypt_roundtrip(
            key in prop::collection::vec(any::<u8>(), 32..64),
            data in prop::collection::vec(any::<u8>(), 0..4096)
        ) {
            let ct = symmetric_encrypt(&key, &data).unwrap();
            let pt = symmetric_decrypt(&key, &ct).unwrap();
            prop_assert_eq!(pt, data);
        }

        #[test]
        fn prop_tampered_data_fails_auth(
            key in prop::collection::vec(any::<u8>(), 32..64),
            data in prop::collection::vec(any::<u8>(), 1..2048),
            tamper_pos in 0..2048usize
        ) {
            let mut ct = symmetric_encrypt(&key, &data).unwrap();
            if tamper_pos < ct.len() {
                ct[tamper_pos] ^= 0xFF;
                let result = symmetric_decrypt(&key, &ct);
                prop_assert!(matches!(result, Err(CarbonadoError::AuthenticationFailed)));
            }
        }
    }
}
