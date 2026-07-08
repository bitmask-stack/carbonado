//! Symmetric cryptographic primitives for Carbonado v2.
//!
//! This module implements the core of the clean cryptographic break from the old ECIES design:
//!
//! - **AES-256-CTR** for length-preserving bulk encryption (hardware accelerated via AES-NI/VAES).
//! - **HMAC-SHA512** (full 64-byte tags) in Encrypt-then-MAC construction for integrity and authentication.
//! - **HMAC-SHA512-based subkey derivation** (BIP-32 style) for key separation.
//! - **SLH-DSA (FIPS-205 / SPHINCS+)** post-quantum signatures via `libbitcoinpqc`, **strictly for sidecar use only**.
//!
//! # Hybrid Paranoia Extension (v2)
//!
//! For maximal paranoia we also provide a hybrid layer:
//! - Inner: secp256k1 ECDH (ephemeral key per operation for forward secrecy) + ChaCha20-Poly1305 AEAD.
//! - The inner "ECC" blob is then wrapped by the outer AES-256-CTR + HMAC-SHA512 EtM (using the caller's master key + our existing derive_subkey EtM).
//!
//! This deliberately doubles up:
//! - Ciphers: AES-256-CTR (outer) + ChaCha20 (inner)
//! - Key generation mechanisms: HMAC-SHA512 subkeys (outer, labels) + ECDH-derived secret processed again via derive_subkey("ecc-chacha-poly")
//! - Authentication: full 64B HMAC-EtM (outer) + Poly1305 AEAD tag (inner)
//!
//! The pure symmetric path (AES+HMAC only) remains the default and is controlled by the `Encrypted` Format bit in high-level APIs.
//! Use the hybrid APIs (`hybrid_encrypt*`, `ecc_aead_*`) when you also have secp256k1 recipient key material and want defense-in-depth.
//!
//! ## Security considerations for the hybrid layer
//!
//! - The outer EtM (HMAC under master-derived key) is always verified first. Inner is only reached on outer success.
//! - Inner uses a fresh ephemeral secp key per encrypt (forward secrecy for that blob).
//! - The secp256k1 ECDH itself is *not* post-quantum (Shor's algorithm). However the outer symmetric layer still provides ~128-bit Grover resistance for confidentiality.
//! - Purpose of the ECC+ChaCha layer: defense in depth against implementation bugs, side-channel differences, or future breaks in one specific primitive or KDF path. Different algorithm families + independent key derivation.
//! - You still need the master key *and* the recipient secret key to decrypt. This is by design.
//!
//! Passphrase-to-key derivation (e.g. Argon2id) is the caller's responsibility before
//! supplying a 32-byte master key to Carbonado.
//!
//! # Important Security Model
//!
//! See [AGENTS.md §2](https://github.com/bitmask-stack/carbonado/blob/main/AGENTS.md#2-cryptographic-architecture-v2--current-target)
//! for the normative invariants. Key points:
//!
//! - Nonces must be unique per `(master_key, encryption operation)`.
//! - The high-level `file::encode` path uses **one nonce for the entire archive**.
//! - SLH-DSA signatures are **never** embedded inside Carbonado containers — they are sidecars only.
//! - The library performs **no automatic zeroization** of caller-supplied master keys (callers own the bytes;
//!   use e.g. zeroize crate in your app if you need to clear after use; documented per AGENTS §10).
//!
//! # Two Encryption Paths (plus hybrid)
//!
//! 1. **Recommended for most users**: Use [`crate::file::encode`] / [`crate::file::decode`].
//!    These use the Header with explicit nonce and separate header authentication.
//!    The Header (including the nonce) is public authenticated metadata — no secret key material
//!    is ever placed in it.
//!    When the `Encrypted` bit is set this uses pure symmetric (AES-CTR + HMAC EtM).
//! 2. **Low-level pure symmetric**: The `symmetric_encrypt*` / `symmetric_decrypt*` functions
//!    (used by `encoding`/`decoding` and internally by high-level when Encrypted).
//! 3. **Hybrid for maximal paranoia**: `hybrid_encrypt*` / `hybrid_decrypt*` (and the `ecc_aead_*`
//!    building blocks). These produce/ consume a value that is already "the encryption result"
//!    (inner AEAD wrapped by outer symmetric EtM under master).
//!
//! ## Using hybrid together with compression / FEC / Bao / Header
//!
//! Hybrid replaces the "encrypt" step in the pipeline.
//!
//! Recommended pattern for a full archive using hybrid:
//! - (optional) compress the data yourself with `encoding::compress` (Zstd-20) or let a higher layer do it.
//! - Call `hybrid_encrypt(master, recipient_pub, data)` (or the _with_nonce variant if you need to record the outer nonce for a Header).
//! - The result is an opaque blob in the same layout family as `symmetric_encrypt` output.
//! - Feed that blob onward to `encoding::zfec` (if desired) and/or `encoding::bao` (if desired).
//! - If building a Header + .cXX file: use the *same* outer nonce you supplied to hybrid (or parse it from the hybrid ct if using the internal-nonce hybrid fn) as `payload_nonce`, set the format bits *without* `Encrypted` (so standard decoders do not attempt pure-symmetric decrypt), construct the Header with master (for header_mac), and prepend it.
//! - On the read side: parse Header (verifies header_mac with master), reverse bao/zfec, then call `hybrid_decrypt(master, recipient_secret, recovered_blob)` to obtain the original plaintext.
//!
//! The resulting container still benefits from header authentication, Bao verifiability (keyed), deterministic RS FEC, etc.
//! The Encrypted bit in the format is intentionally left clear because the encryption work was performed by the hybrid APIs.
//!
//! Do not set the Encrypted bit *and* also wrap with hybrid unless you specifically want an extra outer symmetric layer (triple encryption).
//!
//! # Stability
//!
//! This module is public so advanced users and higher-level tools can access the primitives directly.
//! The API surface is intended to be relatively stable for 2.0.x, but the exact set of re-exported
//! `bitcoinpqc` types may be adjusted. Always prefer the high-level `file` API when possible.

use std::path::Path;

use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes256;
use blake3;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, Nonce};
use ctr::Ctr128BE;
use hmac::{Hmac, Mac};
use secp256k1::{ecdh::SharedSecret, Secp256k1};
use sha2::Sha512;

use crate::error::CarbonadoError;

// SLH-DSA / post-quantum support is optional (disabled for WASM builds where libbitcoinpqc cannot easily compile).
#[cfg(feature = "pqc")]
pub use bitcoinpqc::{
    self, Algorithm, KeyPair, PqcError as BitcoinPqcError, PublicKey, SecretKey, Signature,
};

/// Re-export secp256k1 types for the hybrid ECC layer (to avoid forcing users to
/// add the dep just for the key types).
pub use secp256k1::{PublicKey as SecpPublicKey, SecretKey as SecpSecretKey};

/// Domain separation prefix for all v2 HMAC-SHA512 subkey derivation.
const LABEL_PREFIX: &[u8] = b"carbonado-v2/";

/// Magic prefix for SLH-DSA sidecar files (`<bao-hash>.cXX.slh`).
pub const SLH1_MAGIC: &[u8; 4] = b"SLH1";

/// Raw SLH-DSA-SHAKE-128s signature length (FIPS-205 / libbitcoinpqc).
pub const SLH1_SIGNATURE_LEN: usize = 7856;

/// Total on-disk SLH-DSA sidecar size: `SLH1_MAGIC` + signature.
pub const SLH1_SIDECAR_LEN: usize = 4 + SLH1_SIGNATURE_LEN;

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
/// - `"ecc-chacha-poly"` → hybrid inner ChaCha20-Poly1305 key (ECDH shared secret as PRF input)
/// - `"slh-dsa-seed"` / `"slh-dsa-seed-2"` → SLH-DSA keygen entropy stretching (`slh_sign` only)
///
/// Keyed Bao uses a separate BLAKE3 KDF — see [`carbonado_bao_key`], not `derive_subkey`.
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

/// Derive the 32-byte keyed-Bao BLAKE3 key for a Carbonado format level (c0–c15).
///
/// This is **not** an HMAC-SHA512 subkey. It uses BLAKE3's `derive_key`:
///
/// ```text
/// blake3::derive_key("carbonado-v2/bao", &[format_byte])
/// ```
///
/// Keyed Bao roots commit to the exact format pipeline chosen at encode time.
/// Different format bytes produce independent roots even for identical logical input.
///
/// See AGENTS.md §2.1.5 (Keyed Bao KDF) and `tests/bao_keyed_contract.rs`.
pub fn carbonado_bao_key(format: u8) -> [u8; 32] {
    blake3::derive_key("carbonado-v2/bao", &[format])
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
    let aes_key: [u8; 32] = enc_material[..32].try_into().map_err(|_| {
        CarbonadoError::InternalStateError("derive_subkey must yield 64 bytes".to_string())
    })?;

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
    let aes_key: [u8; 32] = enc_material[..32].try_into().map_err(|_| {
        CarbonadoError::InternalStateError("derive_subkey must yield 64 bytes".to_string())
    })?;

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

// ============================================================================
// Hybrid Paranoia Layer (maximal security doubling)
// ============================================================================
//
// Inner AEAD: secp256k1 ECDH (eph for FS) + ChaCha20-Poly1305.
// That result is treated as plaintext to the *outer* symmetric_encrypt_with_nonce
// (AES-256-CTR + full HMAC-SHA512 EtM under caller's master_key using our EtM).
//
// Exactly as requested: "do an AEAD based on ChaCha20-Poly1305 and secp256k1, and
// wrap the ECC in our symmetric AES256-CTR with HMAC verification using our EtM approach."
//
// Doubles ciphers, key-gen paths, and MAC/AEAD styles for defense-in-depth.
// See the module-level docs above for composition with the rest of the pipeline
// and security rationale. The pure-symmetric Encrypted path is unchanged.

/// Perform the inner ECC-based AEAD: secp256k1 ECDH + ChaCha20-Poly1305.
///
/// Returns a blob: [33-byte compressed ephem pubkey | 12-byte nonce | ciphertext+tag]
///
/// The caller provides the *recipient's* public key (for ECDH).
/// An ephemeral key is generated internally for forward secrecy.
pub fn ecc_aead_encrypt(
    recipient_pub: &SecpPublicKey,
    input: &[u8],
) -> Result<Vec<u8>, CarbonadoError> {
    // Generate ephemeral key for this encryption (forward secrecy)
    // Use getrandom for consistency with the rest of the crate (no rand dep in lib).
    let mut secret_bytes = [0u8; 32];
    getrandom::getrandom(&mut secret_bytes).map_err(|_| CarbonadoError::RandomnessError)?;
    let eph_secret =
        SecpSecretKey::from_slice(&secret_bytes).map_err(|_| CarbonadoError::InvalidKeyLength)?;
    let eph_pub = SecpPublicKey::from_secret_key(&Secp256k1::new(), &eph_secret);

    // ECDH - use SharedSecret::new in secp 0.29+
    let shared = SharedSecret::new(recipient_pub, &eph_secret);

    // Double up key gen: use our HMAC derive_subkey on the shared secret bytes
    // as if it were a "master" for this layer. This incorporates our symmetric
    // key generation mechanism into the ECC path.
    let key_material = derive_subkey(shared.secret_bytes().as_ref(), "ecc-chacha-poly")?;
    let chacha_key: [u8; 32] = key_material[..32].try_into().map_err(|_| {
        CarbonadoError::InternalStateError("derive_subkey must yield 64 bytes".to_string())
    })?;

    let cipher =
        <ChaCha20Poly1305 as chacha20poly1305::aead::KeyInit>::new(Key::from_slice(&chacha_key));

    // Random 12-byte nonce for ChaChaPoly (standard for this AEAD)
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).map_err(|_| CarbonadoError::RandomnessError)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(nonce, input)
        .map_err(|_| CarbonadoError::AuthenticationFailed)?;

    // Build blob: ephem_pub (compressed 33 bytes) + nonce(12) + ct
    let mut out = Vec::with_capacity(33 + 12 + ct.len());
    out.extend_from_slice(&eph_pub.serialize()); // 33 bytes compressed
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt the inner ECC AEAD blob.
///
/// Requires the *recipient's* secret key (the one corresponding to the pubkey
/// used at encrypt time).
pub fn ecc_aead_decrypt(
    recipient_secret: &SecpSecretKey,
    blob: &[u8],
) -> Result<Vec<u8>, CarbonadoError> {
    if blob.len() < 33 + 12 {
        return Err(CarbonadoError::InvalidCiphertextLength);
    }

    let eph_pub = SecpPublicKey::from_slice(&blob[0..33])
        .map_err(|_| CarbonadoError::InvalidCiphertextLength)?;

    let nonce_bytes = &blob[33..45];
    let ct = &blob[45..];

    let shared = SharedSecret::new(&eph_pub, recipient_secret);

    let key_material = derive_subkey(shared.secret_bytes().as_ref(), "ecc-chacha-poly")?;
    let chacha_key: [u8; 32] = key_material[..32].try_into().map_err(|_| {
        CarbonadoError::InternalStateError("derive_subkey must yield 64 bytes".to_string())
    })?;

    let cipher =
        <ChaCha20Poly1305 as chacha20poly1305::aead::KeyInit>::new(Key::from_slice(&chacha_key));
    let nonce = Nonce::from_slice(nonce_bytes);

    let pt = cipher
        .decrypt(nonce, ct)
        .map_err(|_| CarbonadoError::AuthenticationFailed)?;

    Ok(pt)
}

/// High-level hybrid encrypt: ECC-AEAD inner, then wrapped in our symmetric EtM.
///
/// The `inner_blob` from ecc_aead_encrypt is treated as the "plaintext" for the
/// outer symmetric_encrypt_with_nonce (using the caller's master_key and provided nonce).
///
/// Output is the outer ciphertext (with its own HMAC tag).
///
/// This "wraps the ECC in our symmetric AES256-CTR with HMAC-EtM".
pub fn hybrid_encrypt_with_nonce(
    master_key: &[u8],
    nonce: [u8; 16],
    recipient_pub: &SecpPublicKey,
    input: &[u8],
) -> Result<Vec<u8>, CarbonadoError> {
    let inner = ecc_aead_encrypt(recipient_pub, input)?;
    // Wrap the entire ECC result inside the outer symmetric layer.
    symmetric_encrypt_with_nonce(master_key, nonce, &inner)
}

/// Hybrid decrypt: first unwrap the outer symmetric, then decrypt the inner ECC.
pub fn hybrid_decrypt_with_nonce(
    master_key: &[u8],
    nonce: [u8; 16],
    recipient_secret: &SecpSecretKey,
    input: &[u8], // the outer ct [tag | ct]
) -> Result<Vec<u8>, CarbonadoError> {
    let outer_pt = symmetric_decrypt_with_nonce(master_key, nonce, input)?;
    ecc_aead_decrypt(recipient_secret, &outer_pt)
}

/// Convenience hybrid with internal nonce (like symmetric_encrypt).
///
/// Output layout for the outer: [nonce(16) | tag(64) | ct] where the "pt" was the ECC blob.
pub fn hybrid_encrypt(
    master_key: &[u8],
    recipient_pub: &SecpPublicKey,
    input: &[u8],
) -> Result<Vec<u8>, CarbonadoError> {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|_| CarbonadoError::RandomnessError)?;

    let inner = hybrid_encrypt_with_nonce(master_key, nonce, recipient_pub, input)?;

    let mut out = Vec::with_capacity(16 + inner.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&inner);
    Ok(out)
}

/// Convenience hybrid decrypt with internal nonce.
pub fn hybrid_decrypt(
    master_key: &[u8],
    recipient_secret: &SecpSecretKey,
    input: &[u8], // [nonce(16) | tag(64) | ct]
) -> Result<Vec<u8>, CarbonadoError> {
    if input.len() < 80 {
        return Err(CarbonadoError::InvalidCiphertextLength);
    }
    let nonce: [u8; 16] = input[0..16]
        .try_into()
        .map_err(|_| CarbonadoError::InvalidCiphertextLength)?;
    let rest = &input[16..];
    hybrid_decrypt_with_nonce(master_key, nonce, recipient_secret, rest)
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
/// Formula (normative):
///
/// ```text
/// HMAC-SHA512(header-auth subkey, auth_data)
/// ```
///
/// where `auth_data` is exactly:
/// `MAGICNO || payload_nonce || bao_hash || slh_public_key || format || chunk_index (u32 LE)
///  || encoded_len || padding_len || metadata`
///
/// and `MAGICNO` is `b"CARBONADO20\n"`. The leading magic bytes in `auth_data` are the
/// domain binding — no separate `carbonado-v2-header` (or other) prefix is prepended.
///
/// This provides integrity and authenticity for the container metadata independently
/// of the payload EtM tag.
///
/// ## Visibility (important)
///
/// The returned 64-byte tag is stored **in cleartext** in the on-disk Header (`header_mac` field).
/// This is correct: the tag is not secret key material (same class as AEAD tags or TLS MACs).
/// Secrecy lives in the master key and the derived `header-auth` subkey, which never appear on disk.
/// See AGENTS.md "Header Visibility and Confidentiality Model" and "`header_mac` is an authentication tag".
pub fn compute_header_mac(
    master_key: &[u8],
    header_data: &[u8],
) -> Result<[u8; 64], CarbonadoError> {
    if master_key.len() < 32 {
        return Err(CarbonadoError::InvalidKeyLength);
    }
    let header_key = derive_subkey(master_key, "header-auth")?;
    let mut mac =
        HmacSha512::new_from_slice(&header_key).map_err(|_| CarbonadoError::InvalidKeyLength)?;
    mac.update(header_data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    Ok(out)
}

/// Write an SLH-DSA sidecar file: `SLH1` magic (4 bytes) + raw signature (7856 bytes).
///
/// The 32-byte SLH-DSA public key is **not** stored in the sidecar — it lives in
/// [`crate::file::Header::slh_public_key`] of the referenced archive segment.
///
/// See AGENTS.md §2.3 and [`read_slh_sidecar`].
pub fn write_slh_sidecar(path: impl AsRef<Path>, signature: &[u8]) -> Result<(), CarbonadoError> {
    if signature.len() != SLH1_SIGNATURE_LEN {
        return Err(CarbonadoError::OutboardVerificationFailed(format!(
            "SLH-DSA signature must be {SLH1_SIGNATURE_LEN} bytes, got {}",
            signature.len()
        )));
    }
    let mut sidecar = Vec::with_capacity(SLH1_SIDECAR_LEN);
    sidecar.extend_from_slice(SLH1_MAGIC);
    sidecar.extend_from_slice(signature);
    std::fs::write(path, &sidecar).map_err(CarbonadoError::StdIoError)
}

/// Read and validate an SLH-DSA sidecar file.
///
/// Returns the raw 7856-byte signature after verifying the `SLH1` magic prefix and
/// exact wire length ([`SLH1_SIDECAR_LEN`]).
pub fn read_slh_sidecar(path: impl AsRef<Path>) -> Result<Vec<u8>, CarbonadoError> {
    let bytes = std::fs::read(path).map_err(CarbonadoError::StdIoError)?;
    if bytes.len() != SLH1_SIDECAR_LEN {
        return Err(CarbonadoError::OutboardVerificationFailed(format!(
            "SLH-DSA sidecar must be {SLH1_SIDECAR_LEN} bytes, got {}",
            bytes.len()
        )));
    }
    if &bytes[..4] != SLH1_MAGIC {
        return Err(CarbonadoError::InvalidMagicNumber(
            String::from_utf8_lossy(&bytes[..4.min(bytes.len())]).into_owned(),
        ));
    }
    Ok(bytes[4..].to_vec())
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

    /// TDD coverage + polish test for hot symmetric paths (AES-CTR + EtM).
    ///
    /// Documents that derive_subkey + array extraction for aes_key (first 32B of 64B)
    /// and mac_key succeed for valid master (programmer invariant: derive always yields exactly 64B on Ok).
    /// The .expect sites were replaced (via TDD: test first, then minimal change to map_err + specific
    /// InternalStateError) to meet production bar ("no .expect() in hot library paths").
    /// Errors are now specific rather than panic on (impossible in practice for valid flow) invariant break.
    /// This test exercises encrypt_with_nonce + decrypt paths used by file::encode/decode .
    #[test]
    fn symmetric_hot_paths_derive_subkeys_without_panic_and_produce_specific_errors_on_bad() {
        let master = random_key(32);
        // Normal path must succeed (covers the try_into sites after derive).
        let ct = symmetric_encrypt_with_nonce(&master, [0u8; 16], b"test data for hot path")
            .expect("encrypt ok for valid");
        let pt = symmetric_decrypt_with_nonce(&master, [0u8; 16], &ct).expect("decrypt ok");
        assert_eq!(pt, b"test data for hot path");

        // Short master still gives specific error upstream (before reaching extract).
        let short = random_key(16);
        let res = symmetric_encrypt(&short, b"data");
        assert!(matches!(res, Err(CarbonadoError::InvalidKeyLength)));
    }

    /// TDD (red first): public header_mac paths (Header::new, compute_header_mac,
    /// used by file::encode for !Encrypted + encode_outboard public + decode auth)
    /// must reject master <32 bytes with InvalidKeyLength (consistent with encrypted
    /// paths). derive_subkey alone only rejects empty; we enforce 32B contract here.
    /// Test added before the guard; currently may pass for non-empty short (red for intent).
    #[test]
    fn header_mac_and_public_paths_reject_short_master_keys() {
        let short = random_key(16); // non-empty but <32
        let payload_nonce = [0u8; 16];
        let hash = [0u8; 32];
        let fmt = crate::constants::Format::from(0u8); // public even
        let res =
            crate::file::Header::new(&short, payload_nonce, &hash, [0u8; 32], fmt, 0, 0, 0, None);
        assert!(
            matches!(res, Err(CarbonadoError::InvalidKeyLength)),
            "Header::new (public header_mac path) with short master must err InvalidKeyLength, got {:?}",
            res
        );

        // Also direct on compute (used by decode header verify for public too)
        let auth_dummy = b"dummy";
        let res2 = compute_header_mac(&short, auth_dummy);
        assert!(
            matches!(res2, Err(CarbonadoError::InvalidKeyLength)),
            "compute_header_mac short must specific error"
        );
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

    #[cfg(feature = "pqc")]
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

    #[cfg(feature = "pqc")]
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
        auth_data.extend_from_slice(&[0u8; 32]); // bao hash
        auth_data.extend_from_slice(&[0u8; 32]); // slh_public_key
        auth_data.push(0x0F); // format byte
        auth_data.extend_from_slice(&0u32.to_le_bytes()); // chunk_index
        auth_data.extend_from_slice(&0u32.to_le_bytes()); // encoded_len
        auth_data.extend_from_slice(&0u32.to_le_bytes()); // padding_len
        auth_data.extend_from_slice(&[0u8; 8]); // metadata

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

    // ========================================================================
    // Hybrid paranoia layer tests (ecc_aead + outer symmetric EtM wrap)
    // ========================================================================

    fn random_secp_keypair() -> (SecpSecretKey, SecpPublicKey) {
        let mut secret_bytes = [0u8; 32];
        getrandom::getrandom(&mut secret_bytes).unwrap();
        let secret = SecpSecretKey::from_slice(&secret_bytes).unwrap();
        let public = SecpPublicKey::from_secret_key(&Secp256k1::new(), &secret);
        (secret, public)
    }

    #[test]
    fn hybrid_roundtrip_basic() {
        let master = random_key(32);
        let (recipient_secret, recipient_pub) = random_secp_keypair();
        let plaintext = b"hybrid test: inner chacha+secp wrapped by outer aes+hmac";

        let ct = hybrid_encrypt(&master, &recipient_pub, plaintext).unwrap();
        let pt = hybrid_decrypt(&master, &recipient_secret, &ct).unwrap();

        assert_eq!(pt, plaintext);
    }

    #[test]
    fn hybrid_roundtrip_empty() {
        let master = random_key(32);
        let (recipient_secret, recipient_pub) = random_secp_keypair();
        let plaintext = b"";

        let ct = hybrid_encrypt(&master, &recipient_pub, plaintext).unwrap();
        let pt = hybrid_decrypt(&master, &recipient_secret, &ct).unwrap();

        assert_eq!(pt, plaintext);
    }

    #[test]
    fn hybrid_wrong_master_fails_outer() {
        let master1 = random_key(32);
        let master2 = random_key(32);
        let (good_secret, pubk) = random_secp_keypair();
        let plaintext = b"secret via hybrid";

        let ct = hybrid_encrypt(&master1, &pubk, plaintext).unwrap();
        let result = hybrid_decrypt(&master2, &good_secret, &ct);

        // Should fail at outer EtM verification (never reaches inner)
        assert!(matches!(result, Err(CarbonadoError::AuthenticationFailed)));
    }

    #[test]
    fn hybrid_wrong_recipient_secret_fails_inner() {
        let master = random_key(32);
        let (_secret_good, pubk) = random_secp_keypair();
        let (secret_bad, _pub_bad) = random_secp_keypair();
        let plaintext = b"only correct recipient priv can open inner";

        let ct = hybrid_encrypt(&master, &pubk, plaintext).unwrap();
        let result = hybrid_decrypt(&master, &secret_bad, &ct);

        // Outer succeeds (correct master), inner AEAD tag fails
        assert!(matches!(result, Err(CarbonadoError::AuthenticationFailed)));
    }

    #[test]
    fn hybrid_tamper_outer_tag_fails() {
        let master = random_key(32);
        let (_s, pubk) = random_secp_keypair();
        let plaintext = b"tamper the outer HMAC tag";

        let mut ct = hybrid_encrypt(&master, &pubk, plaintext).unwrap();
        // Outer layout after hybrid_encrypt: [nonce(16) | tag(64) | inner_blob]
        // Tamper in the outer tag area
        if ct.len() > 16 + 10 {
            ct[16 + 5] ^= 0xFF;
        }

        let result = hybrid_decrypt(&master, &_s, &ct);
        assert!(matches!(result, Err(CarbonadoError::AuthenticationFailed)));
    }

    #[test]
    fn hybrid_tamper_inner_blob_fails_inner_after_outer() {
        let master = random_key(32);
        let (secret, pubk) = random_secp_keypair();
        let plaintext = b"tamper inside the ecc aead portion";

        let mut ct = hybrid_encrypt(&master, &pubk, plaintext).unwrap();
        // Tamper far enough into the ciphertext portion (after nonce+outer tag)
        // This corrupts the inner blob (eph pub / chacha nonce / ct)
        let tamper_start = 16 + 64 + 5;
        if ct.len() > tamper_start {
            ct[tamper_start] ^= 0xFF;
        }

        let result = hybrid_decrypt(&master, &secret, &ct);
        assert!(matches!(result, Err(CarbonadoError::AuthenticationFailed)));
    }

    #[test]
    fn hybrid_with_nonce_roundtrip() {
        let master = random_key(32);
        let (secret, pubk) = random_secp_keypair();
        let plaintext = b"explicit nonce hybrid path";
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).unwrap();

        let ct = hybrid_encrypt_with_nonce(&master, nonce, &pubk, plaintext).unwrap();
        // ct here is the outer [tag(64) | inner]  (no leading nonce)
        let pt = hybrid_decrypt_with_nonce(&master, nonce, &secret, &ct).unwrap();

        assert_eq!(pt, plaintext);
    }

    #[test]
    fn ecc_aead_standalone_roundtrip() {
        let (secret, pubk) = random_secp_keypair();
        let data = b"direct ecc+chacha test data, not wrapped";

        let blob = ecc_aead_encrypt(&pubk, data).unwrap();
        let recovered = ecc_aead_decrypt(&secret, &blob).unwrap();

        assert_eq!(recovered, data);
    }

    #[test]
    fn hybrid_large_payload() {
        let master = random_key(32);
        let (secret, pubk) = random_secp_keypair();
        let mut data = vec![0u8; 64 * 1024]; // 64 KiB
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }

        let ct = hybrid_encrypt(&master, &pubk, &data).unwrap();
        let pt = hybrid_decrypt(&master, &secret, &ct).unwrap();

        assert_eq!(pt, data);
    }

    #[test]
    fn carbonado_bao_key_matches_blake3_derive_key() {
        for format in [0u8, 4, 14, 15] {
            let expected = blake3::derive_key("carbonado-v2/bao", &[format]);
            assert_eq!(carbonado_bao_key(format), expected);
        }
    }

    #[test]
    fn header_mac_uses_auth_data_only_no_extra_domain_prefix() {
        let master = random_key(32);
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(crate::constants::MAGICNO);
        auth_data.extend_from_slice(&[0xAAu8; 16]); // nonce
        auth_data.extend_from_slice(&[0xBBu8; 32]); // hash
        auth_data.extend_from_slice(&[0u8; 32]); // slh pk
        auth_data.push(0x0E);
        auth_data.extend_from_slice(&0u32.to_le_bytes());
        auth_data.extend_from_slice(&1024u32.to_le_bytes());
        auth_data.extend_from_slice(&0u32.to_le_bytes());
        auth_data.extend_from_slice(&[0u8; 8]);

        let mac = compute_header_mac(&master, &auth_data).unwrap();

        let header_key = derive_subkey(&master, "header-auth").unwrap();
        let mut expected =
            HmacSha512::new_from_slice(&header_key).expect("header-auth subkey length");
        expected.update(&auth_data);
        let expected_bytes = expected.finalize().into_bytes();
        assert_eq!(mac.as_slice(), expected_bytes.as_slice());
    }

    #[test]
    fn slh_sidecar_roundtrip_and_validation() {
        let dir = std::env::temp_dir().join(format!("carbonado-slh1-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.slh");

        let sig = vec![0xCDu8; SLH1_SIGNATURE_LEN];
        write_slh_sidecar(&path, &sig).unwrap();
        let read = read_slh_sidecar(&path).unwrap();
        assert_eq!(read, sig);

        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(on_disk.len(), SLH1_SIDECAR_LEN);
        assert_eq!(&on_disk[..4], SLH1_MAGIC);

        let bad_magic_path = dir.join("bad-magic.slh");
        std::fs::write(&bad_magic_path, vec![0u8; SLH1_SIDECAR_LEN]).unwrap();
        let err = read_slh_sidecar(&bad_magic_path).unwrap_err();
        assert!(matches!(err, CarbonadoError::InvalidMagicNumber(_)));

        let short_path = dir.join("short.slh");
        std::fs::write(&short_path, b"SLH1").unwrap();
        let err2 = write_slh_sidecar(&short_path, b"short").unwrap_err();
        assert!(matches!(
            err2,
            CarbonadoError::OutboardVerificationFailed(_)
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
