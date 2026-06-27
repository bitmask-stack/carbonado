//! # Carbonado — Apocalypse-resistant archival format
//!
//! Carbonado is a single flat-file container format for long-term, consensus-critical data.
//!
//! It combines a fully symmetric, hardware-accelerated cryptographic stack
//! (AES-256-CTR + full HMAC-SHA512 EtM) with Bao streaming verifiability,
//! FEC (reed-solomon-erasure 4/8) forward error correction, optional Zstd (level 20) compression, and
//! SLH-DSA post-quantum signatures delivered exclusively as **sidecars**.
//!
//! ## Security Model & Production Guidance
//!
//! **This is a clean cryptographic break from the old ECIES design.**
//! The library contains no code to read or write v1 ECIES containers.
//!
//! All security invariants, nonce rules, subkey labels, SLH-DSA sidecar format,
//! and "never violate" rules are documented in [AGENTS.md](https://github.com/bitmask-stack/carbonado/blob/main/AGENTS.md#2-cryptographic-architecture-v2--current-target).
//!
//! Hardware acceleration is expected. Run with:
//! ```bash
//! RUSTFLAGS="-C target-cpu=native" cargo build
//! ```
//!
//! See the [benches/](https://github.com/bitmask-stack/carbonado/tree/main/benches) for measured performance numbers.
//!
//! ## Quick Start
//!
//! Using the low-level API (recommended for documentation examples):
//!
//! ```rust
//! use carbonado::{encode, decode};
//! use getrandom::getrandom;
//!
//! let mut master_key = [0u8; 32];
//! getrandom(&mut master_key).unwrap();
//!
//! let data = b"important archival payload";
//! let encoded = encode(&master_key, data, 15).unwrap();
//!
//! let recovered = decode(
//!     &master_key,
//!     encoded.1.as_bytes(),
//!     &encoded.0,
//!     encoded.2.padding_len,
//!     15,
//! ).unwrap();
//!
//! assert_eq!(recovered, data);
//! ```
//!
//! For passphrase-based keys, derive a 32-byte master key using a memory-hard KDF
//! such as Argon2id (recommended) before passing it to Carbonado.
//!
//! For post-quantum sidecar signatures, see [`crypto`] (especially the `slh_dsa_*` functions)
//! and the [sidecar example](https://github.com/bitmask-stack/carbonado/blob/main/examples/slh_dsa_sidecar.rs).

////////////////////////////////////////////////////////////////////////////////

/// For details on Carbonado formats and their uses, see the [Carbonado Format bitmask constant](constants::Format).
pub mod constants;
/// Symmetric cryptographic primitives for the v2 design.
///
/// This module is public for advanced use cases. Most applications should use the
/// high-level [`file`] module instead.
///
/// See the module-level documentation in [`crypto`] and AGENTS.md §2 for the
/// security model, nonce rules, and SLH-DSA sidecar requirements.
pub mod crypto;
/// Error types
pub mod error;
/// File helper methods.
pub mod file;
/// See [structs::EncodeInfo](structs::EncodeInfo) for various statistics gatthered in the encoding step.
pub mod structs;
/// Various utilities to assist with Carbonado encoding steps.
pub mod utils;

mod decoding;
mod encoding;

pub use encoding::encode;

pub use decoding::decode;

pub use decoding::extract_slice;

pub use decoding::verify_slice;

pub use decoding::scrub;

pub use bao;
