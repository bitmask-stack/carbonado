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
//! header visibility (`header_mac` is a public tag, not secret key material),
//! CLI key handling (§7.2), and "never violate" rules are documented in
//! [AGENTS.md](https://github.com/bitmask-stack/carbonado/blob/main/AGENTS.md#2-cryptographic-architecture-v2--current-target).
//!
//! Hardware acceleration is expected. Run with:
//! ```bash
//! RUSTFLAGS="-C target-cpu=native" cargo build
//! ```
//!
//! See the [Benchmarks](https://github.com/bitmask-stack/carbonado/blob/main/README.md#benchmarks)
//! table in README.md for measured throughput numbers (run with `RUSTFLAGS="-C target-cpu=native"`).
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

/// Dual-backend dispatch (`backend-rust` / `backend-lean`). See docs/TEST_CONTRACT.md.
pub mod backend;

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
pub use crypto::carbonado_verification_key;
/// Error types
pub mod error;
/// File helper methods.
pub mod file;
/// See [structs::EncodeInfo](structs::EncodeInfo) for various statistics gathered in the encoding step.
pub mod structs;
/// Various utilities to assist with Carbonado encoding steps.
pub mod utils;

/// Adamantine 1.0 wire envelope for directory catalog payloads.
pub mod adamantine;
/// Adamantine payload body (rkyv manifest + centralized Bao bundle).
pub mod adamantine_payload;
mod decoding;
/// Directory archive helpers (segment format policy).
pub mod directory;
mod encoding;
pub mod filepack;
/// rkyv FilepackManifest schema (canonical directory manifest).
pub mod filepack_manifest;
#[cfg(feature = "ots")]
/// OpenTimestamps stub stamping for Bao-root binding.
pub mod ots;

/// Deprecated: use [`filepack_manifest`] instead.
#[deprecated(since = "2.1.0", note = "renamed to filepack_manifest")]
#[allow(deprecated)]
pub mod pack_index {
    pub use crate::filepack_manifest::*;
    pub use crate::{
        PackEntry, PackIndex, PackSegmentRef, MAX_PACK_ENTRIES, PACK_INDEX_FORMAT_LEVEL,
        PACK_INDEX_FORMAT_LEVEL_ENCRYPTED, PACK_INDEX_FORMAT_LEVEL_PUBLIC, PACK_INDEX_VERSION,
    };
}
/// Clap schema for the `carbonado` binary (`cli` feature).
#[cfg(feature = "cli")]
pub mod cli_app;
/// On-disk artifact naming and sidecar path helpers (CLI + directory decode).
pub mod paths;
/// Seekable verified Bao slice reads (P1).
pub mod stream;

pub use encoding::encode;

pub use encoding::encode_outboard;

pub use decoding::decode;

pub use decoding::decode_outboard;

pub use decoding::extract_slice;

pub use decoding::verify_slice;

pub use decoding::scrub;

pub use decoding::scrub_outboard;

#[doc(hidden)]
pub use decoding::verify_inboard_keyed_oracle;

pub use paths::{detect_archive_layout, ArchiveLayout};
#[cfg(feature = "async")]
pub use stream::stream_decode_async;
pub use stream::{
    decode_shards_stream, encode_shard_stream, stream_decode, stream_decode_buffer,
    stream_decode_outboard, stream_decode_outboard_buffer, stream_encode_buffer,
    stream_encode_outboard_buffer, verify_slice_inboard_seekable, verify_slice_outboard,
    ShardEncodeResult, ShardSource, DEFAULT_SEGMENT_PLAINTEXT_BUDGET,
};

pub use bao;

pub use structs::OutboardEncoded;

pub use filepack::{
    pack_directory, parse_filepack_cbor, FilepackCborEntry, Packed, MAX_FILEPACK_CBOR_MANIFEST_LEN,
    MAX_FILEPACK_PACKAGE_DEPTH,
};

pub use adamantine::{
    decode_adamantine, encode_adamantine, AdamantineHeader, ADAMANTINE_CARBONADO_FMT_ENCRYPTED,
    ADAMANTINE_CARBONADO_FMT_PUBLIC, ADAMANTINE_FLAG_REQUIRE_OTS, ADAMANTINE_HEADER_LEN,
    ADAMANTINE_MAGIC,
};
pub use adamantine_payload::{
    build_adamantine_payload, fec_slice_from_bundle, split_adamantine_payload,
    verification_slice_from_bundle, MAX_ADAMANTINE_PAYLOAD_LEN, MAX_BAO_BUNDLE_LEN,
};
pub use directory::SegmentFormatPolicy;

pub use filepack_manifest::{
    expected_fec_parity_len, FilepackEntry, FilepackManifest, FilepackSegmentMap, SegmentRef,
    FILEPACK_MANIFEST_FORMAT_LEVEL, FILEPACK_MANIFEST_FORMAT_LEVEL_ENCRYPTED,
    FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC, FILEPACK_MANIFEST_VERSION,
    MAX_FILEPACK_MANIFEST_ENTRIES, MAX_SEGMENT_MAIN_LEN,
};

/// Deprecated: renamed to [`FilepackManifest`].
#[deprecated(since = "2.1.0", note = "renamed to FilepackManifest")]
pub type PackIndex = FilepackManifest;

/// Deprecated: renamed to [`FilepackEntry`].
#[deprecated(since = "2.1.0", note = "renamed to FilepackEntry")]
pub type PackEntry = FilepackEntry;

/// Deprecated: renamed to [`SegmentRef`].
#[deprecated(since = "2.1.0", note = "renamed to SegmentRef")]
pub type PackSegmentRef = SegmentRef;

/// Deprecated: renamed to [`FILEPACK_MANIFEST_VERSION`].
#[deprecated(since = "2.1.0", note = "renamed to FILEPACK_MANIFEST_VERSION")]
pub const PACK_INDEX_VERSION: u32 = FILEPACK_MANIFEST_VERSION;

/// Deprecated: renamed to [`FILEPACK_MANIFEST_FORMAT_LEVEL`].
#[deprecated(since = "2.1.0", note = "renamed to FILEPACK_MANIFEST_FORMAT_LEVEL")]
pub const PACK_INDEX_FORMAT_LEVEL: u8 = FILEPACK_MANIFEST_FORMAT_LEVEL;

/// Deprecated: renamed to [`FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC`].
#[deprecated(
    since = "2.1.0",
    note = "renamed to FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC"
)]
pub const PACK_INDEX_FORMAT_LEVEL_PUBLIC: u8 = FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC;

/// Deprecated: renamed to [`FILEPACK_MANIFEST_FORMAT_LEVEL_ENCRYPTED`].
#[deprecated(
    since = "2.1.0",
    note = "renamed to FILEPACK_MANIFEST_FORMAT_LEVEL_ENCRYPTED"
)]
pub const PACK_INDEX_FORMAT_LEVEL_ENCRYPTED: u8 = FILEPACK_MANIFEST_FORMAT_LEVEL_ENCRYPTED;

/// Deprecated: renamed to [`MAX_FILEPACK_MANIFEST_ENTRIES`].
#[deprecated(since = "2.1.0", note = "renamed to MAX_FILEPACK_MANIFEST_ENTRIES")]
pub const MAX_PACK_ENTRIES: usize = MAX_FILEPACK_MANIFEST_ENTRIES;

#[cfg(feature = "ots")]
pub use ots::{stamp_bao_root, verify_stamp, OtsPolicy, OtsVerification};

pub use file::{
    decode_directory, encode_directory, encode_directory_with_options, DirectoryArchive,
    DirectoryEncodeOptions, DIRECTORY_ARCHIVE_FORMAT, DIRECTORY_ARCHIVE_FORMAT_ENCRYPTED,
    DIRECTORY_TEST_SEGMENT_BUDGET,
};
