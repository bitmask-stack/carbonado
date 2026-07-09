# Changelog

All notable changes to the Carbonado crate and `carbonado` CLI are documented here.

## [Unreleased] — 2.1.0 (directory archive redesign)

### Added

- **`bitcoinpqc` 0.4:** migrate from crates.io `libbitcoinpqc` 0.1 to `bitcoinpqc` 0.4 (WASM-capable bindings). SLH-DSA parameter set is now **SHA2-128s** (`SLH_DSA_SHA2_128S`); SHAKE-128s sidecars from dev builds are incompatible — re-sign if needed. Temporary `.cargo/config.toml` `[patch.crates-io]` — delete on or after **2026-07-18** once registry mirrors sync.
- **Phase 3 CPU parallelism (`parallel` feature, default on):** scoped fork-join RS parity generation in `FecInboardEncoder::take_stripe` (`src/stream/parallel.rs`); `ParallelConfig::max_threads` caps per-wave workers; output bit-identical to serial `rs.encode`. WASM compiles with `parallel` but stays serial at runtime. Disable with `--no-default-features` for serial-only builds. Tests: `tests/parallel_determinism.rs` (default), `tests/serial_fec_path.rs` (no-`parallel` CI gate); bench: `benches/parallel_bench.rs`. Documented in `doc/STREAMING_PARALLELISM.md` § Phase 3.
- **Phase 2 async I/O adapter (optional `async` feature):** `stream_decode_async` (`AsyncRead` → `AsyncWrite` inboard decode), `stream::io` pipeline traits (`PipelineSource`/`PipelineSink`, `AsyncPipelineSource`/`AsyncPipelineSink`), `BoundedCopyTruncation` for sync-aligned truncation errors. Disk spool bridge preserves MAC-before-decrypt; `async-tokio` offloads sync pipeline via `spawn_blocking`. WASM returns `NotImplemented`. Tests: `tests/streaming_async.rs` (`cargo test --features async`).
- **Adamantine 1.0 directory envelope:** magic `ADAMANTINE10\n` (version in magic); 19-byte header with u8 flags (`REQUIRE_OTS` only). New module `adamantine_payload` (rkyv + centralized Bao bundle). Dev `ADAMANTINE2\n` rejected.
- **Heterogeneous FEC segment formats:** `directory/format_policy` with `infer` heuristic (compressible → c14/c15, incompressible → c12/c13); `SegmentFormatPolicy` Auto/Force*; `FilepackEntry.segment_format`; `SegmentRef` verification + `fec_parity` bundle indices.
- **Catalog OTS trailer:** optional `[COTS][u32 len][proof]` after inboard catalog bytes (stable Bao root).
- **Filepack CBOR interop:** `FilepackManifest::from_filepack_cbor`, `from_packed`, `to_filepack_cbor`; `FilepackSegmentMap`; DoS limits on CBOR flatten. Error: `InvalidFilepackCbor`.
- **New errors:** `InvalidAdamantineFlags`, `SegmentFormatMismatch`.

### Changed

- **M1 pipeline memory (hard break):** non-FEC verification decode (c6) uses `SeekWriteAt` over the post-preprocess spool (O(chunk) RAM; no full logical `Vec`). FEC verification uses `FecInboardWriteAt::finish_into` (stream logical bytes without a second full logical buffer; shard buffers remain O(FEC body) under segment-wide RS geometry). See `doc/STREAMING_PARALLELISM.md`.
- **M2 outboard verify memory:** `stream_verification_outboard_verify` uses `PostOrderOutboard` + `ReadAt` (on-demand hash pairs) instead of copying the full sidecar into `PostOrderMemOutboard`. Streaming outboard decode keeps the sidecar on a disk spool.
- **S5 scrub verify oracle:** `scrub` pre-check uses `verify_inboard_keyed` (`DiscardWriteAt` sink) instead of buffer `verification()` full-body staging; `scrub_outboard` pre-check uses `stream_verification_outboard_verify` with `io::sink()`. Memory tiers in `doc/STREAMING_PARALLELISM.md`.
- **S4 streaming inboard decode:** `stream_decode` / `stream_decode_buffer` stream keyed Bao verify into `WriteAt` sinks without staging the encoded body; `decode_stream` and `file::decode` share the same Bao/FEC path. Memory tiers documented in `doc/STREAMING_PARALLELISM.md`.
- **Directory archive layout (clean break):** inboard catalog c14/c15 only; bare segment mains; no directory `.out`/`.par`/`.ots` sidecars; Bao outboard centralized in Adam payload. Removed `DirectoryLayout`, homogeneous segment format, directory `--inboard`/`--outboard`/`--format` CLI flags.
- **CLI directory output:** defaults to `{input}-archive/`; never `.`.
- **Directory segment FEC (clean break):** catalog locked to c14/c15; segments heterogeneous c12–c15 (Verification+FEC); legacy c4–c7 rejected. Centralized bundle holds verification outboard + FEC parity per segment.
- **Keyed verification KDF domain:** `blake3::derive_key("carbonado-v2/verification", &[format])` replaces `"carbonado-v2/bao"` (breaks keyed roots vs pre-2.1.0). Public API: `crypto::carbonado_verification_key`.
- **Directory manifest API rename (Phase 1):** `PackIndex` → `FilepackManifest`, `PackEntry` → `FilepackEntry`, `PackSegmentRef` → `SegmentRef`, module `pack_index` → `filepack_manifest`. rkyv wire layout unchanged; on-disk archives remain compatible.
- **Error variant rename (breaking):** `InvalidPackIndex` → `InvalidFilepackManifest`. No enum alias is provided.
- **Narrowed error taxonomy:** OTS proof size failures → `InvalidOtsProof`; Adamantine oversized `payload_len` → `InvalidAdamantinePayloadTooLarge`; directory decode integrity failures → `SegmentMainLenMismatch`, `ContentBlake3Mismatch`, `OutputPathEscape`, `OtsFeatureRequired`, `OtsProofRequired`.

### Deprecated (one release; `since = "2.1.0"`)

Crate-root type/const aliases: `PackIndex`, `PackEntry`, `PackSegmentRef`, `PACK_INDEX_VERSION`, `PACK_INDEX_FORMAT_LEVEL`, `PACK_INDEX_FORMAT_LEVEL_PUBLIC`, `PACK_INDEX_FORMAT_LEVEL_ENCRYPTED`, `MAX_PACK_ENTRIES`. The `carbonado::pack_index` module re-exports both new and deprecated names.

**Note:** Rust emits `deprecated` warnings only after the crate version reaches **2.1.0** (`Cargo.toml` is currently **2.0.0**).

### Migration

```rust
// Before (2.0.x)
use carbonado::{PackIndex, PackEntry, PackSegmentRef, pack_index::PACK_INDEX_VERSION};
match err {
    CarbonadoError::InvalidPackIndex(msg) => { ... }
}

// After (2.1.x)
use carbonado::{FilepackManifest, FilepackEntry, SegmentRef, FILEPACK_MANIFEST_VERSION};
match err {
    CarbonadoError::InvalidFilepackManifest(msg) => { ... }
    CarbonadoError::InvalidOtsProof(msg) => { ... }  // was mis-mapped to InvalidPackIndex
    CarbonadoError::SegmentMainLenMismatch { .. } => { ... }
    // ...
}
```

## [2.0.0] — 2026-07-04

First public release. Symmetric v2 stack, streaming pipeline, seekable slices, segment sharding, and Adamantine directory archives ship together under `CARBONADO20\n`.

### Added

- **Symmetric v2 stack:** AES-256-CTR + full 64-byte HMAC-SHA512 Encrypt-then-MAC; HMAC-SHA512 BIP-32-style subkey derivation (`aes-ctr`, `etm-hmac`, `header-auth`).
- **177-byte authenticated header:** `CARBONADO20\n` magic, `payload_nonce`, `header_mac`, Bao root, SLH-DSA public key slot, format bits, u32 `chunk_index`, lengths, metadata.
- **Keyed 4 KiB Bao groups** (local `bao-tree` fork): `SLICE_LEN=4096`; root commits to format pipeline byte.
- **Seekable slice verification (P1):** `verify_slice_inboard_seekable`, `verify_slice_outboard` — O(slice) verified reads without full-stream materialization.
- **Streaming-first encode/decode (P2):** `encode_stream` / `decode_stream`, `stream_encode_buffer`, `stream_encode_outboard`, `stream_decode_*`; buffer helpers in `encoding`/`decoding` delegate to `src/stream/`.
- **Segment sharding (P3):** `encode_shard_stream` / `decode_shards_stream` for multi-segment logical files; `SHARDED` Adamantine flag when `PackEntry.segments.len() > 1`.
- **FEC:** reed-solomon-erasure RS 4/8 (deterministic encode; reproducible scrub).
- **Compression:** Zstd level 20 (Snappy format bit retained for stability).
- **Outboard mode:** bare public mains + `.cXX.out` / `.cXX.par` sidecars; `scrub_outboard` for recovery.
- **SLH-DSA sidecars** (FIPS-205 SHAKE-128s via `libbitcoinpqc`); signatures never embedded in containers.
- **Optional hybrid paranoia layer:** secp256k1 ECDH + ChaCha20-Poly1305 inner, wrapped in outer symmetric EtM.
- **Directory archives (initial P4; superseded by Adamantine 1.0 in 2.1.0 unreleased):** `encode_directory` / `decode_directory` with rkyv `PackIndex` v2 catalog. See 2.1.0 `[Unreleased]` for the Adamantine 1.0 directory redesign (clean break).
- **Encrypted directories:** `DirectoryEncodeOptions.encrypted` / CLI `--encrypted --master` for c15 catalogs and encrypted per-file segments.
- **OTS stub (`ots` feature):** `stamp_bao_root` / `verify_stamp` with entry `ots_proof` and optional catalog `.ots` sidecar; verified at decode. Enabled in default features alongside `pqc`.
- **Per-file c14/c15 segments:** each archived file stored as bare outboard `{bao_root}.c14` or `.c15` (decimal suffix for directory mode).
- **Unified `carbonado` binary:** single CLI for single-file and directory encode/decode; directories default to public c14; `--encrypted` for c15.
- **Examples:** `dir_archival.rs` (directory roundtrip), `bare_serve.rs` (minimal HTTP static server with `verify_slice_outboard` + HTTP range for bare `.c14` + sidecars).
- **Benchmarks:** `outboard_c14`, `encode_directory`, and `scrub_outboard` groups in `benches/crypto_bench.rs`.

### Removed / breaking

- **Clean cryptographic break:** no in-library decode of v1 ECIES archives.
- **Argon2id KDF** removed from library; callers supply high-entropy 32/64-byte master keys.
- **u16 slice caps** widened to u32 (~64 MiB FEC segment cap removed).
- **Canonical manifest:** directory path uses rkyv `FilepackManifest` v2; legacy CBOR `filepack` is interop only. Dev `ADAMANTINE2\n` was never published; 2.1.0 ships Adamantine 1.0 (`ADAMANTINE10\n`).

### Changed

- **Default features:** `default = ["pqc", "ots"]` — SLH-DSA sidecars and OTS stamping enabled by default; disable with `--no-default-features` for minimal builds.
- **On-disk naming:** directory mode uses decimal format level in suffixes (`.c14`, `.c15`, `.adam.c14`, `.adam.c15`); single-file CLI outboard continues hex suffixes (e.g. `.c0e` for format 14).

### Documentation

- AGENTS.md normative v2 security model, invariants, §7.1 Adamantine + PackIndex spec, and CHIPs tracker.
- README: unified binary, streaming APIs, seekable verification, catalog layout, naming distinction, Adamantine header diagram, benchmark table.
- Dev tasks via `justfile`: `just all` (fmt, lint, tests, release binary); `just lint` = clippy + source checks; smoke tests (`seekable_slices`, `streaming`, `sharding`, `bao_keyed_contract`).