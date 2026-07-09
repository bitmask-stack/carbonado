# Carbonado Test Strategy (2.1+)

This document plans the test matrix, FEC/scrub/sharding coverage, and remaining work after the Adamantine 1.0 directory redesign.

## Goals

1. **Exhaustive format coverage** — all 16 pipeline combinations (c0–c15) with strict `matches!` error assertions.
2. **FEC durability** — RS 4/8 recovery under distributed random corruption (≤50% shard budget), JBOD/UDP use-case confidence.
3. **Scrub + sharding intent** — recovery paths tested per segment, not only whole-archive smoke.
4. **Streaming memory honesty** — three axes (pipeline memory / async concurrency / CPU parallelism) stay separate in tests. `streaming_limits` documents tiers; S4 proves read-chunk parity; M1 (kill O(logical) verification decode) must retarget those tests when it lands. Peak-RSS instrumentation remains optional.
5. **Rust-idiomatic layout** — unit tests in `src/**`, integration tests in `tests/**`, shared helpers in `tests/common/`.

## Test layout (idiomatic Rust)

| Layer | Location | Examples |
|-------|----------|----------|
| **Unit** | `#[cfg(test)]` in `src/` | `src/stream/fec.rs` — stripe geometry, incremental feed, `zfec` roundtrip |
| **Integration** | `tests/*.rs` (one crate per file) | `fec_chaos.rs`, `fec_scrub_matrix.rs`, `shard_fec_scrub.rs` |
| **Property** | `proptest!` in integration crates | `fec_chaos.rs`, `streaming.rs`, `adversarial_proptest.rs` |
| **Shared helpers** | `tests/common/` | `corruption.rs`, `format_matrix.rs`, `header_layout.rs` |
| **WASM subset** | `#[wasm_bindgen_test]` in `codec.rs` | Light flip + 16 KiB stripe-boundary distributed knockout (full chaos native) |

Each integration test file starts with `mod common;` and imports only needed helpers.

## Format matrix (c0–c15)

Bitmask: `Encryption(1) | Compression(2) | Verification(4) | Fec(8)`.

### Coverage tiers

| Tier | Scope | Status |
|------|-------|--------|
| **T0** | Low-level `encode`/`decode` roundtrip all 16 | Done — `tests/codec.rs::all_formats_matrix_roundtrips` |
| **T1** | `stream_encode_buffer` all 16 (proptest) | Done — `tests/streaming.rs` |
| **T2** | Scrub all Bao+Zfec (c12–c15) light + distributed | Done — `tests/fec_scrub_matrix.rs` |
| **T3** | Outboard scrub c12/c14/c15 light flip | Done — `tests/fec_scrub_matrix.rs` |
| **T3b** | Outboard distributed chaos + stripe-boundary scrub | Done — `tests/fec_chaos.rs` |
| **T4** | Outboard roundtrip all 16 | Done — `tests/format.rs::outboard_and_keyed_c_number` |
| **T5** | `encode_stream`/`decode_stream` format sweep | Done — `tests/streaming.rs::file_stream_format_sweep` |
| **T6** | Directory heterogeneous c12–c15 + catalog c14/c15 | Done — `tests/directory_archive.rs` |
| **T7** | Sharding × FEC × scrub per segment | **New** — `tests/shard_fec_scrub.rs` |

### Option-combination scenarios (planned matrix)

For each relevant level, test dimensions:

- **Payload size**: 0, 1, 4 KiB−1, 4 KiB, 16 KiB stripe edge, 64 KiB–1 MiB, multi-MiB shard
- **Key**: zero (public) vs random 32-byte (encrypted)
- **Path**: buffer, stream, file header, outboard, shard, directory segment
- **Corruption**: none, light flip, distributed knockout (≤4 shards), 5-shard irrecoverable
- **Sidecars**: present/missing/tampered (outboard `.out`/`.par`)

Helper: `tests/common/format_matrix.rs` — iterators for `bao_zfec_levels()`, `public_zfec_levels()`, etc.

## FEC chaos model (RS 4/8)

Carbonado uses **reed-solomon-erasure 4/8**: any **4 of 8** shards reconstruct the stripe. That is a **50% shard erasure** budget, not 50% of arbitrary bytes.

### Distributed knockout (`tests/common/corruption.rs`)

- `distributed_byte_knockout` — XOR flips (non-zero mask) across ≤4 distinct shard regions
- `scattered_stream_knockout` — XOR flips spread through the encoded stream
- `erase_shards` — full shard loss (simulates JBOD disk failure)

### Integration tests (`tests/fec_chaos.rs`)

- Public Bao+Zfec (c12, c14): sizes 4 KiB–256 KiB, 4-shard distributed recovery
- Encrypted (c13, c15): scattered knockout + content roundtrip
- **Outboard distributed chaos** (c12/c14/c15): corrupt bare main + intact `.par` → `scrub_outboard` + `decode_outboard`
- **`zfec_with_parity` without scrub** (c8 outboard): truncated main erasure + intact `.par` → direct `decode_outboard` (XOR corruption on Bao+Zfec still uses scrub)
- **Stripe-boundary chaos** (single-stripe `chunk_len` scaling): inboard + outboard at 16 KiB ±1, 32 KiB, 48 KiB
- **Negative proof**: 5 erased shards → `InvalidScrubbedHash`
- Proptest: c12 random size/knockout counts

### JBOD / UDP motivation

| Use case | What tests prove |
|----------|------------------|
| **JBOD replacement** | Scrub recovers when any 4 drives/shards hold good data; deterministic re-encode matches Bao root |
| **UDP datagrams** | RS 4/8 tolerates 50% packet loss at chaos-injection coordinates (`tests/udp_fec_sim.rs`; approximate layout, not normative wire) |
| **P2P replication** | Keyed Bao roots + slice verify without full decode (`tests/seekable_slices.rs`) |

## Scrub & sharding (intentional scenarios)

| Scenario | File | Asserts |
|----------|------|---------|
| Inboard scrub matrix c12–c15 | `fec_scrub_matrix.rs` | `UnnecessaryScrub`, light flip, distributed chaos, decode content |
| Outboard scrub c12/c14/c15 | `fec_scrub_matrix.rs` | `scrub_outboard` + `decode_outboard` |
| Zfec-only → `ScrubRequiresVerification` | `fec_scrub_matrix.rs` | c8, c10 |
| Multi-shard archive, corrupt middle segment | `shard_fec_scrub.rs` | Per-segment scrub + `decode_shards_stream` |
| FEC stripe boundary sizes | `shard_fec_scrub.rs` | 16 KiB ±1, segment budget edge |
| Shard sequence errors | `shard_fec_scrub.rs`, `sharding.rs` | `MissingShardIndex`, auth failures |

## Remaining work (prioritized)

### P0 — Pipeline memory hard-break

1. ~~**M1** — Non-FEC c6 `SeekWriteAt`; FEC `finish_into`~~ **Done** (FEC residual = O(segment body) shards under current geometry)
2. ~~**M2** — Outboard `PostOrderOutboard` + `ReadAt`~~ **Done**
3. **M3** — Async: drop full encoded-body spool (`bao_tree::io::fsm` or equivalent); extend `streaming_async` contracts

### P1 — Matrix completion (shipped)

1. ~~Extend `tests/format.rs` — outboard roundtrip all 16 formats~~ **Done**
2. ~~Extend `tests/streaming.rs` — outboard stream parity for c6/c7/c13/c15~~ **Done**
3. ~~`encode_stream` format sweep (c0, c4, c8, c12, c14, c15)~~ **Done**
4. ~~S2 inboard FEC incremental encode parity + bounded-read contract~~ **Done** — `tests/streaming_limits.rs` (c4/c8/c12/c14/c15 parity, bounded-read, padding boundaries, short-read negative, decode roundtrip via `tests/common/inboard_parity.rs`); `tests/sharding.rs` per-segment buffer parity
4b. ~~S3 streaming keyed Bao inboard encode (no FEC body staging `Vec`)~~ **Done** — `FecStripeReadAt` / `SeekReadAt`; `tests/streaming_limits.rs` (c6 seek-read, c12/c14/c15 unchanged parity); `src/stream/fec.rs::fec_stripe_read_at_matches_flattened_stripe`
4c. ~~S4 streaming inboard decode (Bao verify → FEC without encoded-body staging)~~ **Done** — `FecInboardWriteAt` / `LogicalBufferWriteAt`; shared `inboard_bao_content_len_prefix` in `bao.rs`; `tests/streaming_limits.rs` (`stream_decode_bounded_read_matches_buffer_path`, `stream_decode_matches_buffer_path_c4_c6_c8_c12_c14_c15`, bounded-read c6/c12/c15, error-taxonomy + wrong-key tests); `src/stream/decode.rs::stream_decode_inboard_pipeline`; `file::decode` wired to S4 path
4d. ~~S5 scrub verify oracle (no O(decoded) body staging on scrub entry)~~ **Done** — `DiscardWriteAt` + `verify_inboard_keyed` in `bao.rs`; `scrub` pre-check wired; `scrub_outboard` uses `stream_verification_outboard_verify` + `io::sink()`; `tests/streaming_limits.rs` (`scrub_s5_pristine_returns_unnecessary_scrub`, `scrub_s5_corrupt_still_recovers`, `scrub_s5_outboard_pristine_returns_unnecessary_scrub`, scrub entry error-routing negatives); `src/stream/bao.rs` oracle parity unit tests
4e. ~~Phase 2 async I/O adapter~~ **Done** — `stream_decode_async` + `stream::io`; `tests/streaming_async.rs` (format matrix c4/c6/c8/c12/c14/c15, chunked `BoundedAsyncRead`, trailing bytes, staging truncation c4/c8, verification truncation divergence c12, `UnevenFecChunks`, MAC-before-decrypt, error taxonomy); gates: `cargo test --features async --test streaming_async` (blocking-in-async path), `cargo test --features async-tokio --test streaming_async` (`spawn_blocking` offload + `async_tokio_spawn_blocking_path_enabled`)
5. ~~Sharding: c15 encrypted multi-shard + outboard sharding (if supported)~~ **Done** (outboard sharding documented as unsupported)

### P2 — FEC / scrub depth

1. ~~Outboard distributed chaos (corrupt bare main + intact `.par`)~~ **Done** — `tests/fec_chaos.rs::outboard_distributed_knockout_scrub_recover_c12_c14_c15`
2. ~~`zfec_with_parity` corruption without scrub (direct decode recovery)~~ **Done** — `tests/fec_chaos.rs::zfec_with_parity_outboard_decode_without_scrub` + `src/stream/fec.rs` unit test (c8 erasure via truncated main)
3. ~~Multi-stripe payloads (>16 KiB) chaos across stripe boundaries~~ **Done** — `tests/fec_chaos.rs::multi_stripe_boundary_*`
4. ~~WASM: expand `wasm_fec_robustness_small` or document native-only chaos~~ **Done** — expanded in `tests/codec.rs` (stripe-boundary distributed knockout); outboard/multi-format chaos documented native-only

### P3 — Directory + P2P integration

1. ~~Directory segment corruption + centralized bundle extract + FEC scrub~~ **Done** — `tests/directory_archive.rs::{directory_segment_corruption_bao_bundle_extract_scrub_roundtrip,directory_fec_scrub_matrix_c12_c13_c14_c15,directory_multi_segment_fec_bundle_indices}` (c12–c15 segments: verification + FEC parity indexed in Adamantine bundle; `scrub_outboard` recovers corrupt bare mains within ≤4 shard taints; c15 encrypted five-shard knockout documented as `InvalidScrubbedHash` negative)
2. ~~Cross-tool interop fixtures (manifest + segment naming)~~ **Done** — `tests/fixtures/directory_interop_golden.json` + `tests/filepack_interop.rs::{adamantine_decimal_segment_naming_contract,golden_directory_interop_checksums_and_manifest_wire}`
3. ~~UDP shard mapping contract test (chaos-injection datagram ↔ shard slot at `InboardShardLayout` coordinates)~~ **Done** — `tests/udp_fec_sim.rs` (datagram drop = `erase_shards` at approximate coordinates; not normative Bao-wrapped wire; ≤4-drop scrub recovery; c12 five-drop irrecoverable)

### P4 — External normative

1. CHIP-0005 in `bitmask-stack/CHIPs` (wire + FEC + scrub semantics)
2. Append-only streaming catalog (deferred; bundle version byte hook only today)

## Running tests

```bash
# Full native gate (serial FEC path + full matrix)
cargo test --features "pqc,ots,cli"
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings

# FEC-focused
cargo test --test fec_chaos --test fec_scrub_matrix --test shard_fec_scrub

# Directory + P2P (P3)
cargo test --test directory_archive --test filepack_interop --test udp_fec_sim

# Streaming pipeline memory contracts (honest tiers until M1)
cargo test --test streaming_limits

# Phase 2 async (not in default features)
cargo test --features async --test streaming_async
cargo test --features async-tokio --test streaming_async

# Phase 3 CPU parallelism (`parallel` is a default feature)
cargo test --test parallel_determinism

# Serial FEC path without `parallel` (exercises fec.rs rs.encode branch)
cargo test --no-default-features --features "pqc,ots,cli" --test serial_fec_path

# WASM lint (no pqc)
just lint-wasm
```

## CI recommendations

- Keep chaos tests on native Linux (may be slow at 256 KiB × 4 public levels)
- Shard FEC scrub tests parallel-safe (unique temp dirs per test)
- **Default gate:** `cargo test` (includes `parallel` and `parallel_determinism`)
- **Serial FEC gate:** `cargo test --no-default-features --features "pqc,ots,cli" --test serial_fec_path` — must run before or alongside `--all-features`
- **Phase 3 determinism:** covered by default `cargo test --test parallel_determinism` (RS parity vs `encode_rs_parity_serial`, c12/c14 bytes + Bao root, scrub roundtrip)
- **WASM `parallel`:** compile-only in `test-matrix` (`cargo check --target wasm32-unknown-unknown --all-features`); runtime serial fallback documented in `STREAMING_PARALLELISM.md` § Phase 3 WASM
- Proptest cases capped at 32 for `fec_chaos` (raise when stable)