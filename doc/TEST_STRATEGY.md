# Carbonado Test Strategy (2.1+)

This document plans the test matrix, FEC/scrub/sharding coverage, and remaining work after the Adamantine 1.0 directory redesign.

## Goals

1. **Exhaustive format coverage** — all 16 pipeline combinations (c0–c15) with strict `matches!` error assertions.
2. **FEC durability** — RS 4/8 recovery under distributed random corruption (≤50% shard budget), JBOD/UDP use-case confidence.
3. **Scrub + sharding intent** — recovery paths tested per segment, not only whole-archive smoke.
4. **Streaming memory honesty** — document and test current O(N) materialization; aspirational tests for bounded memory.
5. **Rust-idiomatic layout** — unit tests in `src/**`, integration tests in `tests/**`, shared helpers in `tests/common/`.

## Test layout (idiomatic Rust)

| Layer | Location | Examples |
|-------|----------|----------|
| **Unit** | `#[cfg(test)]` in `src/` | `src/stream/fec.rs` — stripe geometry, incremental feed, `zfec` roundtrip |
| **Integration** | `tests/*.rs` (one crate per file) | `fec_chaos.rs`, `fec_scrub_matrix.rs`, `shard_fec_scrub.rs` |
| **Property** | `proptest!` in integration crates | `fec_chaos.rs`, `streaming.rs`, `adversarial_proptest.rs` |
| **Shared helpers** | `tests/common/` | `corruption.rs`, `format_matrix.rs`, `header_layout.rs` |
| **WASM subset** | `#[wasm_bindgen_test]` in `codec.rs` | Small FEC scrub path only (full matrix native) |

Each integration test file starts with `mod common;` and imports only needed helpers.

## Format matrix (c0–c15)

Bitmask: `Encrypted(1) | Snappy(2) | Bao(4) | Zfec(8)`.

### Coverage tiers

| Tier | Scope | Status |
|------|-------|--------|
| **T0** | Low-level `encode`/`decode` roundtrip all 16 | Done — `tests/codec.rs::all_formats_matrix_roundtrips` |
| **T1** | `stream_encode_buffer` all 16 (proptest) | Done — `tests/streaming.rs` |
| **T2** | Scrub all Bao+Zfec (c12–c15) light + distributed | **New** — `tests/fec_scrub_matrix.rs` |
| **T3** | Outboard scrub c12/c14/c15 | **New** — `tests/fec_scrub_matrix.rs` |
| **T4** | Outboard roundtrip all 16 | Done — `tests/format.rs::outboard_and_keyed_c_number` |
| **T5** | `encode_stream`/`decode_stream` format sweep | Done — `tests/streaming.rs::file_stream_format_sweep` |
| **T6** | Directory heterogeneous c4–c7 + catalog c14/c15 | Done — `tests/directory_archive.rs` (28) |
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

- `distributed_byte_knockout` — random zeros across ≤4 distinct shard regions
- `scattered_stream_knockout` — XOR flips spread through the encoded stream
- `erase_shards` — full shard loss (simulates JBOD disk failure)

### Integration tests (`tests/fec_chaos.rs`)

- Public Bao+Zfec (c12, c14): sizes 4 KiB–256 KiB, 4-shard distributed recovery
- Encrypted (c13, c15): scattered knockout + content roundtrip
- **Negative proof**: 5 erased shards → `InvalidScrubbedHash`
- Proptest: c12 random size/knockout counts

### JBOD / UDP motivation

| Use case | What tests prove |
|----------|------------------|
| **JBOD replacement** | Scrub recovers when any 4 drives/shards hold good data; deterministic re-encode matches Bao root |
| **UDP datagrams** | RS 4/8 tolerates 50% packet loss if each datagram maps to a shard; Bao provides ordering/verification |
| **P2P replication** | Keyed Bao roots + slice verify without full decode (`tests/seekable_slices.rs`) |

## Scrub & sharding (intentional scenarios)

| Scenario | File | Asserts |
|----------|------|---------|
| Inboard scrub matrix c12–c15 | `fec_scrub_matrix.rs` | `UnnecessaryScrub`, light flip, distributed chaos, decode content |
| Outboard scrub c12/c14/c15 | `fec_scrub_matrix.rs` | `scrub_outboard` + `decode_outboard` |
| Zfec-only → `ScrubRequiresBao` | `fec_scrub_matrix.rs` | c8, c10 |
| Multi-shard archive, corrupt middle segment | `shard_fec_scrub.rs` | Per-segment scrub + `decode_shards_stream` |
| FEC stripe boundary sizes | `shard_fec_scrub.rs` | 16 KiB ±1, segment budget edge |
| Shard sequence errors | `shard_fec_scrub.rs`, `sharding.rs` | `MissingShardIndex`, auth failures |

## Remaining work (prioritized)

### P0 — Gate & commit (from directory redesign)

1. Stage untracked files (`adamantine_payload.rs`, `directory/`, `format_policy.rs` tests)
2. Commit + 2.1.0 release notes

### P1 — Matrix completion (this plan)

1. ~~Extend `tests/format.rs` — outboard roundtrip all 16 formats~~ **Done**
2. ~~Extend `tests/streaming.rs` — outboard stream parity for c6/c7/c13/c15~~ **Done**
3. ~~`encode_stream` format sweep (c0, c4, c8, c12, c14, c15)~~ **Done**
4. ~~Sharding: c15 encrypted multi-shard + outboard sharding (if supported)~~ **Done** (outboard sharding documented as unsupported)

### P2 — FEC / scrub depth

1. Outboard distributed chaos (corrupt bare main + intact `.par`)
2. `zfec_with_parity` corruption without scrub (direct decode recovery)
3. Multi-stripe payloads (>16 KiB) chaos across stripe boundaries
4. WASM: expand `wasm_fec_robustness_small` or document native-only chaos

### P3 — Directory + P2P integration

1. Directory segment corruption + centralized Bao bundle extract + scrub
2. Cross-tool interop fixtures (manifest + segment naming)
3. UDP shard mapping contract test (document datagram = FEC shard index)

### P4 — External normative

1. CHIP-0005 in `bitmask-stack/CHIPs` (wire + FEC + scrub semantics)
2. Append-only streaming catalog (deferred; bundle version byte hook only today)

## Running tests

```bash
# Full native gate
cargo test
cargo clippy --all-targets --all-features -- -D warnings

# FEC-focused
cargo test --test fec_chaos --test fec_scrub_matrix --test shard_fec_scrub

# Streaming limits (includes one ignored aspirational test)
cargo test --test streaming_limits
cargo test --test streaming_limits -- --ignored
```

## CI recommendations

- Keep chaos tests on native Linux (may be slow at 256 KiB × 4 public levels)
- Shard FEC scrub tests parallel-safe (unique temp dirs per test)
- Proptest cases capped at 32 for `fec_chaos` (raise when stable)