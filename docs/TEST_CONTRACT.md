# carbonado — Rust test contract

The Rust integration suite under `tests/` is the **normative behavioral contract for the Rust engine**.

Lean (`Carbonado/`, `CarbonadoTest/`) is spec + proofs + an AOT demo. There is **no** Cargo `backend-lean`, **no** `carbonado-sys`, and **no** product C ABI. Do **not** claim G8 C-ABI parity.

See [PARITY.md](./PARITY.md), [GAPS.md](./GAPS.md), [LIMITS.md](./LIMITS.md), AGENTS.md product model.

**Invariant:** never regress default `cargo test`.

## Engines

| Feature flag | Engine | Expected of this suite |
|--------------|--------|------------------------|
| `backend-rust` (default, empty marker) | Pure Rust (`src/encoding`, `src/decoding`, `src/file`, …) | Full green |

```bash
cargo test
just test-lean-ci    # Lean no-sorry + AOT demo (nix), not cargo --features backend-lean
just test-g9         # Rust decode of committed Lean AOT goldens under tests/fixtures/g9/lean/
```

Helpers under `tests/common/` are not separate contract files; they support the files below.

---

## Classification (every `tests/*.rs` file)

| Class | File | Notes |
|-------|------|-------|
| **core** | `codec.rs` | Low-level `encode`/`decode`, slice, scrub, header layout, samples |
| **core** | `format.rs` | Full format matrix (inboard + outboard + scrub) |
| **core** | `format_amplification.rs` | Size/geometry amplification via `file::encode` |
| **core** | `header_tamper.rs` | Header field flips → auth / layout failures |
| **core** | `bao_keyed_contract.rs` | Verification key, keyed roots, slice verify paths |
| **core** | `adversarial_proptest.rs` | Proptest outboard/header adversarial |
| **core** | `deprecation_aliases.rs` | Type/const aliases only (no encode path) |
| **fec_scrub** | `fec_chaos.rs` | Distributed knockouts inboard/outboard |
| **fec_scrub** | `fec_scrub_matrix.rs` | Scrub matrix public/encrypted FEC |
| **fec_scrub** | `shard_fec_scrub.rs` | Per-segment scrub after sharding |
| **fec_scrub** | `udp_fec_sim.rs` | Datagram FEC sim + directory scrub path |
| **fec_scrub** | `apocalypse.rs` | Large-sample encode/scrub chaos |
| **stream** | `streaming.rs` | Stream encode/decode buffer + outboard |
| **stream** | `streaming_limits.rs` | Bounds, FEC encoder, crypto stream, scrub |
| **stream** | `seekable_slices.rs` | O(slice) retain/hash |
| **shard** | `sharding.rs` | `encode_shard_stream` / `decode_shards_stream` |
| **directory** | `directory_archive.rs` | Adamantine 1.0 + rkyv catalog + scrub_outboard |
| **directory** | `filepack_interop.rs` | Filepack / CBOR interop + directory decode |
| **directory** | `format_policy.rs` | Segment format policy (no I/O encode) |
| **cli** | `bin_cli.rs` | Prebuilt `carbonado` binary CLI |
| **cli** | `bin_smoke.rs` | CLI smoke encode/decode |
| **cli** | `bin_heuristics.rs` | Filename heuristics + CLI |
| **pqc** | `slh_outboard.rs` | SLH-DSA sidecars + header `slh_public_key` |
| **async** | `streaming_async.rs` | `#![cfg(feature = "async")]` |
| **parallel** | `parallel_determinism.rs` | RS parallel vs serial determinism |
| **parallel** | `serial_fec_path.rs` | Serial FEC encoder vs buffer path |
| **g9_goldens** | `g9_cross_backend.rs` | Rust decode of committed Lean AOT goldens + rust self-roundtrip (`just test-g9`) |
| **determinism** | `determinism_roundtrip.rs` | codecode (EDE) + decodec (DED); same-engine compress + directory |
| **zstd** | `zstd_frame_params.rs` | Frame flags vs Lean AOT goldens (honest descriptor residual); explicit level, no library default |
| **zstd** | `adam_zstd.rs` | Required zstd level; inboard/outboard Adamantine file counts; dict ID in bundle; layout detect |
| **rkyv** | `rkyv_golden_lock.rs` | Directory catalog rkyv goldens |

Removed 2026-08-24: `lean_backend_smoke.rs`, `lean_backend_phase2.rs`, `lean_backend_phase3.rs`, `lean_backend_phase4.rs` (they existed only for Cargo `backend-lean` via C).

---

## Historical note (not current product)

G8 dual-backend via C ABI (`carbonado-sys` / `libcarbonado` / `backend-lean`) was **removed** 2026-08-24. Earlier GAPS/TEST_CONTRACT text that claimed full-suite parity through that C trampoline is archaeology, not a live gate. Lean proofs and the AOT demo remain.
