# carbonado — Rust test contract (dual-backend)

The Rust integration suite under `tests/` is the **normative behavioral contract**.
Both `backend-rust` (default) and `backend-lean` (Lean AOT `libcarbonado` via C ABI) must pass the **same** tests, growing from a Phase 1 allowlist to the full suite.

See [ABI.md](./ABI.md), [PARITY.md](./PARITY.md), [GAPS.md](./GAPS.md) G8, [LIMITS.md](./LIMITS.md).

**Invariant:** never regress `backend-rust` `cargo test` while landing Lean paths.

## How backends relate to this suite

| Feature flag | Engine | Expected of this suite |
|--------------|--------|------------------------|
| `backend-rust` (default) | Pure Rust (`src/encoding`, `src/decoding`, `src/file`, …) | Full green (always) |
| `backend-lean` | Lean AOT via `carbonado-sys` / `libcarbonado` | Phased allowlist → full green (G8) |

```bash
# Normative default
cargo test

# Dual-backend (after Phase 1 wiring + linked lib)
# nix build .#libcarbonado
# export CARBONADO_LEAN_LIB=$PWD/result/lib CARBONADO_LEAN_INCLUDE=$PWD/result/include
cargo test --no-default-features --features "backend-lean,pqc,ots"
```

Helpers under `tests/common/` are not separate contract files; they support the files below.

---

## Classification (every `tests/*.rs` file)

| Class | File | lean-backend target phase | Notes |
|-------|------|---------------------------|-------|
| **core** | `codec.rs` | Phase 1–2 | Low-level `encode`/`decode`, slice, scrub, header layout, samples |
| **core** | `format.rs` | Phase 1–2 | Full format matrix (inboard + outboard + scrub) |
| **core** | `format_amplification.rs` | Phase 2 | Size/geometry amplification via `file::encode` |
| **core** | `header_tamper.rs` | Phase 1–2 | Header field flips → auth / layout failures |
| **core** | `bao_keyed_contract.rs` | Phase 1–2 | Verification key, keyed roots, slice verify paths |
| **core** | `adversarial_proptest.rs` | Phase 2 | Proptest outboard/header adversarial |
| **core** | `deprecation_aliases.rs` | Phase 3+ | Type/const aliases only (no encode path) |
| **fec_scrub** | `fec_chaos.rs` | Phase 2 | Distributed knockouts inboard/outboard |
| **fec_scrub** | `fec_scrub_matrix.rs` | Phase 2 | Scrub matrix public/encrypted FEC |
| **fec_scrub** | `shard_fec_scrub.rs` | Phase 2 | Per-segment scrub after sharding |
| **fec_scrub** | `udp_fec_sim.rs` | Phase 2 | Datagram FEC sim + directory scrub path |
| **fec_scrub** | `apocalypse.rs` | Phase 2 | Large-sample encode/scrub chaos |
| **stream** | `streaming.rs` | Phase 2 | Stream encode/decode buffer + outboard |
| **stream** | `streaming_limits.rs` | Phase 2 | Bounds, FEC encoder, crypto stream, scrub |
| **stream** | `seekable_slices.rs` | Phase 2 | O(slice) verify inboard/outboard |
| **shard** | `sharding.rs` | Phase 2 | `encode_shard_stream` / `decode_shards_stream` |
| **directory** | `directory_archive.rs` | Phase 3 | Adamantine 1.0 + rkyv catalog + scrub_outboard |
| **directory** | `filepack_interop.rs` | Phase 3 | Filepack / CBOR interop + directory decode |
| **directory** | `format_policy.rs` | Phase 3 | Segment format policy (no I/O encode) |
| **cli** | `bin_cli.rs` | Phase 4 | Prebuilt `carbonado` binary CLI |
| **cli** | `bin_smoke.rs` | Phase 4 | CLI smoke encode/decode |
| **cli** | `bin_heuristics.rs` | Phase 4 | Filename heuristics + CLI |
| **pqc** | `slh_outboard.rs` | Phase 4 | SLH-DSA sidecars + header `slh_public_key` |
| **async** | `streaming_async.rs` | **rust-only** (unless declared) | `stream_decode_async` |
| **parallel** | `parallel_determinism.rs` | rust-only or serial lean path | RS parallel vs serial determinism |
| **parallel** | `serial_fec_path.rs` | Phase 2 (serial) | Serial FEC encoder vs buffer path |

**Inventory count:** 26 integration test files under `tests/*.rs` (complete as of Phase 0 close).

---

## Primary public APIs used by tests

Mapped from actual `use carbonado::…` imports in `tests/*.rs`. C ABI column is the dual-backend export target ([ABI.md](./ABI.md)).

| API / type | Typical tests | C ABI priority |
|------------|---------------|----------------|
| `encode` / `decode` (crate root = `encoding`/`decoding`) | codec, format, header_tamper, fec_*, apocalypse, udp_fec_sim, parallel_determinism | **v0** (`carbonado_encode` / `carbonado_decode`) |
| `encode_outboard` / `decode_outboard` | format, fec_*, bao_keyed, streaming*, directory, adversarial | **v1+** (not in `include/carbonado.h` v0) |
| `scrub` / `scrub_outboard` | codec, format, fec_*, apocalypse, streaming_limits, shard_fec_scrub, directory | **v1+** |
| `verify_slice` / `extract_slice` | codec, seekable_slices, bao_keyed | **v1+** |
| `verify_slice_inboard_seekable` / `verify_slice_outboard` | bao_keyed, seekable_slices | **v1+** |
| `carbonado_verification_key` | bao_keyed_contract | **v0** |
| `file::encode` / `file::decode` / `Header` | format, format_amplification, header_tamper, streaming_limits, slh_outboard, adversarial | **v0** (`carbonado_encode_headered` / `carbonado_decode_headered`) |
| `file::encode_stream` / `decode_stream` | streaming, streaming_limits | Phase 2 (may stay Rust-side over buffer ABI) |
| `file::encode_directory` / `encode_directory_with_options` / `decode_directory` | directory_archive, filepack_interop, udp_fec_sim | Phase 3 (+ rkyv wire) |
| `stream_encode_buffer` / `stream_decode_buffer` (+ outboard buffer variants) | streaming*, bao_keyed, parallel_determinism | Phase 2 |
| `stream::fec::*` / `stream::parallel::*` | streaming_limits, serial_fec_path, parallel_determinism | rust-internal / serial lean |
| `encode_shard_stream` / `decode_shards_stream` | sharding, shard_fec_scrub | Phase 2 |
| Adamantine / filepack_manifest / format_policy | directory_*, filepack_interop, format_policy | Phase 3 |
| `crypto::slh_*` / sidecar helpers | slh_outboard | Phase 4 (G10) |
| `ots::*` | directory_archive (feature `ots`) | Phase 4 |
| Deprecation aliases (`PackIndex`, …) | deprecation_aliases | n/a (API surface only) |
| `stream_decode_async` | streaming_async | **rust-only** initially |
| CLI binary (`src/bin/carbonado.rs`) | bin_* | Phase 4 |

### Error-contract note (both backends)

Tests that `matches!` ultra-specific `CarbonadoError` variants require a stable C-code → Rust mapping ([ABI.md](./ABI.md) error table). Phase 1 may collapse some Lean `PipelineError` variants into broader ABI codes; refine mapping before claiming full-suite green on failure-mode tests (`header_tamper`, scrub unnecessary vs failed, etc.).

---

## Phase 1 allowlist (first green `backend-lean` gate)

**Honest status at Phase 0 close:** C symbols exist in `include/carbonado.h` and `carbonado-sys`, but `nix/native/carbonado_abi.c` weak stubs return `CARBONADO_ERR_NOT_IMPLEMENTED` for all encode/decode/verification_key entry points. Lean has pure helpers in `Carbonado/Ffi.lean` (`encodeHeaderedBytes`, `decodeHeaderedBytes`, `ofPipelineError`) — **not** yet linked as live C exports in the archive used by `backend-lean`. Phase 1 work is: real `@[export]` / link, Rust dispatch into `src/backend/lean`, then the allowlist below.

### Phase 1 scope (concrete)

1. **Public (even) formats only** for first green: e.g. c0, c2, c4, c6, c12, c14 — no encryption / no random nonce dependency until headered encrypted path is deterministic under test nonces.
2. **Buffer / headered APIs only** (match C ABI v0):
   - `carbonado_abi_version` / `carbonado_free`
   - `carbonado_verification_key`
   - `carbonado_encode` / `carbonado_decode` (low-level body; Rust `encoding::encode` / `decoding::decode` shape)
   - `carbonado_encode_headered` / `carbonado_decode_headered` (Rust `file::encode` / `file::decode` shape)
3. **Suggested first test targets** (grow in CI / justfile as green):
   - Subset of `tests/codec.rs` (roundtrip + basic failure) **or** a dedicated `tests/lean_backend_smoke.rs` reusing `tests/common` helpers
   - `tests/bao_keyed_contract.rs` cases that only need verification key + comparable encode roots
   - Selected `tests/header_tamper.rs` auth-fail cases once headered encode is real (not stub)
4. **Explicitly out of Phase 1:** outboard, scrub, seekable slice C exports, directory/rkyv, CLI, SLH FFI, async, parallel RS.

### Phase 1 non-goals

- Full `tests/` green on `backend-lean`
- Changing normative wire format
- Replacing or deleting the Rust engine

Document the live allowlist in CI / justfile as it grows. Full suite remains the G8 end state (Phase 5).

---

## Later phases (test-suite coverage)

| Phase | Test classes unlocked | Depends on |
|-------|----------------------|------------|
| 2 | fec_scrub, stream, shard, remaining core | scrub/outboard/slice ABI or Rust-side composition over body ABI; format matrix |
| 3 | directory, format_policy, filepack_interop, deprecation_aliases | rkyv-compatible catalog wire (not Lean-only CFP2) |
| 4 | cli, pqc (slh_outboard), ots paths | libbitcoinpqc in libcarbonado (G10); CLI dual path |
| 5 | CI freeze both backends; G8 closed | full suite + docs freeze |

---

## Maintenance

- New `tests/*.rs` files **must** be added to the classification table above in the same PR.
- New public encode/decode surfaces used by tests must be listed in the API table and, if dual-backend-relevant, in [ABI.md](./ABI.md).
- Prefer strict `matches!` on specific `CarbonadoError` variants for failure-mode tests; when ABI collapse prevents 1:1 mapping, document backend-aware expectations rather than loosening asserts permanently.
