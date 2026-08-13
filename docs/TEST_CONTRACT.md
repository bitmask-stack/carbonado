# carbonado — Rust test contract (dual-backend)

The Rust integration suite under `tests/` is the **normative behavioral contract**.
Both `backend-rust` (default) and `backend-lean` (Lean AOT `libcarbonado` via C ABI) must pass the **same** tests, growing from a Phase 1 allowlist to the full suite.

See [ABI.md](./ABI.md), [PARITY.md](./PARITY.md), [GAPS.md](./GAPS.md) G8, [LIMITS.md](./LIMITS.md).

**Invariant:** never regress `backend-rust` `cargo test` while landing Lean paths.

## How backends relate to this suite

| Feature flag | Engine | Expected of this suite |
|--------------|--------|------------------------|
| `backend-rust` (default) | Pure Rust (`src/encoding`, `src/decoding`, `src/file`, …) | Full green (always) |
| `backend-lean` | Lean AOT via `carbonado-sys` / `libcarbonado` | Full green (G8 closed at R7; freeze = unfiltered dual suite) |

```bash
# Normative default (backend-rust)
cargo test

# Dual-backend freeze (Phase 5 / G11 + R7 G8 full close — shared CI + humans)
# Prefer the single recipe (builds libcarbonado if needed; fail-closed if .so missing):
just test-lean-ci

# Manual equivalent (R7: freeze = full unfiltered dual suite):
# nix build .#libcarbonado -o result-libcarbonado
# export CARBONADO_LEAN_LIB=$PWD/result-libcarbonado/lib
# export CARBONADO_LEAN_INCLUDE=$PWD/result-libcarbonado/include
# export LD_LIBRARY_PATH=$CARBONADO_LEAN_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
# cargo test --no-default-features --features "backend-lean,pqc,ots,cli"
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
| **stream** | `seekable_slices.rs` | Phase 2 | O(slice) retain/hash; full body/main at lean C (W4a/W4b; see LIMITS slice table) |
| **shard** | `sharding.rs` | Phase 2 | `encode_shard_stream` / `decode_shards_stream` |
| **directory** | `directory_archive.rs` | Phase 3 (core); OTS cases Phase 4 closed | Adamantine 1.0 + rkyv catalog + scrub_outboard; OTS via CBOTS composition |
| **directory** | `filepack_interop.rs` | Phase 3 | Filepack / CBOR interop + directory decode |
| **directory** | `format_policy.rs` | Phase 3 | Segment format policy (no I/O encode) |
| **cli** | `bin_cli.rs` | Phase 4 | Prebuilt `carbonado` binary CLI (default rust-engine; lean when rebuilt with `backend-lean,cli`) |
| **cli** | `bin_smoke.rs` | Phase 4 | CLI smoke encode/decode |
| **cli** | `bin_heuristics.rs` | Phase 4 | Filename heuristics + CLI |
| **pqc** | `slh_outboard.rs` | Phase 4 closed | SLH-DSA sidecars + header `slh_public_key` (Rust bitcoinpqc under both backends) |
| **async** | `streaming_async.rs` | **feature-gated permanent** (needs `async`; **R10 closed**) | Freeze excludes `async` → 0 tests under dual suite; optional lean+async dual-aware via R5 E1 |
| **parallel** | `parallel_determinism.rs` | **feature-gated** (needs `parallel`; not dual residual) | RS parallel vs serial determinism; 0 tests under dual feature set |
| **parallel** | `serial_fec_path.rs` | Phase 2 (serial) | Serial FEC encoder vs buffer path |
| **lean_allowlist** | `lean_backend_smoke.rs` | Phase 1 closed | Dual-backend body/headered/auth smoke (`just test-lean-smoke`) |
| **lean_allowlist** | `lean_backend_phase2.rs` | Phase 2 closed | Outboard/scrub/slice/stream + G9 seed (`just test-lean-phase2`) |
| **lean_allowlist** | `lean_backend_phase3.rs` | Phase 3 closed | Directory composition + G9 dir fixture (`just test-lean-phase3`) |
| **lean_allowlist** | `lean_backend_phase4.rs` | Phase 4 closed | SLH composition + CLI dual (directory dual-engine + buffer APIs; stream E1 dual closed at R5; **W1a** `decode_stream` dual closed; **W1b** public non-compress outboard composition E2 closed; pure Lean chunked stream C residual) + directory OTS (`just test-lean-phase4`) |
| **g9_matrix** | `g9_cross_backend.rs` | **R8 / G9 closed** | Full cross-backend no-compress matrix both directions; fixtures `tests/fixtures/g9/` (`just test-g9`) |
| **determinism** | `determinism_roundtrip.rs` | **W2d closed** | codecode (EDE) + decodec (DED) no-compress matrix; same-engine compress (body/headered/outboard) + directory; W2a/W2b hard residual asserts (live-vs-live dir roots; G9 c14 mains) |
| **lean_freeze (P5+R7)** | see Phase 5 / R7 section | Phase 5 + R7 closed | Freeze = full dual suite: `just test-lean-ci` (unfiltered lean features; includes `g9_cross_backend` + `determinism_roundtrip`) |

**Inventory count:** 32 integration test files under `tests/*.rs` (R8: `g9_cross_backend`; W2: `determinism_roundtrip`).

**Directory vs OTS:** Core Adamantine / rkyv dual-suite green is **Phase 3**. Entry/catalog OTS proof cases (feature `ots`) are **Phase 4 closed** via pure-Rust CBOTS composition over Lean container crypto (no Lean-native stamping).

---

## Primary public APIs used by tests

Mapped from actual `use carbonado::…` imports in `tests/*.rs`. C ABI column is the dual-backend export target ([ABI.md](./ABI.md)).

| API / type | Typical tests | C ABI priority |
|------------|---------------|----------------|
| `encode` / `decode` / `encode_with_nonce` (crate root = `encoding`/`decoding`) | codec, format, header_tamper, fec_*, apocalypse, udp_fec_sim, parallel_determinism, **g9_cross_backend** | **v0** (`carbonado_encode` / `carbonado_decode`; fixed nonce via optional C arg) |
| `encode_outboard` / `decode_outboard` | format, fec_*, bao_keyed, streaming*, directory, adversarial | **P2 live** (`carbonado_encode_outboard` / `carbonado_decode_outboard`) |
| `scrub` / `scrub_outboard` | codec, format, fec_*, apocalypse, streaming_limits, shard_fec_scrub, directory | **P2 live** (`carbonado_scrub` / `carbonado_scrub_outboard`) |
| `verify_slice` / `extract_slice` | codec, seekable_slices, bao_keyed | **P2 + W4a** (`carbonado_verify_slice`; extract = count 1; O(slice) retain; full body input) |
| `verify_slice_inboard_seekable` / `verify_slice_outboard` | bao_keyed, seekable_slices | **v1+**; **R9** outboard C live (`carbonado_verify_slice_outboard` + lean dispatch) |
| `crypto::slh_*` (pure Lean path) | AOT demo / optional | **R9** `carbonado_slh_*` live; dual-suite may keep Rust bitcoinpqc |
| rkyv catalog encode+decode (Lean) | AOT demo goldens | **W3** `Carbonado/RkyvFilepack` encode/decode; dual-suite encode still Rust rkyv composition SSOT |
| `carbonado_verification_key` | bao_keyed_contract | **v0** |
| `file::encode` / `file::decode` / `Header` | format, format_amplification, header_tamper, streaming_limits, slh_outboard, adversarial | **v0** (`carbonado_encode_headered` / `carbonado_decode_headered`) |
| `file::encode_stream` / `decode_stream` | streaming, streaming_limits | **R5 E1** encode_stream → Lean; **W1a** `decode_stream` spool→Lean `decode_headered` (E1 RAM; not E2) |
| `file::encode_directory` / `encode_directory_with_options` / `decode_directory` | directory_archive, filepack_interop, udp_fec_sim | **P3 live** (composition: rkyv+FS Rust; segment/catalog crypto via outboard/headered Lean ABI) |
| `stream_encode_buffer` / `stream_decode_buffer` (+ outboard buffer variants) | streaming*, bao_keyed, parallel_determinism | Phase 2 + **R5** stream I/O E1 over same Lean buffer ABI |
| `stream_encode_inboard` / `stream_decode` | streaming, streaming_limits | **R5 E1** spool-to-buffer → Lean (O(logical); not E2) |
| `stream_encode_outboard` / `stream_decode_outboard` | streaming, streaming_limits | **W1b:** public non-compress → S4 O(chunk/stripe) composition E2 under lean; public+Compression under lean O(logical) bulk zstd; encrypted → Lean E1 |
| `stream::fec::*` / `stream::parallel::*` | streaming_limits, serial_fec_path, parallel_determinism | rust-internal / serial lean |
| `encode_shard_stream` / `decode_shards_stream` | sharding, shard_fec_scrub | Phase 2 |
| Adamantine / filepack_manifest / format_policy | directory_*, filepack_interop, format_policy | **P3 live** (rkyv wire; format_policy pure Rust) |
| `crypto::slh_*` / sidecar helpers (dual-suite product) | slh_outboard, lean_backend_phase4 | **P4 live** (G10-A: Rust `bitcoinpqc` composition under both backends) |
| `carbonado_slh_*` C ABI (pure Lean path) | AOT demo / optional C consumers | **R9 live** optional purity; dual-suite need not switch from composition |
| `ots::*` | directory_archive OTS + lean_backend_phase4 (feature `ots`) | **P4 live** (Rust CBOTS; no Lean OTS engine) |
| Deprecation aliases (`PackIndex`, …) | deprecation_aliases | n/a (API surface only) |
| `stream_decode_async` | streaming_async | **R10:** optional adapter; dual freeze never requires `async`; under lean+async → dual-aware `stream_decode` (disk O(encoded); lean peak RAM O(encoded+logical); not E2) |
| CLI binary (`src/bin/carbonado`) | bin_*, lean_backend_phase4 | **P4 + R5 + W1:** directory CLI + buffer APIs + stream encode E1 + `decode_stream` W1a + public outboard W1b composition; rebuild with `cli`+`backend-lean` |

### Error-contract note (both backends)

Tests that `matches!` ultra-specific `CarbonadoError` variants require a stable C-code → Rust mapping ([ABI.md](./ABI.md) error table). Phase 1 may collapse some Lean `PipelineError` variants into broader ABI codes; refine mapping before claiming full-suite green on failure-mode tests (`header_tamper`, scrub unnecessary vs failed, etc.).

---

## Phase 1 allowlist (first green `backend-lean` gate)

**Phase 1 closed:** live C ABI via Lean AOT (`l_carbonado_*` + `carbonado_abi.c`), `nix build .#libcarbonado`, Rust `backend-lean` dispatch for `encode`/`decode`/`file::{encode,decode}`/`carbonado_verification_key`, allowlist `tests/lean_backend_smoke.rs` (`just test-lean-smoke`).

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

Document the live freeze in CI / justfile. Full suite is the G8 bar — **closed at R7** (see Phase 5 / R7).

---

## Phase 2 allowlist (outboard / scrub / slice + G9 start)

**Phase 2 closed:** additive C ABI for outboard encode/decode, scrub / scrub_outboard, verify_slice; richer encode metadata (`chunk_len`, `bytes_ecc`, `verifiable_slice_count`); Lean geometry-peel inboard scrub + outboard scrub; Rust dispatch under `backend-lean` for those APIs + stream buffer composition over body/outboard ABI; allowlist `tests/lean_backend_smoke.rs` + `tests/lean_backend_phase2.rs` (`just test-lean-phase2`).

### Phase 2 scope (concrete)

1. **Public formats** c0/c4/c12/c14 (+ fixed-nonce encrypted helpers for c5) on body, headered, outboard.
2. **New C symbols (ABI v1 additive):**
   - `carbonado_encode_outboard` / `carbonado_decode_outboard`
   - `carbonado_scrub` / `carbonado_scrub_outboard`
   - `carbonado_verify_slice`
   - `CARBONADO_ERR_SCRUB_REQUIRES_VERIFICATION` (13) — distinct from scrub recovery failure
   - encode body pack extended with chunk/ecc/vsc fields (nullable C out-params)
3. **G9 start:** rust-engine golden buffers (c0/c4 body + headered c4) decoded under lean; lean re-encode bit-matches rust body.
4. **Stream buffers:** `stream_encode_buffer` / `stream_decode_buffer` / outboard buffer helpers compose over Lean under `backend-lean` (not silent pure-Rust).

### Phase 2 residuals (historical; full suite green at R7)

- ~~Residual sharding/fec_chaos~~ **green under lean (R6)** — **`format` (R1)** / **`header_tamper` (R2)** / **`format_amplification` (R3)** / **`codec` + `seekable_slices` (R4)** / **`streaming` + `streaming_limits` (R5)** / **`sharding` + `fec_chaos` (R6)** / `bao_keyed_contract` / `fec_scrub_matrix` in freeze
- Seekable outboard slice C **R9 live** (`carbonado_verify_slice_outboard` + lean dispatch; **W4b permanent** full buffers at C ABI — no ReadAt callback)
- **Inboard `verify_slice` under lean (W4a closed):** auth-first O(slice) retain via `decodeRecRetainRange` (O(N) time over full response; full body input at C) — parity with Rust `SliceRegionWriter` class; `seekable_slices` freeze-green
- CI freeze (Phase 5); pure Lean SLH FFI **closed at R9** (dual-suite may keep composition)
- ~~Pure Lean rkyv encode residual (**W3**)~~ **closed** — pure Lean encode/decode + Directory/CLI rkyv; dual-suite still uses Rust rkyv via composition
- Rust-root directory checksum goldens under lean encode (**W2b permanent residual** — same-engine directory codecode green in `determinism_roundtrip`; cross-engine roots may differ; `phase3_g9_directory` decode SSOT)

### Determinism contracts (**W2d shipped**)

| Contract | Steps | Assert |
|----------|-------|--------|
| **codecode** (EDE) | encode → decode → encode | `pt' == pt` and `A' == A` under fixed params (nonce pinned when Encrypted) |
| **decodec** (DED) | decode archive → encode → decode | `pt' == pt` and `B == A` when encode is deterministic under same pins |

**Shipped:** `tests/determinism_roundtrip.rs` (auto-included in lean freeze). Pins: G9 MASTER/NONCE/`g9_matrix_v1`.

| Matrix | Coverage | Wire equality |
|--------|----------|---------------|
| No-compress body | c0/c1/c4/c5/c8/c9/c12/c13 | full `A' == A` both engines |
| No-compress headered | c4/c5/c12/c13 | full `A' == A` both engines |
| No-compress outboard | c4/c5/c12/c13 | full wire (main/out/par/header) both engines |
| Compress body (same-engine) | c2/c3/c6/c7/c10/c11/c14/c15 | same-engine `A' == A`; **cross-engine permanent residual (W2a)** |
| Compress headered (same-engine) | c6/c7/c14/c15 | same-engine `A' == A` |
| Compress outboard (same-engine) | c6/c7/c14/c15 | same-engine wire equality |
| Directory public (same-engine) | phase3 seed tree, zero master | same-engine catalog+segments |
| DED from G9 body goldens | body no-compress, active-engine fixtures | re-encode matches committed golden |
| W2a residual | G9 `outboard_c14` rust vs lean mains | hard `assert_ne!` + frame descriptor (fail-closed if fixtures missing) |
| W2b residual | live rust vs live lean catalog roots | hard pins `0b119f12…` ≠ `f67b6f49…`; seed `16e2369f…` decode-only |

Encrypted without fixed nonce: wire identity out of scope.

---

## Phase 3 allowlist (directory dual-backend)

**Phase 3 closed:** directory encode/decode under `backend-lean` via composition (Rust rkyv FilepackManifest v2 + Adamantine framing + FS; Lean outboard/headered crypto). Allowlist `tests/lean_backend_phase3.rs` (+ `format_policy`); G9 rust-encode fixture → lean decode (`tests/fixtures/phase3_g9_directory/`). `just test-lean-phase3`.

Core `directory_archive` and non-golden `filepack_interop` pass under lean in practice; dedicated allowlist remains the gate. OTS dual-backend / CLI dual → Phase 4 (closed).

---

## Phase 4 allowlist (PQC + CLI + directory OTS)

**Phase 4 closed:** dual-suite SLH via **G10 strategy A** (Rust `bitcoinpqc` `crypto::slh_*` under both backends). **R9:** pure Lean `signRoot`/`verifyRoot` live via libbitcoinpqc in `libcarbonado` (optional purity path; dual-suite need not switch). Directory OTS: offline CBOTS composition (no Lean-native stamping).

**CLI dual (honest scope):**
- **Dual-engine:** directory encode/decode (library + subprocess), buffer APIs (`file::encode` / `file::encode_outboard` / headered decode), inboard/encrypted stream **E1** → Lean buffer ABI, **W1a** `decode_stream` → Lean `decode_headered`.
- **W1b:** public `stream_*_outboard` under lean is S4 O(chunk/stripe) **composition** (not pure Lean stream). Pure Lean chunked C residual remains.
- **Lean-linked binary:** `cli` + `backend-lean` proves link/run; directory subprocess + stream dual paths are CLI evidence.

```bash
just test-lean-phase4
# or:
cargo test --no-default-features --features "backend-lean,pqc,ots,cli" \
  --test lean_backend_smoke --test lean_backend_phase2 --test lean_backend_phase3 \
  --test format_policy --test slh_outboard --test lean_backend_phase4
```

Allowlist: `lean_backend_phase4.rs` + `slh_outboard.rs` (+ Phase 1–3). Full `bin_*` matrix optional under lean-linked binary.

---

## Phase 5 — CI freeze both backends (G11 closed; G8 allowlist freeze → R7 full)

**Phase 5 closed** as dual-backend CI freeze of the allowlist. **R7 expanded freeze to full dual suite and closed full-suite G8.**

### Normative commands

| Backend | CI job (`.github/workflows/rust.yaml`) | Local / shared command |
|---------|----------------------------------------|-------------------------|
| `backend-rust` | **`desktop`** | `cargo test`; serial: `--no-default-features --features "backend-rust,pqc,ots,cli" --test serial_fec_path`; optional: `--features "async,async-tokio,man-gen"` (never `--all-features`); smoke + CLI |
| `backend-lean` | **`dual-backend-lean`** | `just test-lean-ci` (full dual suite as of R7) |

### Lean env + build (fail-closed)

```bash
nix build .#libcarbonado -o result-libcarbonado
export CARBONADO_LEAN_LIB=$PWD/result-libcarbonado/lib
export CARBONADO_LEAN_INCLUDE=$PWD/result-libcarbonado/include
export LD_LIBRARY_PATH=$CARBONADO_LEAN_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
# Fail-closed: libcarbonado.so (or .dylib) must exist under CARBONADO_LEAN_LIB
just test-lean-ci
```

- **Never** enable both engines: must use `--no-default-features --features "backend-lean,pqc,ots,cli"` (not `--features backend-lean` alone).
- If `CARBONADO_LEAN_LIB` is unset, `just test-lean-ci` runs `nix build .#libcarbonado -o result-libcarbonado` then exports env.
- If the shared library is still missing after build, the recipe **exits non-zero** (fail-closed).
- `carbonado-sys` with feature `require-lib` (enabled by `backend-lean`) **hard-errors** if `CARBONADO_LEAN_LIB` is unset or the library file is missing; CI always sets env after nix build.
- Lean-only integration crates (`tests/lean_backend_*.rs`) use `#![cfg(feature = "backend-lean")]`. Under default/`backend-rust` builds they compile as empty harnesses (0 tests) — expected, not a silent skip of freeze coverage (freeze always uses `backend-lean`).

### Freeze contents (R7)

Unfiltered full dual suite under features `"backend-lean,pqc,ots,cli"`: lib units + all integration tests (phase gates, measured-green files from P5/R1–R6, **`bin_cli` / `bin_heuristics` / `bin_smoke`**, etc.). Historical P5 explicit `--test` allowlist documented in [GAPS.md](./GAPS.md) for archaeology.

### G8 status (honest)

| Claim | Status |
|-------|--------|
| G11 live CI both backends (Linux) | **closed** |
| G8 **allowlist** dual-backend bar (P5 freeze) | **closed** (this phase) |
| G8 **full** `cargo test --no-default-features --features "backend-lean,pqc,ots,cli"` | **closed** (R7 2026-07) — freeze equals full suite |

**Post-G8 residuals (purity / feature-policy — not dual-suite red):** ~~pure Lean SLH FFI~~ **R9 closed**; ~~seekable outboard slice C~~ **R9 closed**; ~~rkyv dual-decode~~ **R9 closed**; ~~pure Lean rkyv encode + Directory/CLI~~ **W3 closed** (dual-suite Rust rkyv encode composition SSOT; never claim dual-suite *requires* pure Lean); ~~async dual policy~~ **R10 closed** (freeze never requires `async`; lean+async dual-aware via E1); `streaming_async` / `parallel_determinism` permanently feature-gated off freeze; ~~W1a+W1b dual honesty / public outboard E2~~ **closed** (pure Lean chunked C residual); ~~W2d codecode/decodec~~ **closed** (`determinism_roundtrip`); ~~W2a/W2b~~ **permanent residuals** (cross-engine compress/dir encode; same-engine green); ~~W4a inboard O(slice) retain~~ **closed**; **W4b** permanent full-buffer C outboard slice; **W4c** permanent buffer-only zstd under lean; **W4d** permanent FEC O(body) + async encoded spool.

---

## Later phases (test-suite coverage)

| Phase | Test classes unlocked | Depends on |
|-------|----------------------|------------|
| **2** | outboard/scrub/slice smoke + G9 seed + stream buffer compose | **closed** — see Phase 2 allowlist above |
| **3** | directory (core Adamantine/rkyv), format_policy, filepack_interop (non-golden), deprecation_aliases | **closed** — rkyv dual-suite via composition |
| **4** | cli dual, pqc (slh_outboard), ots directory paths | **closed** — G10-A composition; pure Lean SLH FFI **R9 closed** |
| **5** | CI freeze both backends; G11 closed; G8 allowlist freeze | **closed** — `just test-lean-ci` + `dual-backend-lean` job |
| **R7** | Full G8 close; freeze = unfiltered lean suite (incl. `bin_*`) | **closed** (2026-07) — see [GAPS.md](./GAPS.md) R7 |
| **R8** | G9 full cross-backend matrix (body/headered/outboard, both directions) | **closed** (2026-07) — `tests/g9_cross_backend.rs` + `tests/fixtures/g9/`; see [GAPS.md](./GAPS.md) R8 |

### R8 / G9 classification

| Concern | Detail |
|---------|--------|
| Contract file | `tests/g9_cross_backend.rs` |
| Fixtures | `tests/fixtures/g9/{rust,lean}/` (manifest JSON + binary blobs) |
| lean→rust | default `backend-rust` decodes `lean/*` (no libcarbonado required) |
| rust→lean | `backend-lean` + `CARBONADO_LEAN_LIB` decodes `rust/*`; public + fixed-nonce encrypted body re-encode bit-match |
| Matrix | body c0/c1/c4/c5/c8/c9/c12/c13; headered c4/c5/c12/c13; outboard c4/c5/c12/c13/c14 |
| Residual | **W2a/W2b permanent:** cross-engine Compression / directory encode bit-match; same-engine codecode green; `phase3_g9_directory` decode seed remains SSOT |
| Regen | `just g9-gen-fixtures` or `G9_WRITE_FIXTURES=1` on ignored `write_fixtures` |

### W2d / determinism classification

| Concern | Detail |
|---------|--------|
| Contract file | `tests/determinism_roundtrip.rs` |
| Contracts | **codecode** (EDE) + **decodec** (DED) — shipped for claimed matrix |
| Pins | same MASTER/NONCE/`g9_matrix_v1` as G9 |
| Engines | default `backend-rust` + lean freeze (auto-include) |
| Cross-link | [GAPS.md](./GAPS.md) W2 table; [LIMITS.md](./LIMITS.md) W2a/W2b permanent residuals |

---

## Maintenance

- New `tests/*.rs` files **must** be added to the classification table above in the same PR.
- New public encode/decode surfaces used by tests must be listed in the API table and, if dual-backend-relevant, in [ABI.md](./ABI.md).
- Prefer strict `matches!` on specific `CarbonadoError` variants for failure-mode tests; when ABI collapse prevents 1:1 mapping, document backend-aware expectations rather than loosening asserts permanently.
- **R7 freeze is unfiltered** under lean features (`just test-lean-ci` = full `cargo test --no-default-features --features "backend-lean,pqc,ots,cli"`). New contract integration tests **auto-enter** CI `dual-backend-lean` — no allowlist edit required. Rust-only or feature-gated suites **must** use `#![cfg(...)]` (as `streaming_async` / `parallel_determinism` do) and be documented under post-G8 residuals in [GAPS.md](./GAPS.md) / [LIMITS.md](./LIMITS.md); otherwise lean CI will compile and run them.
