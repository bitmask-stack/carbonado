# carbonado — gaps

Living inventory. IDs are durable; close only when theorems and/or parity gates are green.

## Dual-backend model (north star)

| Role | Location |
|------|----------|
| First-class engine | **Rust** (`src/`, default `backend-rust`) — production library + CLI |
| Normative contract | **Rust `tests/`** — both backends must pass the same suite |
| Second engine | **Lean 4 AOT** (`Carbonado/`, `libcarbonado` via C ABI) — proofs + wire-compatible implementation |
| Build / proofs | Nix flakes (`nix flake check`, `libcarbonado` package) |
| Oracles | `ref/` pins + parity drivers |

**Parity bar (G8):** same `tests/` on both engines (not Lean-only demos). Default features enable `backend-rust` only — do **not** pass `--features backend-lean` alone (both engines → `compile_error!`).

```bash
cargo test                                                              # backend-rust (default)
just test-lean-ci                                                       # G8 freeze = full dual suite
# Equivalent unfiltered lean suite (includes bin_* via cli feature):
# cargo test --no-default-features --features "backend-lean,pqc,ots,cli"
```

See [TEST_CONTRACT.md](./TEST_CONTRACT.md), [ABI.md](./ABI.md), [PARITY.md](./PARITY.md), [LIMITS.md](./LIMITS.md), AGENTS.md dual-backend block.

| ID | Gap | Status |
|----|-----|--------|
| G0 | Lean+Nix scaffold | **closed** (Program A) |
| G1 | `ref/` pins + dual-backend SSOT clarity | **closed** (2026-07 **W5a**: third-party `ref/` pins present; dual-backend SSOT docs closed at P0; **permanent policy — no** `ref/carbonado-rust` product pin — live `src/` + `tests/` are dual-suite SSOT; see [PARITY.md](./PARITY.md)) |
| G2 | EtM Lean | **closed** (Program B) |
| G3 | RS 4/8 Lean | **closed** (Program C) |
| G4 | Keyed Bao Lean | **closed** (Program D) |
| G5 | Pipeline / stream / scrub / shard | **closed** (Program E) |
| G6 | zstd link + SLH product | **closed** (zstd AOT closed; dual-suite SLH composition **P4**; pure Lean SLH FFI **R9/G10** — dual-suite may still use Rust `bitcoinpqc` composition by design) |
| G7 | Adamantine + CLI | **partial** (dual directory + stream E1 + **W1a/W1b** closed; **W3** pure Lean rkyv encode/CLI closed; dual-suite rkyv encode remains Rust composition SSOT; pure Lean chunked stream residual) |
| **G8** | **Dual-backend: C ABI + full `cargo test --no-default-features --features "backend-lean,pqc,ots[,cli]"` suite** | **closed** (2026-07 R7: full suite green under lean; freeze = full suite via `just test-lean-ci`; post-G8 purity/feature residuals below) |
| G9 | Cross-backend encode/decode matrix (Rust↔Lean) | **closed** (2026-07 R8: no-compress body/headered/outboard both directions + fixed-nonce encrypted; `tests/g9_cross_backend.rs` + `tests/fixtures/g9/`; **W2d** codecode/decodec shipped; **W2a/W2b** permanent cross-engine compress/dir encode residuals) |
| G10 | libbitcoinpqc real SLH sign/verify in libcarbonado | **closed** (R9: pin `b309f444…` into `libcarbonado_native.a`; `carbonado_slh_*` C ABI + Lean `@[extern]`; AOT `signRoot`/`verifyRoot` live; dual-suite may still use Rust composition) |
| G11 | Live CI matrix both backends | **closed** (2026-07 P5: Linux job `dual-backend-lean` runs `just test-lean-ci`; `desktop` keeps `backend-rust` full suite) |

## Dual-backend phases (G8 breakdown)

| Phase | Work | Status |
|-------|------|--------|
| **P0** | Test contract inventory, ABI.md, GAPS/AGENTS dual-backend, cross-doc consistency | **closed** (2026-07; docs-only) |
| **P1** | C ABI v0 live exports + libcarbonado link + `backend-lean` core allowlist green | **closed** (2026-07; live `carbonado_*` via Lean AOT + `tests/lean_backend_smoke.rs`) |
| **P2** | Format matrix + scrub/outboard/stream + cross-backend buffer (G9 start) | **closed** (2026-07; additive outboard/scrub/slice C ABI; lean dispatch; `lean_backend_phase2.rs`; residual: full `format`/`codec`/`fec_scrub` suites, directory, seekable outboard slice, CI freeze → P3–P5) |
| **P3** | rkyv-compatible catalog + directory suite (G7 residual) | **closed** (2026-07; composition: Rust rkyv + Lean segment/catalog crypto; `lean_backend_phase3.rs`; G9 dir fixture) |
| **P4** | PQC (G10) + CLI dual path + directory OTS cases | **closed** (2026-07; G10 strategy A: Rust `bitcoinpqc` SLH + Lean container; CLI dual = directory library/subprocess dual-engine + lean-linked binary smoke; single-file stream E1 closed at **R5**; **W1a/W1b** dual honesty closed later; directory OTS CBOTS; `lean_backend_phase4` + `slh_outboard`; pure Lean SLH FFI residual **closed later at R9**) |
| **P5** | CI freeze both backends; G11 closed; G8 allowlist freeze | **closed** (2026-07; allowlist freeze; **full-suite G8 closed at R7**) |

### P3 deliverables (evidence of close)

| Deliverable | Location |
|-------------|----------|
| Dual-suite catalog wire = **rkyv** FilepackManifest v2 (not CFP2) | `src/filepack_manifest.rs` + `encode_directory` under `backend-lean` |
| Directory composition dispatch | segment `encode_outboard`/`decode_outboard` + catalog `file::encode`/`decode` → Lean C ABI; FS/rkyv/Adamantine framing stay Rust (`src/backend/mod.rs`, `src/file.rs`) |
| Allowlist | `tests/lean_backend_phase3.rs` (+ `format_policy`; smoke+phase2 still required) — `just test-lean-phase3` |
| G9 directory seed | `tests/fixtures/phase3_g9_directory/` rust-encoded → lean `decode_directory` |
| Docs | this file, [ABI.md](./ABI.md), [TEST_CONTRACT.md](./TEST_CONTRACT.md), [LIMITS.md](./LIMITS.md), AGENTS dual-backend |

**P3 honest residuals (historical; P4 closed OTS/CLI dual-suite):** pure Lean CLI still CFP2 (no Lean rkyv codec); no new directory C ABI symbols (composition only); rust-root checksum goldens (`filepack_interop` golden) are `backend-rust`-only until G9 encode bit-match; full format/codec suite → G8/P5.

### P4 deliverables (evidence of close)

| Deliverable | Location |
|-------------|----------|
| G10 dual-suite SLH (strategy A composition) | Rust `crypto::slh_*` + `bitcoinpqc` under both backends; Lean `Carbonado/Slh.lean` wire+bind model; pure Lean `carbonado_slh_*` C ABI added later at **R9** (optional purity) |
| SLH allowlist | `tests/slh_outboard.rs` + `tests/lean_backend_phase4.rs` SLH cases (`just test-lean-phase4`) |
| CLI dual path **as of P4 close** | **Directory** encode/decode library + subprocess hit Lean composition; **buffer** single-file APIs (`file::encode` / `encode_outboard`) hit Lean. **Stream dual at R5 (after P4):** `stream_encode_*` / `stream_decode_*` spool→Lean E1 (O(logical); not E2). At P4 close **`file::decode_stream` remained pure-Rust** — dual later at **W1a** (see post-G8 residual table). Default binary remains rust-engine. |
| Directory OTS | Offline CBOTS stubs (`ots` feature) compose over Lean catalog/segment crypto; phase4 OTS roundtrip + fail-closed cases |
| Allowlist gate | `lean_backend_smoke` + `phase2` + `phase3` + `format_policy` + `slh_outboard` + `lean_backend_phase4` |
| Docs | this file, [ABI.md](./ABI.md), [TEST_CONTRACT.md](./TEST_CONTRACT.md), [LIMITS.md](./LIMITS.md), AGENTS dual-backend |

**Live CLI dual (post-P4 supersession — not P4 evidence):** R5 E1 stream I/O + **W1a** `file::decode_stream` → Lean `decode_headered` + **W1b** public non-compress outboard S4 E2 composition. See residual table / LIMITS E1/E2 matrix.

**P4 honest residuals (historical; superseded in part at R9/R10/W1a):** ~~pure Lean `signRoot` / libbitcoinpqc~~ **closed R9**; ~~seekable outboard slice C~~ **closed R9**; rkyv dual-decode **closed R9** (encode residual remains); stream dual E1 is **spool-to-buffer** (not true chunked stream — O(logical) RAM); ~~`file::decode_stream` pure-Rust~~ **W1a closed**; ~~residual full files `sharding` / `fec_chaos`~~ **green at R6**; ~~async dual~~ **closed R10**.

### P5 deliverables (evidence of close)

| Deliverable | Location |
|-------------|----------|
| Frozen dual suite command (CI + humans) | `just test-lean-ci` (P5 name was “allowlist”; **live since R7** = full unfiltered dual suite) |
| Linux CI job (G11) | `.github/workflows/rust.yaml` job **`dual-backend-lean`**: `cachix/install-nix-action` → `nix build .#libcarbonado -o result-libcarbonado` → fail-closed `.so` check → `just test-lean-ci` |
| `backend-rust` CI | existing **`desktop`** job: `cargo test` (+ serial FEC with `backend-rust,pqc,ots,cli` + optional `async,async-tokio,man-gen` + smoke + CLI) — never `--all-features` (dual-backend mutual exclusion) |
| Env contract | `CARBONADO_LEAN_LIB`, `CARBONADO_LEAN_INCLUDE`, `LD_LIBRARY_PATH` (see [ABI.md](./ABI.md) Linking + [TEST_CONTRACT.md](./TEST_CONTRACT.md) Phase 5) |
| Docs | this file, [TEST_CONTRACT.md](./TEST_CONTRACT.md), [ABI.md](./ABI.md), [LIMITS.md](./LIMITS.md), AGENTS dual-backend |

**P5 freeze allowlist (historical; superseded at R7):** P1–P4 gates + measured-green full files (P5 + R1–R6 growth). Kept for archaeology; live freeze is the full suite.

| Class | Tests (P5-era explicit `--test` list) |
|-------|--------|
| Phase gates | `lean_backend_smoke`, `lean_backend_phase2`, `lean_backend_phase3`, `lean_backend_phase4` |
| P3–P4 companions | `format_policy`, `slh_outboard` |
| Measured-green full files (P5 + R1–R6) | `bao_keyed_contract`, `directory_archive`, `filepack_interop`, `deprecation_aliases`, `fec_scrub_matrix`, `shard_fec_scrub`, `serial_fec_path`, `adversarial_proptest`, `udp_fec_sim`, `apocalypse`, **`format`**, **`header_tamper`**, **`format_amplification`**, **`codec`**, **`seekable_slices`**, **`streaming`**, **`streaming_limits`**, **`sharding`**, **`fec_chaos`** |

### R7 — Full G8 close + freeze expansion (2026-07)

**G8 full suite closed** under lean features with live `libcarbonado`. Freeze equals full dual suite:

```bash
# R7 freeze = full dual suite (lib + integration, including bin_*).
just test-lean-ci
# Equivalent:
# cargo test --no-default-features --features "backend-lean,pqc,ots,cli"
```

| Former residual (now freeze-green) | Closed at |
|------------------------------------|-----------|
| `tests/format.rs` | R1 |
| `tests/codec.rs` | R4 |
| `tests/header_tamper.rs` | R2 |
| `tests/format_amplification.rs` | R3 |
| `tests/streaming.rs` / `streaming_limits.rs` | R5 E1 |
| `tests/seekable_slices.rs` | R4 |
| `tests/sharding.rs` | R6 |
| `tests/fec_chaos.rs` | R6 |
| lib unit missing verification outboard | R1 |
| Full `bin_*` CLI matrix under lean-linked binary | R7 (in unfiltered freeze) |

**Post-G8 residuals** (not dual-suite red; purity / feature-policy / composition honesty).  
**Post-R10 work program (waves):** ~~W0 hygiene~~ **closed** · ~~W1 dual honesty~~ **closed** (~~W1a~~ `decode_stream` dual; ~~W1b~~ public outboard stream E2 MVP) · ~~W2 G9 bit-match + **codecode/decodec** determinism~~ **closed** (W2d shipped; W2a/W2b permanent cross-engine residuals) · ~~W3 pure Lean rkyv encode~~ **closed** · ~~W4 memory/streaming quality~~ **closed** (W4a closed; W4b–d permanent residuals) · ~~W5a G1 pin~~ **closed** (permanent no product pin) · W5b CHIPs (external; out of product-tree scope).

| Residual | Notes | Wave |
|----------|--------|------|
| Pure Lean SLH FFI | **closed R9** (G10) — dual suite may still use Rust `bitcoinpqc` composition (not required to switch) | — |
| Pure Lean rkyv full encode + directory CLI | **W3 closed** — `encodeRkyvManifest` + Directory/CLI emit rkyv; goldens empty/single/multi+OTS; dual-suite encode remains Rust rkyv composition SSOT | **closed** |
| Seekable outboard slice C ABI | **R9 closed** for O(slice+height) hash; **W4b permanent:** full main+outboard buffers at C (no ReadAt callback ABI) | **W4b permanent** |
| Inboard `verify_slice` O(body) retain | **W4a closed** — O(slice) retained output + O(N) full-response walk; C still takes full body input buffer | **W4a closed** |
| Streaming zstd under lean | **W4c permanent** — buffer-only bulk zstd for Lean frame parity (W2a); no dual-safe streaming frames | **W4c permanent** |
| FEC O(body) / async encoded spool | **W4d permanent** — segment-wide RS O(FEC body); async always disk-stages O(encoded); no full async FSM this wave | **W4d permanent** |
| Async dual policy | **closed R10** — freeze never requires `async` | — |
| `streaming_async` / `parallel_determinism` | **permanent feature-gate** off freeze | — |
| ~~Stream E2 / dual honesty~~ | **W1a+W1b closed** — see below | **closed** |
| Pure Lean chunked stream C ABI | No streaming C symbols; inboard/encrypted stream remain E1; public outboard E2 is **composition** | residual after W1b |
| ~~codecode / decodec determinism suite~~ | **W2d closed** — `tests/determinism_roundtrip.rs` (no-compress body/headered/outboard; same-engine compress + directory) | **closed** |
| Compression encode bit-match (cross-engine) | **permanent residual (W2a)** — Lean AOT zstd frames ≠ Rust `zstd`; decode interop only; same-engine codecode green | permanent |
| Directory encode bit-match (cross-engine) | **permanent residual (W2b)** — live rust `0b119f12…` ≠ live lean `f67b6f49…` (pinned); `phase3_g9_directory` decode-only SSOT (not re-encode golden); same-engine codecode green | permanent |

### W1 — Dual-suite honesty (closed 2026-07)

| Item | Status | Detail |
|------|--------|--------|
| **W1a** `file::decode_stream` | **closed** | Under lean: header+`encoded_len` body → Lean `decode_headered` (E1 RAM). Smoke: `decode_stream_codecode_decodec_public_c14`. |
| **W1b** stream E2 MVP | **closed** | **Public non-Compression** `stream_*_outboard` under lean use rust **S4 O(chunk/stripe)** geometric composition (G9 **no-compress** wire bit-match; c4/c12 evidenced; **not** pure-Lean stream). Public **+ Compression** under lean is **O(logical)** bulk zstd (not E2). **Encrypted** outboard + all inboard stream + buffer APIs remain Lean **E1**. Smoke: `stream_outboard_public_e2_codecode_decodec_c4_c12` (2 MiB). Matrix: [LIMITS.md](./LIMITS.md) Stream E1/E2. |
| Residual | pure Lean chunked C ABI | Future — no false “true stream” claims for E1 paths |

### R10 — Async dual policy (closed 2026-07)

**DoD:** Either permanent freeze exclusion of `async`, **or** dual-aware lean+async after R5 E1 stable. **Both:** freeze excludes async permanently; product path dual-aware when both features are on.

| Policy | Detail |
|--------|--------|
| Dual freeze | `just test-lean-ci` / `"backend-lean,pqc,ots,cli"` — **never** includes `async` / `async-tokio` (permanent) |
| Contract tests | `tests/streaming_async.rs` is `#![cfg(feature = "async")]` → **0 tests** under freeze (not dual-suite red) |
| Sync stream dual | R5 E1 + **W1b** public outboard S4 composition (see W1 table above) |
| `stream_decode_async` honesty | After O(encoded) disk staging, calls dual-aware `stream_decode` — `backend-lean` → Lean E1 buffer decode; `backend-rust` → S4 pipeline. No silent pure-Rust when lean+async. |
| Costs (honest) | Disk O(encoded) staging always; under lean peak RAM **O(encoded + logical)** (E1 body `Vec` + plaintext); rust peak spool/chunk (FEC residual O(FEC body)); **not** pure Lean stream E2 |
| WASM | `NotImplemented` (host temp spool) |
| Optional smoke | `cargo test --no-default-features --features "backend-lean,pqc,ots,async,async-tokio" --test streaming_async` (+ `CARBONADO_LEAN_LIB`) — **not** freeze |

**Out of R10 scope (post-R10; ~~W1a+W1b~~ **closed**; ~~W2~~ **closed**; ~~W3~~ **closed**; ~~W4~~ **closed** with permanent residuals W4b–d; ~~W5a G1~~ **closed** permanent no product pin):** pure Lean chunked stream C residual; W5b CHIPs (external).

### W5a — G1 `ref/carbonado-rust` pin bookkeeping (closed 2026-07)

| Item | Status | Detail |
|------|--------|--------|
| **W5a** G1 product pin | **closed** (permanent policy) | **No** `ref/carbonado-rust` submodule or freeze SHA. Dual-suite SSOT = live `src/` + `tests/` (G8). `ref/` pins third-party oracles only. Rationale + procedure: [PARITY.md](./PARITY.md) freeze strategy. Docs: GAPS G1, LIMITS, SPEC-MATRIX, `ref/README.md` intro+row, AGENTS status+gates, `nix/tooling-purity.nix` comments. |
| **W5b** CHIPs | out of product-tree scope | External CHIPs normative drafting — not closed by W5a |

### W4 — Memory / streaming quality (closed 2026-07)

| Item | Status | Detail |
|------|--------|--------|
| **W4a** Inboard seekable slice | **closed** | Lean `decodeRecRetainRange` / `verifySliceInboard`: walk from offset 8 (no second response copy), **O(slice) retained** output (Rust `SliceRegionWriter` class); O(leaf) temps. Time O(N). C still takes full inboard body **input**. `count==0`: Lean C auth-first; dual Rust short-circuit. Tests: `seekable_slices`, `CarbonadoTest/Bao` multi-leaf. |
| **W4b** Outboard streaming C | **permanent residual** | Lean offset walk (`verifyOutboardSliceRecAt`) avoids recursive full half-extracts; hash O(slice+height). **No** additive `carbonado_verify_slice_outboard_at` / ReadAt callback — full main+outboard buffers at C remain permanent. Old full-buffer symbol kept. |
| **W4c** Streaming zstd | **permanent residual** | Prefer buffer-only under lean for Lean AOT frame parity (W2a cross-engine compress residual). Do not claim dual-safe streaming frames or E2 for Compression formats under lean. See LIMITS Stream E1/E2 matrix. |
| **W4d** FEC / async spool | **permanent residual** | FEC verification retains O(FEC body) shard buffers (segment-wide RS). `stream_decode_async` always disk-stages O(encoded); lean+async peak RAM O(encoded+logical). Full async FSM without encoded spool out of scope. Metrics in [STREAMING_PARALLELISM.md](../doc/STREAMING_PARALLELISM.md). |

### W2 — G9 bit-match + determinism (closed 2026-07)

| Item | Status | Detail |
|------|--------|--------|
| **W2d** codecode / decodec | **closed** | `tests/determinism_roundtrip.rs` — EDE + DED under G9 MASTER/NONCE/`g9_matrix_v1`. Matrix: body c0/c1/c4/c5/c8/c9/c12/c13; headered c4/c5/c12/c13; outboard c4/c5/c12/c13. Both engines (default rust + lean freeze). Asserts `pt' == pt` and `A' == A` / `B == A`. |
| **W2a** Compression cross-engine | **permanent residual** | Same-engine body/headered/outboard compress codecode/decodec green. Cross-engine: G9 `outboard_c14` mains differ (frame descriptor `00` vs `20`; roots `0abe5781…` vs `129b4518…`); hard-asserted fail-closed. Decode interop only. See [LIMITS.md](./LIMITS.md). |
| **W2b** Directory cross-engine | **permanent residual** | Same-engine public directory codecode/decodec green. Cross-engine residual is **live rust `0b119f12…` ≠ live lean `f67b6f49…`** (pinned hard asserts). `phase3_g9_directory` (`16e2369f…`) is **decode-only SSOT**, not a live re-encode golden. |
| **W2c** Full c0–c15 G9 matrix | **skipped** (optional) | Not required after W2a permanent residual. |

### W3 — Pure Lean product wire (closed 2026-07)

| Item | Status | Detail |
|------|--------|--------|
| **W3a** rkyv encode | **closed** | Pure Lean `encodeRkyvManifest` bit-matches Rust goldens empty/single/multi+OTS (`tests/fixtures/rkyv/`); encode→decode roundtrip; encode twice → same bytes (codecode). AOT: `rkyv FilepackManifestWire encode/decode goldens ok`. |
| **W3b** Directory / CLI | **closed** | `Directory.encodeDirectory` + CLI emit rkyv catalog body; decode via `decodeCatalogBody` (rkyv **or** CFP2 fallback). Pure Lean directory roundtrip AOT green. Dual-suite encode remains Rust rkyv composition SSOT. |
| **W3c** dual SLH via C | **wontfix** (docs honesty) | Dual-suite keeps Rust `bitcoinpqc` composition; pure Lean `carbonado_slh_*` for AOT/CLI only. Never claim dual-suite requires pure Lean SLH. |

### R9 — Pure Lean depth (optional post-G8; 2026-07)

| Track | Status | Evidence |
|-------|--------|----------|
| **G10 full** SLH FFI | **closed** | `nix/native/carbonado_slh.c` + libbitcoinpqc pin; `carbonado_slh_*`; Lean `signRoot`/`verifyRoot`; demo greps `SLH live sign/verify ok` |
| Seekable outboard slice C | **closed** | `carbonado_verify_slice_outboard` + Lean `verifySliceOutboard`; `backend-lean` dispatch; demo `outboard slice verify ok`; single-leaf short-main regression in `seekable_slices` |
| Pure Lean rkyv | **encode+decode closed (W3)** | `Carbonado/RkyvFilepack.lean` encode/decode goldens empty + single + multi/OTS (`tests/fixtures/rkyv/`); Directory/CLI emit rkyv; dual-suite composition still Rust rkyv SSOT for product encode |

**R9 freeze evidence:** rebuild `nix build .#libcarbonado` + `just test-lean-ci` after R9 review fixes (docs + SLH status taxonomy + count=0 docs + single-leaf test). Dual-suite composition SSOT unchanged.

**Never claim dual-suite requires pure Lean** when composition remains SSOT for product wire.

**P5 bar (historical):** G11 closed + dual allowlist frozen in CI. **R7 bar:** full G8 suite closed; `just test-lean-ci` runs unfiltered full dual suite.

### R8 — G9 full cross-backend matrix (2026-07)

**G9 closed** for the no-compress body/headered/outboard matrix (public + encrypted fixed-nonce), **both directions**:

| Deliverable | Location |
|-------------|----------|
| Fixtures | `tests/fixtures/g9/{rust,lean}/` — body c0/c1/c4/c5/c8/c9/c12/c13; headered c4/c5/c12/c13; outboard c4/c5/c12/c13/c14 |
| Contract tests | `tests/g9_cross_backend.rs` — lean→rust (default features), rust→lean (lean features + lib), re-encode bit-match |
| Pins | MASTER/NONCE from Phase 2; plaintext `g9_matrix_v1`; regen via `just g9-gen-fixtures` / `G9_WRITE_FIXTURES=1` |
| Human gate | `just test-g9` (both directions); auto-included in `just test-lean-ci` (R7 freeze) |
| Fixed-nonce APIs | `encode_with_nonce`, `file::encode_with_nonce`, `stream_encode_buffer_with_nonce` (production defaults still CSPRNG) |

**G9 residuals (honest; settled at W2):**

| Residual | Notes |
|----------|--------|
| Compression encode bit-match | **permanent (W2a)** — Lean AOT zstd ≠ Rust `zstd`; c14 outboard **decode** interop only; same-engine codecode green in `determinism_roundtrip` |
| Directory encode bit-match | **permanent (W2b)** — live rust≠lean catalog roots (pinned); `phase3_g9_directory` is **decode-only SSOT** (not live re-encode golden); same-engine directory codecode green |
| Full c0–c15 with Compression | deferred / not required (W2c optional skipped) |
| ~~codecode/decodec suite~~ | **W2d closed** — `tests/determinism_roundtrip.rs` |

**P5 bar (historical):** G11 closed + dual allowlist frozen in CI. **R7 bar:** full G8 suite closed; `just test-lean-ci` runs unfiltered full dual suite.

### P2 deliverables (evidence of close)

| Deliverable | Location |
|-------------|----------|
| C ABI outboard / scrub / verify_slice (+ encode meta fields) | `include/carbonado.h`, `nix/native/carbonado_abi.c`, `Carbonado/Ffi.lean` |
| Lean scrub geometry peel + outboard scrub | `Carbonado/Scrub.lean` |
| Rust `backend-lean` dispatch | `src/backend/mod.rs`, `encoding`/`decoding`/`stream::{encode,decode}` |
| Allowlist smoke | `tests/lean_backend_smoke.rs` + `tests/lean_backend_phase2.rs` (`just test-lean-phase2`) |
| G9 start | rust golden body/headered → lean decode; lean re-encode bit-match |
| Docs | this file, [ABI.md](./ABI.md), [TEST_CONTRACT.md](./TEST_CONTRACT.md), [LIMITS.md](./LIMITS.md), AGENTS dual-backend |

**P2 honest residuals (historical; P3–P5 closed directory/OTS/CLI dual + CI freeze):** full `tests/format.rs` / `codec.rs` later green at R7; `fec_scrub_matrix` measured green and included in P5 freeze; seekable outboard slice API **closed R9**; ~~async dual~~ **closed R10**; CI freeze closed at P5.

### P0 deliverables (evidence of close)

| Deliverable | Location |
|-------------|----------|
| Full `tests/*.rs` classification + API map + Phase 1 allowlist | [TEST_CONTRACT.md](./TEST_CONTRACT.md) |
| C ABI ownership, error codes, v0 symbols, stub honesty, link notes | [ABI.md](./ABI.md) + `include/carbonado.h` |
| Dual-backend SSOT rules | AGENTS.md (top block); this file |
| Cross-doc model (no “Lean replaces Rust” product rule) | [PARITY.md](./PARITY.md), [LIMITS.md](./LIMITS.md), [PROOFS.md](./PROOFS.md), [VISION.md](./VISION.md) |

P0 does **not** require live encode/decode through `backend-lean` or full `nix build .#libcarbonado` product export maturity.
