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

**Parity bar (G8):** `cargo test` with `backend-rust` and with `backend-lean` (links Lean AOT C). Same tests; not separate Lean-only demos.

See [TEST_CONTRACT.md](./TEST_CONTRACT.md), [ABI.md](./ABI.md), [PARITY.md](./PARITY.md), [LIMITS.md](./LIMITS.md), AGENTS.md dual-backend block.

| ID | Gap | Status |
|----|-----|--------|
| G0 | Lean+Nix scaffold | **closed** (Program A) |
| G1 | `ref/` pins + dual-backend SSOT clarity | **partial** (pins present; dual-backend docs closed at P0; optional `ref/carbonado-rust` freeze still open) |
| G2 | EtM Lean | **closed** (Program B) |
| G3 | RS 4/8 Lean | **closed** (Program C) |
| G4 | Keyed Bao Lean | **closed** (Program D) |
| G5 | Pipeline / stream / scrub / shard | **closed** (Program E) |
| G6 | zstd link + SLH product | **partial** (zstd closed; SLH FFI open — see G10) |
| G7 | Adamantine + CLI | **partial** (Lean CFP2 path closed; **rkyv wire for dual-suite open** — Phase 3) |
| **G8** | **Dual-backend: C ABI + `cargo test --features backend-lean` full suite** | **open** (P0 inventory/docs **closed**; P1+ engineering open) |
| G9 | Cross-backend encode/decode matrix (Rust↔Lean) | **open** (depends on G8 Phase 2 body/headered stability) |
| G10 | libbitcoinpqc real SLH sign/verify in libcarbonado | **open** (wire+binding in Lean; FFI not linked) |
| G11 | Live CI matrix both backends | **open** (depends on G8 Phase 1+ allowlist → full; freeze at P5) |

## Dual-backend phases (G8 breakdown)

| Phase | Work | Status |
|-------|------|--------|
| **P0** | Test contract inventory, ABI.md, GAPS/AGENTS dual-backend, cross-doc consistency | **closed** (2026-07; docs-only) |
| P1 | C ABI v0 live exports + libcarbonado link + `backend-lean` core allowlist green | **open** (stubs still `NOT_IMPLEMENTED`) |
| P2 | Format matrix + scrub/outboard/stream + cross-backend buffer (G9 start) | **open** |
| P3 | rkyv-compatible catalog + directory suite (G7 residual) | **open** |
| P4 | PQC (G10) + CLI dual path | **open** |
| P5 | CI freeze both backends; G8 + G11 closed | **open** |

### P0 deliverables (evidence of close)

| Deliverable | Location |
|-------------|----------|
| Full `tests/*.rs` classification + API map + Phase 1 allowlist | [TEST_CONTRACT.md](./TEST_CONTRACT.md) |
| C ABI ownership, error codes, v0 symbols, stub honesty, link notes | [ABI.md](./ABI.md) + `include/carbonado.h` |
| Dual-backend SSOT rules | AGENTS.md (top block); this file |
| Cross-doc model (no “Lean replaces Rust” product rule) | [PARITY.md](./PARITY.md), [LIMITS.md](./LIMITS.md), [PROOFS.md](./PROOFS.md) |

P0 does **not** require live encode/decode through `backend-lean` or full `nix build .#libcarbonado` product export maturity.
