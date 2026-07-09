# carbonado — vision (dual-backend: Rust + Lean 4 AOT + Nix)

**Mission:** Apocalypse-resistant archival format for consensus-critical data.

**Product model:** Rust remains a **first-class** production engine (`src/`, default `backend-rust`). Lean 4 AOT (`Carbonado/`, `libcarbonado`) is a **second engine**: machine-checked proofs plus a wire- and C-ABI-compatible implementation. Both must pass the same Rust `tests/` (G8 dual-backend parity).

## Prove everything

Each product claim is either:

- machine-checked in Lean (no `sorry` in product), and/or  
- bit-matched via the Rust suite on `backend-lean` and/or pinned `ref/` oracles (CI parity gates).

Lean covers encode/decode, EtM, FEC, keyed Bao, scrub, streaming geometry, sharding, Adamantine directories, outboard, SLH sidecars, CLI — **in addition to**, not as a deletion of, the Rust engine.

## Method

1. Pin references under `ref/` (submodules, exact commits from Cargo.lock / Surmount forks).  
2. Lean algorithms + theorems; keep Rust `src/`/`tests/` first-class.  
3. AOT to C via Lean’s backend (never hand-edit generated C); expose C ABI for `backend-lean`.  
4. Nix links AOT objects and allowed external C (zstd, libbitcoinpqc) until replaced.  
5. Parity: `ref/` drivers + dual-backend `cargo test` ([TEST_CONTRACT.md](./TEST_CONTRACT.md), [PARITY.md](./PARITY.md)).

## Precedents

- **beastdb** — Lean product + Nix AOT packaging  
- **verik1** — prove and bit-match production crypto against `ref/`

## Priority

Truth, correctness, depth, quality — over schedule.
