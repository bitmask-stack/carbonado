# carbonado — vision (Rust engine + Lean 4 proofs + Nix)

**Mission:** Apocalypse-resistant archival format for consensus-critical data.

**Product model:** Rust is the production engine (`src/`, default `backend-rust`). Lean 4 (`Carbonado/`) is spec + machine-checked proofs plus an AOT demo. There is no product C ABI and no Cargo Lean backend. Do not claim G8 C-ABI parity.

## Prove everything

Each product claim is either:

- machine-checked in Lean (no `sorry` in product), and/or
- covered by the Rust suite (`tests/`) and/or pinned `ref/` oracles (CI gates).

Lean covers encode/decode, EtM, FEC, keyed Bao, scrub, streaming geometry, sharding, Adamantine directories, outboard, SLH sidecars, CLI — **in addition to**, not as a deletion of, the Rust engine.

## Method

1. Pin references under `ref/` (submodules, exact commits from Cargo.lock / third-party oracles).
2. Lean algorithms + theorems; keep Rust `src/`/`tests/` first-class.
3. Lean AOT demo may link tiny C `@[extern]` shims (zstd, SLH) for goldens. That is not a Rust `-sys` product.
4. Nix builds Lean proofs/demo and Rust quality packages.
5. Parity: `ref/` drivers + Rust `cargo test` ([TEST_CONTRACT.md](./TEST_CONTRACT.md), [PARITY.md](./PARITY.md)).

## Precedents

- **beastdb** — Lean product + Nix AOT packaging  
- **verik1** — prove and bit-match production crypto against `ref/`

## Priority

Truth, correctness, depth, quality — over schedule.
