# `ref/` — reference implementations (not product source)

Any language. Used to **prove and bit-match** Lean AOT analogues (verik1 / beastdb pattern).

Trees under `ref/` are **third-party oracles / vendors only** — not product engines. Product engines live outside `ref/`:

| Engine | Location |
|--------|----------|
| **Rust** (first-class + dual-suite SSOT) | live `src/`, `tests/` (also benches/examples/CLI) |
| **Lean 4** (proofs + AOT `libcarbonado`) | `Carbonado/`, `CarbonadoTest/`; built via Nix flakes |

**G1/W5a permanent policy:** no `ref/carbonado-rust` product pin. Do not invent a submodule that freezes or demotes live Rust.

See [docs/PARITY.md](../docs/PARITY.md) for pin table and [docs/SPEC-MATRIX.md](../docs/SPEC-MATRIX.md) for coverage.

## Submodules (see [docs/PARITY.md](../docs/PARITY.md) for SHAs)

| Path | Purpose | Status |
|------|---------|--------|
| `bao-tree` | Surmount keyed Bao fork | **pinned** |
| `reed-solomon-erasure` | RS 4/8 | **pinned** |
| `rustcrypto-block-ciphers` | AES 0.8.4 | **pinned** |
| `rustcrypto-macs` | HMAC 0.12.1 | **pinned** |
| `rustcrypto-hashes` | SHA-2 0.10.9 | **pinned** |
| `blake3` | Hash / Bao leaves | **pinned** |
| `zstd` | Compression C (Nix-linked) | **pinned** |
| `bitcoinpqc` | SLH-DSA-SHA2-128s bindings | **pinned** |
| ~~`carbonado-rust`~~ | Product pin (not used) | **absent by policy** (G1/W5a permanent no-pin — live `src/` + `tests/` SSOT; see [PARITY.md](../docs/PARITY.md)) |
| `parity-harness/` | Compare drivers | skeleton (README) |
| `crates/` | crates.io vendors (e.g. `ctr` 0.9.2) | skeleton (README) |

Initialize:

```bash
git submodule update --init --recursive
```
