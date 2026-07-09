# `ref/` — reference implementations (not product source)

Any language. Used to **prove and bit-match** Lean AOT analogues (verik1 / beastdb pattern).

Product code lives only under `Carbonado/` (Lean) and is built with Nix flakes.

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
| `carbonado-rust` | Frozen historical Rust product | pending freeze |
| `parity-harness/` | Compare drivers | skeleton (README) |
| `crates/` | crates.io vendors (e.g. `ctr` 0.9.2) | skeleton (README) |

Initialize:

```bash
git submodule update --init --recursive
```
