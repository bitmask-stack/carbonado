# G9 cross-backend fixtures (Milestone R8)

Committed wire goldens. Rust still **decodes** historical Lean AOT bytes. There is no live Cargo Lean encoder.

## Pins

| Pin | Value |
|-----|--------|
| `MASTER` | `0ca1b0da00112233445566778899aabbccddeeff102030405060708090a0b0c0` (same as `lean_backend_phase2`) |
| `NONCE` | `0102030405060708090a0b0c0d0e0f10` (Phase 2 fixed-nonce pattern) |
| `PLAINTEXT` / `plaintext_id` | `g9 cross-backend matrix v1` / `g9_matrix_v1` |

> **Test-only.** Do **not** reuse `NONCE` (or this `MASTER`) for production encryption.
> AES-CTR nonce reuse under the same master key is **catastrophic** (keystream reuse →
> plaintext recovery). Prefer CSPRNG nonces via `encode` / `file::encode` for live archives.
> See AGENTS.md §2.1.4.

## Layout

```text
g9/
  rust/   # encoded under default backend-rust
  lean/   # historical Lean AOT encode + fixed NONCE when encrypted
```

### Body (`body_c{fmt}.bin` + `.meta.json`)

| Format | Bits | Notes |
|--------|------|--------|
| c0, c4, c8, c12 | public | Deterministic (no RNG) |
| c1, c5, c9, c13 | encrypted | Fixed `NONCE`, **embedded** layout `[nonce\|tag\|ct]` |

### Headered (`headered_c{fmt}.bin` + `.meta.json`)

| Format | Notes |
|--------|--------|
| c4, c12 | public headered |
| c5, c13 | encrypted, fixed `payload_nonce` = `NONCE` |

### Outboard (`outboard_c{fmt}/`)

| Format | Notes |
|--------|--------|
| c4, c12 | public bare main + optional `out.bin` / `par.bin` (no compress; wire-identical engines) |
| c14 | public **with Compression** — decode interop only; mains may differ (Zstd residual) |
| c5, c13 | **header-path** encrypted: main is `[tag\|ct]`, `header.bin` carries `payload_nonce` |

`meta.json` records hash, padding, layout flags, and nonce hex when encrypted.

**Empty `out.bin`:** valid for single-leaf / small mains when Verification is set
(`has_verification_outboard: true` with zero-length outboard). Not a regen bug — bao-tree
geometry yields an empty post-order outboard for some tiny payloads.

## Matrix scope (R8 DoD)

- **In scope now:** Rust decode of committed `lean/` goldens + rust self-roundtrip.
- **Committed fixture identity:** `lean/` is frozen historical AOT output; `just g9-gen-fixtures`
  regenerates `rust/` only. c14 outboard mains may differ (Compression residual).
- **Residuals (W2 settled):** cross-engine Compression encode bit-match is **permanent**
  (W2a — zstd frames differ; decode interop only). Frame **parameters** (magic, checksum
  off, no dict, rust `0x00`+windowLog 25 vs lean `0x20`+FCS) are specified in
  `Carbonado.Compress` and checked by `tests/zstd_frame_params.rs`. Cross-engine directory encode bit-match
  is **permanent** (W2b; `phase3_g9_directory` decode seed remains SSOT). Same-engine
  codecode/decodec shipped in `tests/determinism_roundtrip.rs` (W2d).

## Regeneration

```bash
just g9-gen-fixtures
# or:
G9_WRITE_FIXTURES=1 cargo test --test g9_cross_backend write_fixtures -- --ignored --nocapture
```

Do **not** hand-edit binaries. `lean/` goldens are historical; do not invent a Cargo Lean encoder to regenerate them.

## Tests

| Command | What it does |
|---------|-----------|
| `cargo test --test g9_cross_backend` | Rust decode of `lean/` goldens + rust self-roundtrip + zero-nonce contract |
| `just test-g9` | same |
