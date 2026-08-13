# G9 cross-backend fixtures (Milestone R8)

Committed wire goldens for **Rust ↔ Lean** encode/decode parity on **no-compress** formats.

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
  lean/   # encoded under backend-lean + fixed NONCE when encrypted
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

- **In scope:** body/headered/outboard public + encrypted fixed-nonce, **both directions**.
- **Continuous re-encode bit-match (CI under lean):** body c0/c1/c4/c5/c8/c9/c12/c13;
  headered c4/c5/c12/c13; outboard c4/c5/c12/c13 (no compress). Live lean re-encode vs
  rust golden.
- **Committed fixture identity:** rust/ and lean/ trees are regenerated together under the
  same pins; c14 outboard mains may differ (Compression residual).
- **Residuals (W2 settled):** cross-engine Compression encode bit-match is **permanent**
  (W2a — zstd frames differ; decode interop only). Cross-engine directory encode bit-match
  is **permanent** (W2b; `phase3_g9_directory` decode seed remains SSOT). Same-engine
  codecode/decodec shipped in `tests/determinism_roundtrip.rs` (W2d).

## Regeneration

```bash
# Both engines (recommended)
just g9-gen-fixtures

# Or manually:
G9_WRITE_FIXTURES=1 cargo test --test g9_cross_backend write_fixtures -- --ignored --nocapture

eval "$(just _lean-env)"
G9_WRITE_FIXTURES=1 cargo test --no-default-features --features "backend-lean,pqc,ots" \
  --test g9_cross_backend write_fixtures -- --ignored --nocapture
```

Do **not** hand-edit binaries; regenerate and commit both `rust/` and `lean/` trees together.

## Tests

| Command | Direction |
|---------|-----------|
| `cargo test --test g9_cross_backend` | lean→rust + self RT + zero-nonce contract (no libcarbonado) |
| lean features + `CARBONADO_LEAN_LIB` | rust→lean + continuous re-encode bit-match + self RT |
| `just test-g9` | both directions |
| `just test-lean-ci` | full dual suite (includes this file after R7 freeze) |
