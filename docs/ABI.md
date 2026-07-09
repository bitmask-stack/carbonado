# carbonado C ABI (dual-backend)

Stable C interface for the **Lean AOT engine** (`libcarbonado`). Rust `backend-lean` links this library (`carbonado-sys`) and is required to expose the **same high-level Rust API** as `backend-rust` so that `tests/` is one contract.

**Normative sources (must stay in sync):**

| Artifact | Role |
|----------|------|
| [`include/carbonado.h`](../include/carbonado.h) | C declarations (v0 surface) |
| [`carbonado-sys/src/lib.rs`](../carbonado-sys/src/lib.rs) | Rust FFI bindings + error constants |
| [`nix/native/carbonado_abi.c`](../nix/native/carbonado_abi.c) | C stubs / weak symbols in the native archive |
| [`Carbonado/Ffi.lean`](../Carbonado/Ffi.lean) | Lean pure helpers + planned `@[export]` surface |
| This document | Ownership, versioning, error codes, link instructions |

**ABI version:** `1` (`CARBONADO_ABI_VERSION`). Bump major on breaking changes (symbol rename, error-code reuse, semantic change of successful outputs).

---

## Memory ownership

| Pattern | Rule |
|---------|------|
| Input buffers | Caller owns; not freed by libcarbonado |
| Output buffers | Returned via `uint8_t **out` + `size_t *out_len`; allocated with the same allocator family as `carbonado_free` (malloc); **caller frees with `carbonado_free`** (or takes ownership via `Vec::from_raw_parts` on the Rust side — do not double-free) |
| Errors | Integer codes only on the hot path; no heap error strings in v0 |
| Null | Null input pointers with non-zero lengths → `CARBONADO_ERR_INVALID_ARGUMENT` (when implemented) |

```c
void carbonado_free(void *p);  /* free(NULL) is a no-op */
```

---

## Versioning

```c
#define CARBONADO_ABI_VERSION 1u
uint32_t carbonado_abi_version(void);  /* returns CARBONADO_ABI_VERSION */
```

Lean: `Carbonado.Ffi.abiVersion` / `@[export carbonado_abi_version]`.

---

## Error codes (v0)

Stable integers shared by `include/carbonado.h`, `carbonado-sys`, and `Carbonado.Ffi`. Map to `CarbonadoError` in `src/backend/mod.rs` (`lean::map_err`). Unknown codes → generic failure.

| Code | Name | Meaning | Approximate Rust mapping |
|-----:|------|---------|--------------------------|
| 0 | `CARBONADO_OK` | Success | `Ok` |
| 1 | `CARBONADO_ERR_INVALID_ARGUMENT` | Null/lengths/nonce size/sequence | bad args; nonce length; empty segment |
| 2 | `CARBONADO_ERR_INVALID_KEY_LENGTH` | Master not 32 or 64 bytes | `InvalidKeyLength` (or current stand-in until dedicated variant) |
| 3 | `CARBONADO_ERR_AUTHENTICATION` | Header MAC / payload EtM / Bao auth | `AuthenticationFailed` (+ header MAC fails) |
| 4 | `CARBONADO_ERR_INVALID_MAGIC` | Bad `CARBONADO20\n` (or related magic) | `InvalidMagicNumber` |
| 5 | `CARBONADO_ERR_INVALID_HEADER` | Truncated/malformed header or body bounds | `InvalidHeaderLength` / truncated body |
| 6 | `CARBONADO_ERR_FEC` | RS geometry / shard errors | `UnevenFecChunks` / FEC failures |
| 7 | `CARBONADO_ERR_BAO` | Keyed Bao verify / slice stream errors | Bao / verification failures |
| 8 | `CARBONADO_ERR_ZSTD` | Compress/decompress failures | `ZstdError` |
| 9 | `CARBONADO_ERR_SCRUB_UNNECESSARY` | Scrub not needed | `UnnecessaryScrub` |
| 10 | `CARBONADO_ERR_SCRUB_FAILED` | Scrub cannot recover / requires verification | `InvalidScrubbedHash` / `ScrubRequiresVerification` |
| 11 | `CARBONADO_ERR_NOT_IMPLEMENTED` | Surface not exported or still stubbed | fail closed (Phase 0–1 stubs) |
| 12 | `CARBONADO_ERR_INTERNAL` | Unexpected / allocator / invariant | internal |

**Collapse rule:** Fine-grained Lean `PipelineError` variants map through `Carbonado.Ffi.ofPipelineError` into these codes at the C boundary. Distinct failure modes that tests assert via `matches!` must either keep distinct codes or get refined Rust-side mapping before those tests are on the lean allowlist. Do **not** map unrelated failures to a single diagnostic variant permanently.

**Phase 0–1 honesty:** Until real exports are linked, all encode/decode/verification_key C entry points return `CARBONADO_ERR_NOT_IMPLEMENTED` (weak stubs in `carbonado_abi.c`).

---

## Core v0 functions (in `include/carbonado.h`)

These are the **only** product symbols declared in the header today. Signatures must match the header byte-for-byte in meaning.

### Lifecycle

```c
uint32_t carbonado_abi_version(void);
void carbonado_free(void *p);
```

### Encode (low-level buffer ≈ Rust `encoding::encode` body)

Low-level layout: when encrypted, the body uses the embedded-nonce blob shape Rust low-level paths use (`[nonce|tag|ct]` inside the encrypt stage as applicable). For **public** formats, `nonce` may be null / `nonce_len == 0`. For **encrypted** formats, `nonce` must be 16 bytes (tests use fixed nonces for determinism).

```c
/* out: verifiable body only (no Carbonado Header). hash_out: 32-byte Bao root. */
int carbonado_encode(
    const uint8_t *master, size_t master_len,   /* 32 or 64 */
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t format,
    const uint8_t *nonce, size_t nonce_len,     /* 16 if encrypted; else 0/null */
    uint8_t **out, size_t *out_len,
    uint8_t hash_out[32]
);
```

### Decode (low-level ≈ Rust `decoding::decode`)

```c
int carbonado_decode(
    const uint8_t *master, size_t master_len,
    const uint8_t *hash, size_t hash_len,       /* 32 */
    const uint8_t *body, size_t body_len,
    uint32_t padding,
    uint8_t format,
    uint8_t **out, size_t *out_len
);
```

### Headered encode/decode (≈ Rust `file::encode` / `file::decode`)

```c
/* Full file: Header (177 B) || body. Bao root lives in the header. */
int carbonado_encode_headered(
    const uint8_t *master, size_t master_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t format,
    const uint8_t *nonce, size_t nonce_len,     /* 16 when Encrypted bit set */
    uint8_t **out, size_t *out_len
);

int carbonado_decode_headered(
    const uint8_t *master, size_t master_len,
    const uint8_t *archive, size_t archive_len,
    uint8_t **out, size_t *out_len
);
```

Lean pure analogues (not yet live C malloc wrappers): `Carbonado.Ffi.encodeHeaderedBytes` / `decodeHeaderedBytes`.

### Verification key

```c
/* Format-keyed Bao key: blake3::derive_key("carbonado-v2/verification", &[format]). */
int carbonado_verification_key(uint8_t format, uint8_t key_out[32]);
```

Lean pure: `Carbonado.Ffi.verificationKeyBytes`.

---

## Future C surface (not in `include/carbonado.h` v0)

The following are **planned** for later ABI revisions when Phase 2+ test classes need them. They are **not** declared in the current header; do not document them as exported.

| Future symbol (illustrative) | Rust analogue | Target phase |
|------------------------------|---------------|--------------|
| `carbonado_encode_outboard` / `carbonado_decode_outboard` | `encode_outboard` / `decode_outboard` | Phase 2 |
| `carbonado_scrub` / `carbonado_scrub_outboard` | `scrub` / `scrub_outboard` | Phase 2 |
| `carbonado_verify_slice` / `carbonado_extract_slice` | `verify_slice` / `extract_slice` | Phase 2 |
| Directory / Adamantine catalog helpers | `encode_directory` / `decode_directory` | Phase 3 (rkyv) |
| SLH sign/verify | `crypto::slh_dsa_*` | Phase 4 (G10) |

Until exported, Lean or Rust may implement these **above** the v0 body/headered ABI without new C symbols, but the dual-backend bar for those tests is green only when both backends produce matching results.

---

## Implementation status (Phase 0 close)

| Symbol | Lean pure | C in `libcarbonado` | `carbonado-sys` | Rust `backend-lean` dispatch |
|--------|-----------|---------------------|-----------------|------------------------------|
| `carbonado_abi_version` | `@[export]` in `Ffi.lean` | **implemented** (`carbonado_abi.c`) | bound | `lean::abi_version` |
| `carbonado_free` | — | **implemented** | bound | used on free paths |
| `carbonado_encode` | planned / helpers partial | **weak stub → NOT_IMPLEMENTED** | bound | not yet on crate-root `encode` |
| `carbonado_decode` | planned | **weak stub → NOT_IMPLEMENTED** | bound | not yet on crate-root `decode` |
| `carbonado_encode_headered` | pure `encodeHeaderedBytes` | **weak stub → NOT_IMPLEMENTED** | bound | `lean::encode_headered` wrapper exists; needs live lib |
| `carbonado_decode_headered` | pure `decodeHeaderedBytes` | **weak stub → NOT_IMPLEMENTED** | bound | `lean::decode_headered` wrapper exists; needs live lib |
| `carbonado_verification_key` | pure `verificationKeyBytes` | **weak stub → NOT_IMPLEMENTED** | bound | not yet wired to crate root |
| outboard / scrub / slice C | partial Lean modules | **not in header** | — | later |

**Phase 1 definition of done (engineering, not this doc pass):** real non-stub implementations for the v0 encode/decode/verification_key symbols in the linked archive; Phase 1 test allowlist green on `backend-lean`; `backend-rust` still full green.

Update this table as Phase 1 lands.

---

## Linking

```text
# After: nix build .#libcarbonado
export CARBONADO_LEAN_LIB=$PWD/result/lib
export CARBONADO_LEAN_INCLUDE=$PWD/result/include
cargo test --no-default-features --features "backend-lean,pqc,ots"
# typical link line: -L $CARBONADO_LEAN_LIB -lcarbonado -lpthread -ldl -lm
```

Exact `cargo` `rustc-link-*` flags live in [`carbonado-sys/build.rs`](../carbonado-sys/build.rs). If `CARBONADO_LEAN_LIB` is unset, `carbonado-sys` warns and does not link — encode/decode cannot succeed.

**Known residual (not Phase 0):** flake/`libcarbonado` packaging and full Lean export linkage may still need Phase 1 work; Phase 0 does not require `nix build .#libcarbonado` green for doc closure.

---

## Mutual exclusion of Cargo features

Enable **exactly one** of `backend-rust` or `backend-lean` per build (`src/backend/mod.rs` `compile_error!`). Dual-backend CI runs two invocations, not one binary with both engines.
