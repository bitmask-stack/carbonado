# carbonado C ABI (dual-backend)

Stable C interface for the **Lean AOT engine** (`libcarbonado`). Rust `backend-lean` links this library (`carbonado-sys`) and is required to expose the **same high-level Rust API** as `backend-rust` so that `tests/` is one contract.

**Normative sources (must stay in sync):**

| Artifact | Role |
|----------|------|
| [`include/carbonado.h`](../include/carbonado.h) | C declarations (v0 core + Phase 2 additive) |
| [`carbonado-sys/src/lib.rs`](../carbonado-sys/src/lib.rs) | Rust FFI bindings + error constants |
| [`nix/native/carbonado_abi.c`](../nix/native/carbonado_abi.c) | Strong C exports calling Lean `@[export] l_carbonado_*` |
| [`Carbonado/Ffi.lean`](../Carbonado/Ffi.lean) | Lean pure helpers + live `@[export]` surface |
| This document | Ownership, versioning, error codes, link instructions |

**ABI version:** `1` (`CARBONADO_ABI_VERSION`). Bump major on breaking changes (symbol rename, error-code reuse, semantic change of successful outputs).

---

## Memory ownership

| Pattern | Rule |
|---------|------|
| Input buffers | Caller owns; not freed by libcarbonado |
| Output buffers | Returned via `uint8_t **out` + `size_t *out_len`; allocated with **`malloc`**. C callers free with **`carbonado_free`**. Rust `backend-lean` **copies** into a `Vec` then calls **`carbonado_free`** (allocator-agnostic; safe with jemalloc/mimalloc GlobalAlloc) |
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

Stable integers shared by `include/carbonado.h`, `carbonado-sys`, and `Carbonado.Ffi`. Converted to `CarbonadoError` in `src/backend/mod.rs` (`lean::map_err`). Unknown codes → generic failure.

Two columns matter for dual-backend work:

- **Target mapping** — intended 1:1 (or documented multi-source) diagnostics for failure-mode `matches!` tests.
- **Current `map_err` (Phase 2)** — live mapping; scrub codes 9/10/13 are distinct. Residual: InvalidArgument still generic; FEC modes collapse to `UnevenFecChunks` (with targeted MissingFecParity remap on outboard scrub).

| Code | Name | Meaning | Target Rust mapping | Current `lean::map_err` (Phase 2 + R4) |
|-----:|------|---------|---------------------|--------------------------------------|
| 0 | `CARBONADO_OK` | Success | `Ok` | `Ok` |
| 1 | `CARBONADO_ERR_INVALID_ARGUMENT` | Null/lengths/nonce size/sequence | dedicated arg/nonce/segment variants as needed | `InternalStateError("…invalid argument…")` (**P2 residual:** add `InvalidArgument` / reuse nonce variants before allowlist expands to nonce/sequence fails) |
| 2 | `CARBONADO_ERR_INVALID_KEY_LENGTH` | Master not 32 or 64 bytes | `InvalidKeyLength` | **`InvalidKeyLength`** |
| 3 | `CARBONADO_ERR_AUTHENTICATION` | Header MAC / payload EtM / **Bao auth** | `AuthenticationFailed` | **`AuthenticationFailed`** (R4: `baoAuthenticationFailed` joins header/payload auth) |
| 4 | `CARBONADO_ERR_INVALID_MAGIC` | Bad `CARBONADO20\n` (or related magic) | `InvalidMagicNumber` | `InvalidMagicNumber("lean-backend")` |
| 5 | `CARBONADO_ERR_INVALID_HEADER` | Truncated/malformed header, body bounds, **short inboard Bao prefix** | `InvalidHeaderLength` | **`InvalidHeaderLength`** (R4: Lean `invalidPrefix` maps here) |
| 6 | `CARBONADO_ERR_FEC` | RS geometry / shard errors | `UnevenFecChunks` / FEC failures | `UnevenFecChunks` |
| 7 | `CARBONADO_ERR_BAO` | Bao stream truncation / trailing / residual slice geometry | `BaoResponseTruncated` (not auth) | **`BaoResponseTruncated`** (R4: auth no longer collapses here) |
| 8 | `CARBONADO_ERR_ZSTD` | Compress/decompress failures | `ZstdError` | `ZstdError("lean-backend zstd")` |
| 9 | `CARBONADO_ERR_SCRUB_UNNECESSARY` | Scrub not needed | `UnnecessaryScrub` | `UnnecessaryScrub` |
| 10 | `CARBONADO_ERR_SCRUB_FAILED` | Scrub cannot recover | `InvalidScrubbedHash` | `InvalidScrubbedHash` |
| 11 | `CARBONADO_ERR_NOT_IMPLEMENTED` | Surface not exported or still stubbed | `NotImplemented` | **`NotImplemented`** |
| 12 | `CARBONADO_ERR_INTERNAL` | Unexpected / allocator / invariant | internal / dedicated | `InternalStateError` |
| 13 | `CARBONADO_ERR_SCRUB_REQUIRES_VERIFICATION` | Scrub without Verification bit | `ScrubRequiresVerification` | **`ScrubRequiresVerification`** (P2) |

**Phase 2 + R4 mapping:** scrub requires-verification is distinct (code 13). **R4:** `ofPipelineError` sends `baoAuthenticationFailed` → code 3 and `invalidPrefix` → code 5 (no longer collapsed into code 7). `InvalidSliceIndex { index, content_len }` is produced by Rust-side geometry pre-checks in `lean::verify_slice` (C ABI carries no structured fields). Residual: no dedicated InvalidArgument; MissingFecParity may still surface via FEC path when parity absent after verify fail.

**Collapse rule (C boundary):** Fine-grained Lean `PipelineError` variants map through `Carbonado.Ffi.ofPipelineError` into these **integer codes**. Distinct failure modes that tests assert via `matches!` must either keep distinct codes or get refined Rust-side mapping before those tests are on the lean allowlist. Do **not** permanently map unrelated failures to a single diagnostic variant.

**Phase 2 status:** v0 body/headered **plus** outboard/scrub/verify_slice are **live**. Encode packs include chunk/ecc/vsc metadata; **R3** adds `bytes_compressed` / `bytes_encrypted` (nullable C out-params; ABI version remains 1 additive).

---

## Core functions (in `include/carbonado.h`)

Signatures must match the header byte-for-byte in meaning.

### Lifecycle

```c
uint32_t carbonado_abi_version(void);
void carbonado_free(void *p);
```

### Encode (low-level buffer ≈ Rust `encoding::encode` body)

Low-level layout: when encrypted, the body uses the embedded-nonce blob shape Rust low-level paths use (`[nonce|tag|ct]` inside the encrypt stage as applicable). For **public** formats, `nonce` may be null / `nonce_len == 0`. For **encrypted** formats, `nonce` must be 16 bytes (tests use fixed nonces for determinism).

```c
/* out: verifiable body only (no Carbonado Header). hash_out: 32-byte Bao root.
 * Meta out-params optional (nullable). Skipped compress/encrypt stages report 0 (R3).
 * Lean pack: success = [status:4][pad:4][chunk:4][ecc:4][vsc:4]
 *   [bytes_compressed:4][bytes_encrypted:4][hash:32][body…]  (prefix 60);
 * error = [status:4] only. C parses status first so encode failures return real ABI codes. */
int carbonado_encode(
    const uint8_t *master, size_t master_len,   /* 32 or 64 */
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t format,
    const uint8_t *nonce, size_t nonce_len,     /* 16 if encrypted; else 0/null */
    uint8_t **out, size_t *out_len,
    uint8_t hash_out[32],
    uint32_t *padding_out,                      /* nullable */
    uint32_t *chunk_len_out,                    /* nullable */
    uint32_t *bytes_ecc_out,                    /* nullable */
    uint32_t *verifiable_slice_count_out,       /* nullable */
    uint32_t *bytes_compressed_out,             /* nullable (R3) */
    uint32_t *bytes_encrypted_out               /* nullable (R3) */
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
/* Full file: Header (177 B) || body. Bao root lives in the header.
 * slh_pk: NULL → zero-filled field; non-NULL must point to exactly 32 valid bytes.
 * metadata: NULL → zero-filled field; non-NULL must point to exactly 8 valid bytes.
 * Additive params (R2 SLH/meta + R3 stage counters): ABI version stays 1.
 * Lean pack: success = [status:4][pad:4][chunk:4][ecc:4][vsc:4]
 *   [bytes_compressed:4][bytes_encrypted:4][archive…]  (prefix 28);
 * error = [status:4] only.
 * C is length-implicit (non-null always copies fixed width). Wrong lengths are
 * Lean/export ByteArray-only (encodeHeaderedBytes → errInvalidArgument). */
int carbonado_encode_headered(
    const uint8_t *master, size_t master_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t format,
    const uint8_t *nonce, size_t nonce_len,     /* 16 when Encrypted bit set */
    const uint8_t *slh_pk,                      /* nullable 32 B */
    const uint8_t *metadata,                    /* nullable 8 B */
    uint8_t **out, size_t *out_len,
    uint32_t *padding_out,                      /* nullable (R3) */
    uint32_t *chunk_len_out,                    /* nullable */
    uint32_t *bytes_ecc_out,                    /* nullable */
    uint32_t *verifiable_slice_count_out,       /* nullable */
    uint32_t *bytes_compressed_out,             /* nullable */
    uint32_t *bytes_encrypted_out               /* nullable */
);

int carbonado_decode_headered(
    const uint8_t *master, size_t master_len,
    const uint8_t *archive, size_t archive_len,
    uint8_t **out, size_t *out_len
);
```

Lean pure + live C: `Carbonado.Ffi.encodeHeaderedBytes` / `decodeHeaderedBytes` via
`l_carbonado_encode_headered` / `l_carbonado_decode_headered`.
Lean takes `slhPublicKey` / `metadataBytes` as `ByteArray` (empty or exact length 32 / 8;
empty → zeros; other sizes → `errInvalidArgument`). Coverage: `CarbonadoTest.Pipeline`
`encode_headered_bytes_bad_*_len` theorems. Rust `lean::encode_headered` returns
`(archive, EncodeInfo)`; `file::encode` threads that info (R3). High-level `file::encode`
still passes `slh_public_key = None` (zeros); dual-suite SLH sets the field via `Header`
APIs / sidecars (G10-A).

**R2 residual (not a dedicated `InvalidArgument` variant):** if code 1 reaches Rust
`map_err`, callers see `InternalStateError("lean-backend invalid argument")` — same
P2 residual as other `CARBONADO_ERR_INVALID_ARGUMENT` sources (table above). Typed
headered encode never surfaces wrong SLH/meta lengths through C.

### Verification key

```c
/* Format-keyed Bao key: blake3::derive_key("carbonado-v2/verification", &[format]). */
int carbonado_verification_key(uint8_t format, uint8_t key_out[32]);
```

Lean pure: `Carbonado.Ffi.verificationKeyBytes`.

---

### Outboard / scrub / slice (Phase 2 — live)

```c
/* header_path != 0 → encrypted bare main [tag|ct] (file::encode_outboard);
 * header_path == 0 → embedded [nonce|tag|ct] (encoding::encode_outboard). */
/* Lean pack prefix 52: status+pad+chunk+comp+enc+hash; then len-prefixed main/ob/par (R3). */
int carbonado_encode_outboard(/* master, pt, format, nonce, header_path → main/outboard/parity + hash + pad/chunk + compress/encrypt */);
int carbonado_decode_outboard(/* master, hash, main, outboard, parity, padding, format, header_path, nonce → plaintext */);
int carbonado_scrub(/* body, hash, padding, format → recovered body or SCRUB_* error */);
int carbonado_scrub_outboard(/* main, outboard, parity, hash, padding, chunk_len, format → bare */);
int carbonado_verify_slice(/* body, hash, index, count, format → slice bytes */);
/* R9: seekable outboard slice (O(slice+height) hash; full main+outboard buffers). */
int carbonado_verify_slice_outboard(/* main, outboard, hash, index, count, format → slice */);
/* R9 / G10: SLH-DSA-SHA2-128s (libbitcoinpqc objects in libcarbonado_native.a). */
int carbonado_slh_keygen(/* entropy≥128 → pk[32], sk[64] */);
int carbonado_slh_sign(/* sk[64], message → malloc 7856 B sig */);
int carbonado_slh_verify(/* pk[32], message, sig[7856] → OK or AUTHENTICATION */);
```

See `include/carbonado.h` for full signatures. `extract_slice` is verify_slice with `count == 1` (Rust-side).

**`verify_slice` (inboard) — W4a closed (retained output):** Lean walks the full inboard bao response for authentication (O(N) time; inboard embeds full-range response) starting at offset 8 (no second full-response copy) but retains only the requested slice bytes (O(slice) output) via `decodeRecRetainRange` — same class as Rust `SliceRegionWriter` / `verify_slice_inboard_seekable`. Leaf hashing may use O(leaf) temps. C ABI still takes the **full inboard body buffer as input** (no streaming ReadAt). Do **not** claim O(slice) peak RSS when the caller already holds the full body `Vec`. **`count == 0` split:** Lean C / pure `verifySliceInboard` is **auth-first**; dual Rust API / `lean::verify_slice` short-circuits empty success before C (parity with pure-Rust seekable).

**`verify_slice_outboard` (R9 + W4b permanent full-buffer):** Lean walks only the requested leaf-group range (O(slice + height) hash work; W4b offset walk avoids recursive full half-extracts). C ABI still takes full main + full outboard buffers in memory — **permanent residual** (no additive `carbonado_verify_slice_outboard_at` / `ReadAt` callback ABI this wave). Under `backend-lean` the Rust dispatcher materializes `data_len` once when `data` is a generic `ReadAt`.

**`count == 0` (outboard slice):** empty success **immediately** — no root/geometry/OOB/auth checks (matches Rust `stream/slice.rs::verify_slice_outboard`). Authentication and OOB apply only when `count > 0`.

**SLH C error mapping (R9):** `carbonado_slh_keygen` / `_sign` library failure → `CARBONADO_ERR_INTERNAL`; `carbonado_slh_verify` reject → `CARBONADO_ERR_AUTHENTICATION`; bad args → `CARBONADO_ERR_INVALID_ARGUMENT`. Empty message (`NULL`, len 0) is accepted (non-NULL empty buffer passed to libbitcoinpqc).

## Phase 3 directory (composition — no new C symbols)

Directory dual-backend does **not** add `carbonado_encode_directory` / `decode_directory` C exports.
`file::encode_directory` / `decode_directory` under `backend-lean` compose existing ABI:

| Directory stage | Lean C ABI used |
|-----------------|-----------------|
| Bare segment mains | `carbonado_encode_outboard` / `carbonado_decode_outboard` (embedded-nonce) |
| Catalog inboard c14/c15 | `carbonado_encode_headered` / `carbonado_decode_headered` |
| rkyv FilepackManifest v2 + Adamantine envelope/payload + FS | **Dual-suite composition:** Rust rkyv+FS (SSOT). **Pure Lean Directory/CLI** also emit rkyv (**W3**); CFP2 dual-decode fallback only |

Dual-suite catalogs are **rkyv** (same as `backend-rust`; Rust composition SSOT for dual encode). Pure Lean Directory/CLI emit rkyv (**W3**); CFP2 is dual-decode fallback only (LIMITS).
Allowlist: `tests/lean_backend_phase3.rs` (`just test-lean-phase3`).

**Bao error mapping (R4):** Lean `ofPipelineError` no longer collapses all Bao failures to
`CARBONADO_ERR_BAO`. Current fidelity:

| Lean failure | ABI code | Rust mapping |
|--------------|----------|--------------|
| Bao auth (wrong key / root / leaf-parent mismatch) | 3 `AUTHENTICATION` | `AuthenticationFailed` |
| Short inboard prefix (`invalidPrefix`) | 5 `INVALID_HEADER` | `InvalidHeaderLength` |
| Truncation / trailing / residual geometry (no Rust pre-check) | 7 `BAO` | `BaoResponseTruncated` |
| OOB slice index | n/a (Rust pre-check in `lean::verify_slice`) | `InvalidSliceIndex { index, content_len }` |

Directory catalog body-tamper under both backends surfaces `AuthenticationFailed` for keyed Bao
auth failure (see `tests/directory_archive.rs`). Residual: pure-Rust outboard/inboard entry
points may still use `OutboardVerificationFailed` in other paths — do not re-collapse auth to
code 7.

## Phase 4: SLH / CLI / OTS (composition for dual-suite)

**G10 strategy A (dual-suite, still valid):** product SLH under `backend-lean` may use Rust
`crypto::slh_dsa_*` + `bitcoinpqc` composition. Dual-suite does **not** require pure Lean SLH.

**R9 / G10 full (pure Lean depth):** libbitcoinpqc SLH-DSA-SHA2-128s objects are linked into
`libcarbonado_native.a` (pinned `b309f444…`). Live symbols:

| Symbol | Role |
|--------|------|
| `carbonado_slh_keygen` | entropy ≥128 → pk 32 + sk 64 |
| `carbonado_slh_sign` | sk 64 + message → malloc 7856 B signature |
| `carbonado_slh_verify` | pk + message + sig → OK / AUTHENTICATION |
| Lean `@[extern]` | `carbonado_slh_{keygen,sign,verify}_raw` → `Carbonado/Slh.lean` `signRoot` / `verifyRoot` |

Dual-suite may keep Rust bitcoinpqc composition as product SSOT; pure Lean is for
`libcarbonado` purity. Fail-closed on bad signatures.

Allowlist: `tests/lean_backend_phase4.rs` + `tests/slh_outboard.rs` (`just test-lean-phase4`).

## R9 additive C surface (ABI version stays 1)

| Symbol | Rust analogue | Status |
|--------|---------------|--------|
| `carbonado_verify_slice_outboard` | `verify_slice_outboard` | **live** (R9) |
| `carbonado_slh_keygen` / `_sign` / `_verify` | `crypto::slh_dsa_*` | **live** (R9 / G10) |
| Optional pure-buffer directory helpers | composition | optional (not required) |

---

## Implementation status (Phase 2–4 close)

| Symbol | Lean pure | C in `libcarbonado` | `carbonado-sys` | Rust `backend-lean` dispatch |
|--------|-----------|---------------------|-----------------|------------------------------|
| `carbonado_abi_version` | `abiVersion` (C-owned) | **live** | bound | `lean::abi_version` |
| `carbonado_free` | — | **live** | bound | C callers: `carbonado_free`. Rust `backend-lean`: copy via `take_buf` then `carbonado_free` (not `Vec::from_raw_parts`) |
| `carbonado_encode` | `l_carbonado_encode` | **live** (+ meta; R3 compress/encrypt) | bound | `encoding::encode` → `lean::encode` |
| `carbonado_decode` | `l_carbonado_decode` | **live** | bound | `decoding::decode` → `lean::decode` |
| `carbonado_encode_headered` | `l_carbonado_encode_headered` | **live** (+ SLH/meta R2; EncodeMeta R3) | bound | `file::encode` → `lean::encode_headered` |
| `carbonado_decode_headered` | `l_carbonado_decode_headered` | **live** | bound | `file::decode` → `lean::decode_headered` |
| `carbonado_verification_key` | `l_carbonado_verification_key` | **live** | bound | `crypto::carbonado_verification_key` |
| `carbonado_encode_outboard` | `l_carbonado_encode_outboard` | **live** (+ R3 compress/encrypt) | bound | `encoding::encode_outboard` |
| `carbonado_decode_outboard` | `l_carbonado_decode_outboard` | **live** | bound | `decoding::decode_outboard` |
| `carbonado_scrub` | `l_carbonado_scrub` | **live** | bound | `decoding::scrub` |
| `carbonado_scrub_outboard` | `l_carbonado_scrub_outboard` | **live** | bound | `decoding::scrub_outboard` |
| `carbonado_verify_slice` | `l_carbonado_verify_slice` | **live** | bound | `decoding::verify_slice` |
| `carbonado_verify_slice_outboard` | `l_carbonado_verify_slice_outboard` | **live** (R9) | bound | `stream::verify_slice_outboard` → `lean::verify_slice_outboard` |
| `carbonado_slh_keygen` | `@[extern]` raw | **live** (R9) | bound | optional; dual-suite may use Rust `bitcoinpqc` |
| `carbonado_slh_sign` | `@[extern]` raw | **live** (R9) | bound | optional; dual-suite may use Rust `bitcoinpqc` |
| `carbonado_slh_verify` | `@[extern]` raw | **live** (R9) | bound | optional; dual-suite may use Rust `bitcoinpqc` |

**Phase 2 allowlist:** `tests/lean_backend_smoke.rs` + `tests/lean_backend_phase2.rs` (`just test-lean-phase2`).

**Phase 3 allowlist:** + `tests/lean_backend_phase3.rs` + `tests/format_policy.rs` (`just test-lean-phase3`).
Directory composition (rkyv catalog, no new C symbols).

**Phase 4 allowlist:** + `tests/lean_backend_phase4.rs` + `tests/slh_outboard.rs` (`just test-lean-phase4`; features include `cli` for subprocess smoke).
SLH/CLI/OTS composition (no new C symbols).

**Phase 5 freeze (G11) + R7 G8 full close:** `just test-lean-ci` — full dual suite under lean features (unfiltered `cargo test --no-default-features --features "backend-lean,pqc,ots,cli"`). See [GAPS.md](./GAPS.md) R7 / [TEST_CONTRACT.md](./TEST_CONTRACT.md) Phase 5. Full-suite G8 **closed** at R7; post-G8 residuals are purity/feature-policy only.

---

## Linking

```text
# After: nix build .#libcarbonado -o result-libcarbonado
export CARBONADO_LEAN_LIB=$PWD/result-libcarbonado/lib
export CARBONADO_LEAN_INCLUDE=$PWD/result-libcarbonado/include
export LD_LIBRARY_PATH=$CARBONADO_LEAN_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
# Phase 5 freeze (CI + humans):
just test-lean-ci
# Phase-scoped:
# just test-lean-phase4
# link: -L $CARBONADO_LEAN_LIB -lcarbonado (+ rpath); NEEDED libleanshared from nix store
```

Exact `cargo` `rustc-link-*` flags live in [`carbonado-sys/build.rs`](../carbonado-sys/build.rs). With feature `require-lib` (enabled by carbonado `backend-lean`), a missing `CARBONADO_LEAN_LIB` or missing library file is a **hard build error**. Without `require-lib`, unset env only warns (docs/check). CI / `just test-lean-ci` **fail-closed** if `libcarbonado.so` (or `.dylib`) is missing under `CARBONADO_LEAN_LIB`.

**Packaging:** `nix build .#libcarbonado -o result-libcarbonado` produces `lib/libcarbonado.so` (leanc + whole-archive Lean AOT + zstd/ABI glue + NEEDED absolute nix-store `libleanshared`) and `lib/libcarbonado.a`. Prefer the shared object from `carbonado-sys` (rpath set from `CARBONADO_LEAN_LIB`). Redistribution is nix-store-coupled until a bundled runtime story lands.

**`EncodeInfo` on lean (R3):** full stage counters from Lean pack — `padding_len`, `chunk_len`, `bytes_ecc`, `verifiable_slice_count`, `bytes_compressed`, `bytes_encrypted`, body lengths. Skipped compress/encrypt stages report **0** (matches Rust stream path). `compression_factor` / `amplification_factor` computed in Rust from those fields.

---

## Mutual exclusion of Cargo features

Enable **exactly one** of `backend-rust` or `backend-lean` per build (`src/backend/mod.rs` `compile_error!`). Dual-backend CI runs two invocations, not one binary with both engines.
