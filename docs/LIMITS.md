# carbonado — limits (honest)

## Current product surface

### Dual-backend (normative product model)

| Backend | Status |
|---------|--------|
| **Rust** (`src/`, default `backend-rust`) | First-class production library + CLI; full `cargo test` |
| **Lean AOT** (`Carbonado/`, `libcarbonado`, optional `backend-lean`) | Second engine: proofs + wire/C ABI; dual-suite phased (G8) |
| **Rust `tests/`** | Normative behavioral contract for **both** engines |

- AOT CLI (`packages.carbonado` / `nix run`) runs **Programs A–G**: constants, EtM, FEC, keyed Bao, full pipeline (c0–c15), Header wire, scrub, stream bounds, multi-segment shards, **zstd-20 compression (linked)**, **SLH1 sidecar wire + bind-to-root model**, **Adamantine 1.0 directories**, **encode/decode/slh CLI**.
- Rust tree (`src/`, `tests/`, …) **stays** first-class (AGENTS dual-backend). Optional historical pin under `ref/carbonado-rust` is G1 residual — not a license to delete `src/` or `tests/`.
- Lean theorem/test tree is **`CarbonadoTest/`** (not `Tests/`) so it does not collide with Rust `tests/` on case-insensitive filesystems (Darwin APFS).
- Dependency direction is **CarbonadoTest → Carbonado** only.

## Program B crypto (shipped)

- Full Lean: SHA-512, HMAC-SHA512, AES-256-CTR (Ctr128BE), subkeys, payload EtM (both layouts), header MAC.
- MAC-before-decrypt is a **control-flow theorem** on `decryptAfterMacCheck` (tag verify before keystream). Not a constant-time proof.
- Parity is bit-match goldens vs RustCrypto/`src/crypto.rs` semantics (embedded + etm-vectors driver), not a live Nix `diff` harness against a Rust binary yet.
- **Low-level AESCTR** (`expandKey256` / `ctrXor`) is unchecked: short key/nonce panic via `get!`. EtM validates first.
- Lean exposes `invalidNonceLength` because nonces are `ByteArray`; Rust’s typed `[u8; 16]` cannot be wrong-sized at the same API.

## Program C FEC (shipped)

- Full Lean GF(2^8) (poly 0x1d log/exp tables), systematic RS matrix (Vandermonde × inv(top)), encode + reconstruct matching `reed-solomon-erasure` 5.0.3.
- Carbonado geometry: `calcPaddingLen` / `stripeUnit=16384` / inboard 8×`chunk_len` concat; `encodeInboard` / `decodeInboard` / `reconstructAfterKnockout`.
- **Stripe memory:** encode and decode **materialize O(stripe)** — for one segment-wide stripe that is `O(padded_len × 2)` shard buffers (8 × chunk_len). Same residual class as Rust `FecInboardEncoder` / `FecInboardWriteAt`. Documented and theorem-bounded in `Carbonado.Stream` (`maxFecStripeRetain`).
- Outboard parity-sidecar encode API not yet a separate product surface (inboard concat covers encode; split parity is trivial slice of shards 4..7).
- Parity is bit-match goldens vs pin crate / `rs-vectors` driver, not a live Nix `diff` harness yet.

## Program D keyed Bao (shipped)

- Full Lean BLAKE3 reference (hash / keyed_hash / derive_key + hazmat subtree/parent CVs) ported from the BLAKE3 reference algorithm; parity vs `ref/blake3` 1.8.5 portable semantics and bao-vectors.
- Keyed Bao product paths: format verification key, root, inboard `[u64le|response]`, post-order outboard, **stream slice decode** (`decodeSliceResponse` / `decodeSliceForFormat`) against `(key, root, contentLen)` via `decodeRec` — returns authenticated bytes from the response, **not** a re-encode oracle over trusted plaintext.
- Inboard slice extract (`verifySliceInboard*`) always runs full `decodeInboard` **before** any `count = 0` empty return (auth-first). Stream decode rejects `count = 0` with `invalidSliceCount`.
- Error taxonomy: short stream → `truncatedResponse`; overlong stream → `trailingData` (distinct).
- Tree model uses **leaf-group** recursion (4096 B) matching bao-tree `BlockSize::from_chunk_log(2)` IO.
- **Not claimed:** SIMD BLAKE3 throughput; O(slice) memory for **inboard** slice extract (full inboard materialize then extract — same class as some Rust inboard paths); standalone slice responses are O(response) for stream decode; async/tokio bao-tree APIs; pre-order outboard layout.
- **Constant-time:** logical `ctEq` only on hash compares; not a CT proof.
- Parity is bit-match goldens vs `ref/bao-tree` @ lock + `bao-vectors` driver, not a live Nix `diff` harness yet.

## Program E pipeline / scrub / shard (shipped)

- **Pipeline order:** compress → encrypt → FEC → keyed Bao (reverse on decode). Modules: `Carbonado.Pipeline`, `Header`, `Stream`, `Scrub`, `Shard`.
- **Header:** 177 B wire codec; `header_mac` verified before body (`decodeHeadered`). Authenticated `encoded_len` bounds the body (`truncatedBody` if short; trailers after `encoded_len` ignored). Public metadata only.
- **Nonce layouts:** header-path `[tag|ct]` vs low-level `[nonce|tag|ct]` as in EtM; pure model takes caller-supplied nonce (no CSPRNG).
- **MAC-before-decrypt:** EtM still refuses keystream until MAC ok; pipeline only decrypts after Bao/FEC reverse.
- **Scrub:** pure RS combinatorial search on FEC body + re-encode + Bao root compare. Does **not** implement Rust seekable slice extract entry; tests use `scrubWithMissing` / `scrubFecThenBao` after FEC body is known. Opaque Bao-only damage without FEC extract → `invalidScrubbedHash`.
- **Stream model:** pure stripe transducer + proved O(stripe) retain bounds; product `encodeBody` still uses segment-wide RS geometry (same as Rust residual). Multi-stripe encode model is documented alternative, not default parity path.
- **Sharding:** pure multi-segment headered encode/decode with contiguous `chunk_index` validation.
- **Outboard product pipeline** (`.out`/`.par` high-level file APIs) not fully composed as a separate encode/decode surface in Lean yet (Bao outboard primitives exist from D).
- Parity: format-matrix roundtrips in Lean AOT; live Nix vs `ref/carbonado-rust` product-matrix still open (G8).

## Program F zstd + SLH (shipped with declared residuals)

### Zstd (linked)

- **AOT product:** `nix/native` builds a **static** `libcarbonado_native.a` = FFI glue + single-threaded libzstd objects from pinned commit **`f8745da6…` / v1.5.7** (same as `ref/zstd`; flake `zstdPinned` fetchFromGitHub; no shared `-lzstd`). Level **20** (`Carbonado.Compress.zstdLevel`).
- **Pipeline:** Compression bit → `compressLevel20` / `decompress` in `compressStep` / `decompressStep`; errors map 1:1 via `ofZstdError` → `compressionFailed` | `decompressionFailed` | `decompressOutputTooLarge` | `zstdInvalidInput` (no lumped catch-all).
- **DoS cap:** decompressed output ≤ 256 MiB (`maxDecompressedLen`, matches Rust `MAX_SEGMENT_MAIN_LEN`).
- **Interpreter / `native_decide`:** `@[extern]` bodies are identity fallbacks; **do not** `native_decide` compression formats (extern needs native symbols). Pure tests: status decode + bit-clear paths + non-compression format matrix. **Real** zstd + c2/c6/c14/c15 gated by AOT `demo` (`ZSTD_compress` API goldens empty/hello).
- **Not claimed:** streaming zstd (buffer API only); multi-threaded zstd; dictionary compression.

### SLH-DSA sidecars (wire + binding; no real PQC FFI yet)

- **Wire:** `Carbonado.Slh` — `SLH1` + 7856 B sig = 7860 B; parse/build fail-closed (`invalidSidecarLength` vs `badSlhMagic` vs `invalidSignatureLength` distinct).
- **Binding:** `verifyBound` / `verifyBoundToExpected` — signature is over the 32-byte Bao root; wrong root → `verificationFailed`; pk size / root size / sig size have distinct errors.
- **Sign:** `signRoot` returns `signatureUnavailable` (fail-closed) until libbitcoinpqc is linked.
- **Why no real SLH yet:** `ref/bitcoinpqc` pin is present but nested `libbitcoinpqc` submodule is empty; full cmake+secp+SLH link is deferred. Product integrates **wire + theorems + Header.slh_public_key slot**; real sign/verify oracle is the next deepen step.
- **Mock oracles** in tests only; never used as production crypto.

## External C (declared)

| Component | Status |
|-----------|--------|
| zstd | **Linked** static via `nix/native` + flake `zstdPinned` (commit `f8745da6…` / same as `ref/zstd` v1.5.7); no shared libzstd |
| SLH-DSA-SHA2-128s | Wire + binding in Lean; **FFI not linked** (libbitcoinpqc residual) |

## Program G Adamantine + CLI (shipped with declared residuals)

### Adamantine envelope (wire-compatible)

- Magic `ADAMANTINE10\n` (13 B), header 19 B, `carbonado_fmt` c14/c15, flags bit0 `REQUIRE_OTS` only.
- Payload framing matches Rust: `[u32 LE man_len][man][u32 LE bun_len][bun]`.
- Dev `ADAMANTINE1\n` / `ADAMANTINE2\n` rejected with `unsupportedVersion`.

### Filepack manifest — **CFP2 Lean-native, not rkyv**

- Logical fields match FilepackManifest v2 (version, format_level, entries, SegmentRef, content_blake3, optional OTS).
- Wire body magic `CFP2` + deterministic LE layout (`Carbonado.Filepack`).
- **Not** byte-identical to Rust rkyv `FilepackManifestWire`. Adamantine *envelope* framing is shared; manifest body interop with Rust-produced catalogs needs a converter (future). Product CLI is CFP2 end-to-end.

### Directory model

- Catalog: inboard headered `{root}.adam.c14`/`.adam.c15`; segments: bare mains `{root}.c12`–`.c15`; centralized Bao+FEC bundle in Adamantine payload.
- Path rules fail-closed: empty, `..`, absolute `/`, `\`, empty components, NUL, length cap.
- Content BLAKE3 checked after segment recovery.
- Segment policy Auto/ForceRaw/ForceCompressed/ForceC12–C15; legacy c4–c7 rejected.
- OTS: `REQUIRE_OTS` flag → fail-closed `otsFeatureRequired` (no OTS stamps in Lean path).
- Master policy: zero master only for public; non-zero only for encrypted.

### CLI

- `demo` / no-args: full A–G self-test (flake `checks.demo`).
- `encode`/`decode` single-file (headered) and directory; single-file default name `{bao_root_hex}.c{fmt:02x}` (AGENTS hex).
- `slh parse`: wire only (exit 0 on valid frame). `slh verify`: **exit 1** until real SLH-DSA FFI (never soft-success).
- Nonces: `/dev/urandom` for encrypted encode.
- Directory default outdir `{input}-archive/`.
- Encode rejects `requireOts` (`otsFeatureRequired`); does not mint undecodeable archives.
- CLI encode rejects symlink source entries (`symlinkNotAllowed`); decode refuses write-through symlinks when detectible.

## Dual-backend (G8 — P0 closed, engineering open)

| Backend | Status |
|---------|--------|
| `backend-rust` (default) | Full Rust engine; full `cargo test` (must never regress) |
| `backend-lean` | **Scaffolding** — header, `carbonado-sys`, feature flags, weak C stubs (`NOT_IMPLEMENTED`); pure Lean FFI helpers exist; **not** full suite |
| Cross encode/decode Rust↔Lean | Not yet (G9; after Phase 2) |
| Docs / inventory (Phase 0) | **Closed** — [TEST_CONTRACT.md](./TEST_CONTRACT.md), [ABI.md](./ABI.md), [GAPS.md](./GAPS.md) |

Rust-only for now: `async`, `async-tokio`, and (by default) multi-thread `parallel` paths. Lean uses serial RS.

## Not claimed yet

- **Constant-time** crypto proofs (logical `ctEq` only)
- Secret zeroization proofs / automatic zeroize of master keys
- WASM product target
- Throughput parity with AES-NI / SIMD RS / SIMD BLAKE3 Rust paths (optimize after correctness)
- Real SLH-DSA sign/verify via libbitcoinpqc (G10)
- Byte-identical rkyv FilepackManifest interop with Rust directories (required for directory dual-suite — Phase 3 / G7)
- Live C ABI encode/decode (stubs return `NOT_IMPLEMENTED` until Phase 1)
- Full `cargo test --features backend-lean` (G8 open; Phase 1 allowlist first)
- Live CI matrix both backends (G11)
- Live Nix product-matrix vs optional frozen `ref/carbonado-rust`
