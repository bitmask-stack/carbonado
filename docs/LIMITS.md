# carbonado — limits (honest)

## Current product surface

### Product model

| Layer | Status |
|---------|--------|
| **Rust** (`src/`, default `backend-rust`) | Production library + CLI; full `cargo test` |
| **Lean** (`Carbonado/`, AOT demo) | Spec + proofs; tiny C `@[extern]` for zstd/SLH in the demo only |
| **Rust `tests/`** | Normative behavioral contract for the Rust engine |

There is no `carbonado-sys`, no Cargo `backend-lean`, and no product C ABI. Do not claim G8 C-ABI parity.

- AOT CLI (`packages.carbonado` / `nix run`) runs **Programs A–G**: constants, EtM, FEC, keyed Bao, full pipeline (c0–c15), Header wire, scrub, stream bounds, multi-segment shards, **zstd compression (level is encoder input; AOT demo uses 20)**, **SLH1 sidecar wire + bind-to-root model**, **Adamantine 1.0 directories**, **encode/decode/slh CLI**.
- Rust tree (`src/`, `tests/`, …) **stays** first-class. **G1/W5a closed:** permanent policy — **no** `ref/carbonado-rust` product pin. Not a license to delete `src/` or `tests/`.
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
- **W4a inboard slice** (`verifySliceInboard*`): full-response walk over the inboard artifact from offset 8 (`decodeRecRetainRange` — no second full-response copy); **O(slice) retained output**; O(leaf) temporary leaf extracts for hashing; O(N) time (same class as Rust `verify_slice_inboard_seekable`).
- **`count = 0` split (honest):** pure Lean / C `carbonado_verify_slice` is **auth-first** (corrupt fails, then empty). Dual product API under `backend-lean` (`lean::verify_slice` / `carbonado::verify_slice`) **short-circuits** `Ok([])` without auth — parity with pure-Rust `verify_slice_inboard_seekable`. Stream decode rejects `count = 0` with `invalidSliceCount`.
- **W4b outboard slice:** O(slice + height) hash via offset walk; full main+outboard **input** buffers at C ABI remain **permanent** (no ReadAt callback symbol).
- Error taxonomy: short stream → `truncatedResponse`; overlong stream → `trailingData` (distinct).
- Tree model uses **leaf-group** recursion (4096 B) matching bao-tree `BlockSize::from_chunk_log(2)` IO.
- **Not claimed:** SIMD BLAKE3 throughput; O(slice) **peak RSS** when C/caller already holds full body/main buffers (caller body is still O(body)); standalone slice responses are O(response) for stream decode; async/tokio bao-tree APIs; pre-order outboard layout; streaming ReadAt C ABI for outboard slice.
- **Constant-time:** logical `ctEq` only on hash compares; not a CT proof.
- Parity is bit-match goldens vs `ref/bao-tree` @ lock + `bao-vectors` driver, not a live Nix `diff` harness yet.

## Program E pipeline / scrub / shard (shipped)

- **Pipeline order:** compress → encrypt → FEC → keyed Bao (reverse on decode). Modules: `Carbonado.Pipeline`, `Header`, `Stream`, `Scrub`, `Shard`.
- **Header:** 177 B wire codec; `header_mac` verified before body (`decodeHeadered`). Authenticated `encoded_len` bounds the body (`truncatedBody` if short; trailers after `encoded_len` ignored). Public metadata only.
- **Nonce layouts:** header-path `[tag|ct]` vs low-level `[nonce|tag|ct]` as in EtM; pure model takes caller-supplied nonce (no CSPRNG).
- **MAC-before-decrypt:** EtM still refuses keystream until MAC ok; pipeline only decrypts after Bao/FEC reverse.
- **Scrub:** product `scrubInboard` peels Bao via geometry-only leaf walk then RS combinatorial search + re-encode Bao root oracle; `scrubOutboard` recovers bare main from main+parity. Pristine → `unnecessaryScrub`; no Verification → `scrubRequiresVerification`. Opaque Bao-only (no FEC) damage → `invalidScrubbedHash`. Memory residual: full peel materializes logical FEC body (not O(slice) scrub entry like Rust S5 seekable extract).
- **Stream model:** pure stripe transducer + proved O(stripe) retain bounds; product `encodeBody` still uses segment-wide RS geometry (same as Rust residual). Multi-stripe encode model is documented alternative, not default parity path.
- **Sharding:** pure multi-segment headered encode/decode with contiguous `chunk_index` validation.
- **Outboard product pipeline:** Lean `Outboard.encodeOutboardBody` / `decodeOutboardBody` live via C ABI (Phase 2). Directory high-level dual-suite APIs closed at P3 via composition (Rust rkyv + Lean outboard/headered); pure Lean CLI/directory emit **rkyv** catalog bodies (**W3**).
- Parity: format-matrix roundtrips in Lean AOT; dual-suite product-matrix is live `src/` + `tests/` (G8) — **no** frozen `ref/carbonado-rust` pin (**G1/W5a** permanent policy); G9 closed at R8 for no-compress body/headered/outboard both directions (`tests/fixtures/g9/`).

## Program F zstd + SLH (shipped with declared residuals)

### Zstd (linked)

- **AOT product:** `nix/native` builds a **static** `libcarbonado_native.a` = FFI glue + single-threaded libzstd objects from pinned commit **`f8745da6…` / v1.5.7** (same as `ref/zstd`; flake `zstdPinned` fetchFromGitHub; no shared `-lzstd`). Level **20** (`Carbonado.Compress.zstdLevel`).
- **Pipeline:** Compression bit → `compressLevel20` / `decompress` in `compressStep` / `decompressStep`; errors map 1:1 via `ofZstdError` → `compressionFailed` | `decompressionFailed` | `decompressOutputTooLarge` | `zstdInvalidInput` (no lumped catch-all).
- **DoS cap:** decompressed output ≤ 256 MiB (`maxDecompressedLen`, matches Rust `MAX_SEGMENT_MAIN_LEN`).
- **Interpreter / `native_decide`:** `@[extern]` bodies are identity fallbacks; **do not** `native_decide` compression formats (extern needs native symbols). Pure tests: status decode + bit-clear paths + non-compression format matrix. **Real** zstd + c2/c6/c14/c15 gated by AOT `demo` (`ZSTD_compress` API goldens empty/hello).
- **W4c permanent residual — streaming zstd:** product AOT and lean dual path use **buffer** zstd only (`ZSTD_compress` / `zstd::bulk` under lean; Rust streaming `copy_encode` under `backend-rust` only). Streaming frames are **not** dual-safe / bit-match Lean (W2a). Do **not** claim E2 for public Compression outboard under lean. Multi-threaded zstd and dictionary compression not claimed.

### SLH-DSA sidecars (wire + binding + live FFI at R9 / G10)

- **Wire:** `Carbonado.Slh` — `SLH1` + 7856 B sig = 7860 B; parse/build fail-closed (`invalidSidecarLength` vs `badSlhMagic` vs `invalidSignatureLength` distinct).
- **Binding:** `verifyBound` / `verifyBoundToExpected` — signature is over the 32-byte Bao root; wrong root → `verificationFailed`; pk size / root size / sig size have distinct errors.
- **Sign/verify (R9 / G10 closed):** live SLH-DSA-SHA2-128s via `@[extern]` into libbitcoinpqc objects linked in `libcarbonado_native.a` (flake pin `b309f444…`; `nix/native/carbonado_slh.c`). Product APIs: `signRoot` / `keygen` / `verifyRoot` / `liveVerifyOracle`; C ABI `carbonado_slh_{keygen,sign,verify}`.
- **Elaborator residual:** `@[extern]` bodies are fail-closed (status fail / verify reject) for `native_decide`; real crypto only in AOT / linked `libcarbonado`. Do **not** `native_decide` live sign/verify.
- **Dual-suite:** product SLH under `backend-lean` may still use Rust `bitcoinpqc` composition (G10 strategy A); pure Lean is optional purity for `libcarbonado` — dual-suite does **not** require pure Lean SLH.
- **Mock oracles** in pure theorems only; never used as production crypto.

## External C (declared)

| Component | Status |
|-----------|--------|
| zstd | **Linked** static via `nix/native` + flake `zstdPinned` (commit `f8745da6…` / same as `ref/zstd` v1.5.7); no shared libzstd |
| SLH-DSA-SHA2-128s | **Linked R9** — SLH-only objects from flake pin `b309f444…` + `carbonado_slh_*` C ABI; dual-suite may keep Rust composition |

## Program G Adamantine + CLI (shipped with declared residuals)

### Adamantine envelope (wire-compatible)

- Magic `ADAMANTINE10\n` (13 B), header 19 B, `carbonado_fmt` c14/c15, flags bit0 `REQUIRE_OTS` only.
- Payload framing matches Rust: `[u32 LE man_len][man][u32 LE bun_len][bun]`.
- Dev `ADAMANTINE1\n` / `ADAMANTINE2\n` rejected with `unsupportedVersion`.

### Filepack manifest — dual path

| Path | Manifest body | Status |
|------|---------------|--------|
| **Dual-suite** (`backend-lean` via Rust API / `tests/`) | **rkyv** `FilepackManifestWire` v2 (normative Adamantine 1.0) | **P3 closed** — composition: Rust rkyv + Lean segment/catalog crypto (SSOT for dual encode) |
| **Pure Lean CLI / Program G** | **rkyv** via `Carbonado.RkyvFilepack.encodeCatalogBody` (**W3**) | Wire-compatible with dual-suite decode; goldens in `tests/fixtures/rkyv/` |

- Logical fields match (version, format_level, entries, SegmentRef, content_blake3, optional OTS).
- Adamantine *envelope* framing is shared (`ADAMANTINE10\n`, payload `[man_len][man][bun_len][bun]`).
- Pure Lean **rkyv encode+decode closed at W3** (`encodeRkyvManifest` / `decodeRkyvManifest` + goldens empty/single/multi+OTS). Dual-suite catalog **encode** remains Rust rkyv composition SSOT (do **not** claim dual-suite requires pure Lean). CFP2 remains dual-decode fallback only (`decodeCatalogBody`).

### Directory model

- Catalog: inboard headered `{root}.adam.c14`/`.adam.c15`; segments: bare mains `{root}.c12`–`.c15`; centralized Bao+FEC bundle in Adamantine payload.
- Path rules fail-closed: empty, `..`, absolute `/`, `\`, empty components, NUL, length cap (**UTF-8 bytes**, matching Rust `MAX_REL_PATH_LEN`).
- **Pure Lean stricter than Rust path validate:** Lean also rejects empty components (`a//b`) and embedded NUL. Rust `validate_rel_path` does not; handcrafted rkyv with `//` can pass dual-suite Rust validate and fail Lean `decodeRkyvManifest`→`validate`. Normal FS `encode_directory` walks do not emit those paths.
- Content BLAKE3 checked after segment recovery.
- Segment policy Auto/ForceRaw/ForceCompressed/ForceC12–C15; legacy c4–c7 rejected.
- OTS: `REQUIRE_OTS` flag → fail-closed `otsFeatureRequired` (no OTS stamps in Lean path).
- Master policy: zero master only for public; non-zero only for encrypted.

### CLI

- `demo` / no-args: full A–G self-test (flake `checks.demo`).
- `encode`/`decode` single-file (headered) and directory; single-file default name `{bao_root_hex}.c{fmt:02x}` (AGENTS hex).
- `slh parse`: wire only (exit 0 on valid frame). `slh verify`: live SLH-DSA via `liveVerifyOracle` (exit 0 on accept; exit 1 on reject / bad wire — never soft-success).
- Nonces: `/dev/urandom` for encrypted encode.
- Directory default outdir `{input}-archive/`.
- Encode rejects `requireOts` (`otsFeatureRequired`); does not mint undecodeable archives.
- CLI encode rejects symlink source entries (`symlinkNotAllowed`); decode refuses write-through symlinks when detectible.

## Engines (2026-08-24)

| Layer | Status |
|---------|--------|
| `backend-rust` (default) | Full Rust engine; full `cargo test` (must never regress); CI job **`desktop`** |
| Lean proofs + AOT demo | `just test-lean-ci` / CI job **`lean-proofs`**: nix no-sorry + demo. No Cargo `backend-lean`. |
| Lean AOT goldens | Rust still decodes `tests/fixtures/g9/lean/` (`just test-g9`). Live rust→lean encode via C is gone. |

G8 C-ABI dual-backend (`carbonado-sys` / `libcarbonado` / Cargo `backend-lean`) was **removed**. Historical R7 freeze language below is archaeology, not a live gate.

**Lean proof command:** `just test-lean-ci` builds nix `no-sorry`, `tooling-purity`, `carbonado`, and `demo`.

**Permanent feature-gated exclusions from dual freeze** (lean features stay `"backend-lean,pqc,ots,cli"` — **never** add `async` / `async-tokio` / `parallel` to freeze):

| Item | Why |
|------|-----|
| `tests/streaming_async.rs` | `#![cfg(feature = "async")]` — dual freeze does not enable `async` → **0 tests** under freeze (**R10 permanent policy**). Optional product path: under `backend-lean`+`async`, `stream_decode_async` is dual-engine via R5 E1 `stream_decode` (disk O(encoded) staging; lean peak RAM **O(encoded + logical)** body+plaintext; not E2). Default desktop CI often enables `async` on **rust** only. |
| `tests/parallel_determinism.rs` | `#![cfg(feature = "parallel")]` — dual freeze does not enable `parallel`; Lean RS path is serial |

**R10 closed:** freeze never requires async; optional lean+async dual-aware. Multi-thread `parallel` product paths remain rust-engine / feature-gated; Lean uses serial RS.

## Not claimed yet

- **Constant-time** crypto proofs (logical `ctEq` only)
- Secret zeroization proofs / automatic zeroize of master keys
- WASM product target
- Throughput parity with AES-NI / SIMD RS / SIMD BLAKE3 Rust paths (optimize after correctness)
- ~~Pure Lean SLH-DSA sign/verify via libbitcoinpqc~~ **closed R9 / G10** (`carbonado_slh_*` + Lean `@[extern]`; dual-suite may still use Rust `bitcoinpqc` composition)
- ~~Pure Lean rkyv encode + directory CLI CFP2~~ **W3 closed** — pure Lean rkyv encode/decode + directory/CLI emit rkyv; dual-suite catalog encode remains Rust rkyv composition SSOT (not required pure Lean)
- **W3c SLH:** dual-suite keeps Rust `bitcoinpqc` composition for SLH; pure Lean `carbonado_slh_*` available for AOT/CLI only (honest composition SSOT)
- ~~Seekable outboard slice C~~ **closed R9** (`carbonado_verify_slice_outboard`); **W4b permanent:** full main+outboard buffers at C (no streaming ReadAt / callback ABI)
- ~~Inboard `verify_slice` O(body) retain~~ **W4a closed** — O(slice) retained output; O(N) time; C full body **input** remains
- ~~Stream dual under lean is E1-only~~ **W1b closed (MVP):** see **Stream E1/E2 API matrix** below. Pure Lean chunked stream C ABI residual remains (no streaming C symbols).
- ~~`file::decode_stream` pure-Rust residual~~ **W1a closed** — under lean, spools header+`encoded_len` body → Lean `decode_headered` (peak O(archive+plaintext); not E2)
- ~~Full **codecode** / **decodec** matrix~~ **W2d closed** — `tests/determinism_roundtrip.rs` (no-compress + same-engine compress/directory)
- **W2a permanent residual — Compression cross-engine encode:** Lean AOT zstd frames are **not** bit-identical to Rust `zstd` even at level 20 / same pin rev. Measured evidence (G9 `outboard_c14`): mains both 35 B; frame descriptor byte differs (`28b5 2ffd **00**…` rust vs `28b5 2ffd **20**…` lean); Bao roots and FEC parity diverge. **Specified and proved (header bits only):** level 20, magic `28b52ffd`, checksum off, no dictionary, reserved/unused 0; AOT/`ZSTD_compress` small frames use Single_Segment + 1-byte FCS (`0x20`); rust `copy_encode` unknown-size uses windowLog 25 (`0x00` `0x78`). Lean `Carbonado.Compress`; Rust `tests/zstd_frame_params.rs` parses frames. **Not proved:** compressed-block identity for arbitrary payloads (G9 26-byte c14 happens to share the raw last-block after the 6-byte header). **Policy:** decode interop only across engines; re-encode not bit-identical; same-engine codecode/decodec still requires `A' == A` (green). Do not claim rust↔lean compress wire identity.
- **W2b permanent residual — Directory cross-engine encode:** compare **live rust vs live lean** catalog roots under identical pins (phase3 seed tree, zero master, default options). Pinned in `tests/determinism_roundtrip.rs`: live rust `16e2369f…`, live lean `d468ea7a…` (hard `assert_ne!`). The rust pin equals the `phase3_g9_directory` catalog: encode sorts by `rel_path` before appending verification outboard / FEC (not `read_dir` order). Same-engine directory codecode/decodec green. The remaining residual is catalog packaging across engines (zstd), not filesystem listing order.
- **W4c permanent residual — streaming zstd under lean:** buffer-only bulk zstd for Lean frame parity; public Compression outboard under lean stays O(logical) — not E2 (see matrix).
- **W4d permanent residual — FEC / async spool:** FEC verify O(FEC body) shards (segment-wide RS); async always disk-stages O(encoded); lean+async peak RAM O(encoded+logical). See [STREAMING_PARALLELISM.md](../doc/STREAMING_PARALLELISM.md).
- ~~Live Nix product-matrix vs optional frozen `ref/carbonado-rust`~~ **W5a / G1 closed** — permanent no product pin; live `src/` + `tests/` SSOT; third-party `ref/` pins only

### Slice memory honesty (W4a / W4b)

| Path | Retained hash/output work | Input buffers at C / dual lean | Claim |
|------|---------------------------|--------------------------------|-------|
| Inboard `carbonado_verify_slice` / Lean `verifySliceInboard` | **O(slice)** retained (W4a); walk from offset 8 (no second response copy); O(leaf) temps | Full inboard body (caller / C) | O(slice) **output**; peak still includes full body input when resident |
| Outboard `carbonado_verify_slice_outboard` | **O(slice+height)** hash (R9) | Full main + full outboard | **Permanent** full-buffer input (W4b) |
| Rust `verify_slice_inboard_seekable` | O(slice) via `SliceRegionWriter` | Full inboard body (`&[u8]`) | O(slice) **output**; peak O(body) when blob resident |
| Rust `verify_slice_outboard` + `ReadAt` (`backend-rust`) | O(slice) | Streaming ReadAt | True O(slice) RSS when data is file-backed |
| Rust `verify_slice_outboard` + `ReadAt` (`backend-lean`) | O(slice) hash after materialize | Materializes `data_len` once → C | Full main copy once (honest) |

### Stream E1/E2 API matrix (W1b — dual honesty)

| API | `backend-rust` peak | `backend-lean` peak | Lean dual engine? |
|-----|---------------------|---------------------|-------------------|
| `stream_encode_buffer` / `stream_decode_buffer` (+ outboard buffer) | O(logical) | O(logical) | **Yes** — Lean buffer C ABI |
| `file::decode_stream` / `file::decode` | O(chunk) spool (rust S4) | O(archive+plaintext) **E1** (W1a; MAC-before-body) | **Yes** — Lean `decode_headered` |
| `stream_encode_inboard` / `stream_decode` | O(chunk/stripe) S4 | O(logical) **E1** (disk-spool ingest + Lean buffer) | **Yes** — Lean body encode/decode |
| `stream_*_outboard` **public non-Compression** (c0/c4/c8/c12) | **O(chunk/stripe) E2** | **O(chunk/stripe) E2** (c4/c12 MVP smoke) | **Composition** — rust S4 geometric; G9 **no-compress** wire bit-match (Compression residual **W2a**); **not** pure-Lean stream |
| `stream_*_outboard` **public + Compression** (c2/c6/c10/c14) | O(chunk) streaming zstd | **O(logical)** bulk zstd (`stream_compress` buffer API; **W4c permanent** buffer-only under lean) | Composition S4, **not E2** under lean; no dual-safe streaming frames |
| `stream_*_outboard` **encrypted** | O(chunk) S4 + EtM spool | O(logical) **E1** | **Yes** — Lean `encode_outboard` / `decode_outboard` (crypto dual) |
| `stream_decode_async` (optional `async`) | disk O(encoded) + S4 | disk O(encoded) + E1 | Dual-aware via `stream_decode` (R10); freeze never requires `async` |

**Honesty rules:** never claim “true stream” / O(chunk) for Lean **E1** paths or for public **Compression** outboard under lean. W1b E2 MVP = public **non-Compression** outboard composition only. Pure Lean chunked stream requires a future streaming C ABI.
