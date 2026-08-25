# carbonado — parity and `ref/` pins

## Method

1. **Rust contract:** `tests/` on the Rust engine (`cargo test`). There is no Cargo Lean backend and no product C ABI. Do not claim G8 C-ABI parity. See [TEST_CONTRACT.md](./TEST_CONTRACT.md), [GAPS.md](./GAPS.md).
2. **Component oracles:** pin reference trees under `ref/`; keep offline drivers (`etm-vectors`, `rs-vectors`, `bao-vectors`) for fast regression against Lean goldens / AOT demos.
3. **Lean goldens (G9 remainder):** Rust still decodes committed Lean AOT bytes under `tests/fixtures/g9/lean/` (`just test-g9`). Live rust→lean encode via C is gone. **W2d** same-engine codecode/decodec in `tests/determinism_roundtrip.rs`. Compression / directory encode vs Lean AOT frames remains a measured residual.

**SSOT roles (do not invert):**

| Layer | Role |
|-------|------|
| Rust `src/` + default `backend-rust` | Production engine |
| Rust `tests/` | Normative behavioral contract for the Rust engine |
| Lean `Carbonado/` + AOT demo | Spec, proofs, demo binary (tiny C `@[extern]` for zstd/SLH only) |
| `ref/` | Pinned third-party oracles and vector drivers |

Pin the exact **third-party** trees the Rust product used (Bao, RS, crypto crates, zstd, bitcoinpqc, …); Lean AOT must remain wire-compatible with that contract. Rust product under `src/` + `tests/` is **first-class SSOT** — not demoted to “oracle only.” **G1 closed (W5a):** no `ref/carbonado-rust` product pin (permanent policy; see freeze strategy below).

## Pins (from Carbonado `Cargo.lock` / Surmount)

| ref path | Source | Pin (commit / tag) |
|----------|--------|--------------------|
| `ref/bao-tree` | `https://github.com/SurmountSystems/bao-tree.git` | Oracle snapshot **`02916e784bb0afe0fd5a73c291c8c5335865e166`** (keyed work before upstream squash). **Product** cargo dep is n0-computer/bao-tree **`dbc952e32cbda8ffd14c106b770e72987b01618e`** (PR 78 merge; git rev, not crates.io). |
| `ref/reed-solomon-erasure` | `https://github.com/darrenldl/reed-solomon-erasure.git` | tag **`v5.0.3`** → **`9f974918f8c598eee351406c36fa0295f4bb4d69`** |
| `ref/rustcrypto-block-ciphers` | `https://github.com/RustCrypto/block-ciphers.git` | tag **`aes-v0.8.4`** → **`f2dbee516b4d0cf4cb4f3045d09e35b5fd80087b`** |
| `ref/rustcrypto-macs` | `https://github.com/RustCrypto/MACs.git` | tag **`hmac-v0.12.1`** → **`46797e3b44973a30edb9d7f3a3ebb41810061d90`** |
| `ref/rustcrypto-hashes` | `https://github.com/RustCrypto/hashes.git` | tag **`sha2-v0.10.9`** → **`82c36a428f8d6f05f3bfccdedb243e9d1f85359d`** |
| `ref/blake3` | `https://github.com/BLAKE3-team/BLAKE3.git` | tag **`1.8.5`** → **`93a431c78a52d7ccf0f366f106467f5070e6075e`** |
| `ref/zstd` | `https://github.com/facebook/zstd.git` | tag **`v1.5.7`** → **`f8745da6ff1ad1e7bab384bd1f9d742439278e99`** — **product SSOT** for static libzstd in `nix/native` (not nixpkgs.src); Rust crate was zstd 0.13.3 |
| `ref/bitcoinpqc` | `https://github.com/cryptoquick/libbitcoinpqc-bindings.git` | **`7936b56f15e86b6764947c9298215ecfe38b712b`** |
| `ref/crates/ctr-0.9.2` | crates.io `ctr` 0.9.2 | checksum `0369ee1ad671834580515889b80f2ea915f23b8be8d0daa4bbaf2ac5c7590835` — **vendored (Program B)** |
| `ref/parity-harness` | in-repo | `drivers/etm-vectors` (B); `drivers/rs-vectors` (C); `drivers/bao-vectors` (D); directory/CFP2 vectors deferred (G residual) |
| ~~`ref/carbonado-rust`~~ | **not used** | **G1/W5a permanent policy:** no product pin submodule — live `src/` + `tests/` are dual-suite SSOT |

## Submodules

Declared in [`.gitmodules`](../.gitmodules). Checked-out commits must match the table above
(`git submodule status` / `git -C ref/<name> rev-parse HEAD`).

## Program B EtM parity

1. **Oracle driver:** `ref/parity-harness/drivers/etm-vectors` (RustCrypto aes+ctr+hmac+sha2, same labels/domains as `src/crypto.rs`).
2. **Goldens embedded** in `Carbonado/Main.lean` and `CarbonadoTest/EtM.lean` (`native_decide` + AOT `demo` greps).
3. Vectors cover: SHA-512 empty/abc/fox, HMAC RFC 4231-1, NIST SP 800-38A AES-256-CTR F.5.5, Carbonado subkeys (`aes-ctr`/`etm-hmac`/`header-auth` under master `0x42×32`), header-path EtM blobs, low-level `[nonce\|tag\|ct]`, header MAC samples.
4. **Decrypt error order** matches Rust `symmetric_decrypt_with_nonce`: ciphertext length → master length → (Lean-only) nonce length → MAC. Rust takes `[u8; 16]` nonces so it has no nonce-length branch; Lean’s `invalidNonceLength` is the ByteArray API analogue.

Regenerate goldens:

```bash
cd ref/parity-harness/drivers/etm-vectors && cargo run --quiet
```

## Program C RS 4/8 parity

1. **Oracle driver:** `ref/parity-harness/drivers/rs-vectors` (path dep on `ref/reed-solomon-erasure` @ v5.0.3).
2. **Goldens embedded** in `Carbonado/Main.lean` and `CarbonadoTest/Fec.lean`.
3. Vectors cover:
   - GF(2^8) mul/div/exp samples (poly 0x1d)
   - `calc_padding_len` for 0/1/100/4096/16384/16385
   - RS encode 1-byte shards → parity `45 5e 67 78`
   - sequential 8-byte shards parity heads
   - Carbonado inboard `hello` (pad 16379, chunk 4096, body 32768)
   - pattern `i%251` len 100 parity0 head `001b362d6c775a41`
4. Reconstruct: parity-only (drop data 0–3) and mixed knockouts exercised in AOT Main.

Regenerate goldens:

```bash
cd ref/parity-harness/drivers/rs-vectors && cargo run --quiet
```

## Program D keyed Bao parity

1. **Oracle driver:** `ref/parity-harness/drivers/bao-vectors` (path dep on `ref/bao-tree` @ `02916e78…`, `blake3` 1.x; `Cargo.lock` committed).
2. **Goldens embedded** in `Carbonado/Main.lean` and `CarbonadoTest/Bao.lean`.
3. Vectors cover:
   - BLAKE3 `hash(empty)`, `hash(abc)`
   - `carbonado_verification_key` for formats 0/4/6/12/14/15 via `blake3::derive_key("carbonado-v2/verification", &[format])`
   - Keyed roots for patterned lengths (0…8192) under c4; format domain separation c4/c6/c14 on pat100
   - Inboard `[u64le content_len | response]` for empty/1/hello/pat100/4096/5000/**12288** (three-leaf)
   - Post-order outboard for 5000 B (64 B) and 12288 B (128 B nested parents)
   - Slice encode/stream-decode: first leaf of 5000 → 4160 B; middle leaf of 12288 → 4224 B (`keyed_decode_ranges` without full trusted body)
   - Wrong format key fails decode (`LeafHashMismatch` / `ParentHashMismatch` → Lean `authenticationFailed`)
4. Invariants: full-file root ≡ `blake3::keyed_hash(key, data)`; 4 KiB leaf geometry (`BlockSize::from_chunk_log(2)`).
5. Lean stream API: `decodeSliceResponse` / `decodeSliceForFormat` (not re-encode oracle).

Regenerate goldens:

```bash
cd ref/parity-harness/drivers/bao-vectors && cargo run --quiet
```

## Program E pipeline parity

1. **Composition:** Lean `Carbonado.Pipeline.encodeBody` / `decodeBody` mirrors Rust `stream_encode_buffer` / `stream_decode_buffer` stage order (compress → encrypt → FEC → Bao).
2. **Compression:** Program F links zstd-20 for the Compression bit (see below). Structure + format-byte keying match.
3. **Header:** 177 B layout matches `src/file.rs` `Header::LEN` / `try_to_vec` / `TryFrom<&[u8]>`; header MAC formula matches EtM goldens already in Program B.
4. **Scrub:** pure RS subset + re-encode + Bao root (same oracle idea as `decoding::scrub`); no seekable slice extract entry in Lean yet.
5. **Shards:** pure multi-segment model vs `stream/shard.rs` (`chunk_index` sequence, headered segments).
6. **Optional driver:** `ref/parity-harness/drivers/pipeline-vectors` may be added later for live Rust↔Lean body goldens; until then AOT format-matrix + CarbonadoTest `native_decide` roundtrips are the gate.
7. **Stream bounds:** Lean theorems on O(stripe) retain (`Carbonado.Stream`); documents residual shared with Rust FEC path.

## Program F zstd + SLH parity

1. **zstd pin / product SSOT:** commit **`f8745da6…`** (tag v1.5.7). Checked out as `ref/zstd` submodule for oracle/review; flake **fetches the same rev+hash** into `nix/native` (`zstdPinned` in `flake.nix`) and **statically** compiles `lib/common|compress|decompress` + FFI into `libcarbonado_native.a` (level 20, single-threaded, no shared `-lzstd`). nixpkgs is only for the host toolchain / Lean headers — **not** the zstd source pin. Updating zstd requires: submodule checkout, `flake.nix` rev/hash, and PARITY table together.
2. **Goldens (AOT `demo`):** API frames for empty (`28b52ffd2000010000`) and `hello` (`28b52ffd200529000068656c6c6f`); frame-header parse (Single_Segment + 1-byte FCS, checksum off, no dict); G9 c14 prefixes (`20 1a` lean vs `00 78` rust); corrupt frame → `decompressionFailed`; tight `maxOut` → `outputTooLarge`; zeros shrink; pipeline c2/c6 + **headered c3/c7**; full format matrix incl. compression at runtime. Rust `tests/zstd_frame_params.rs` parses the same bits (not a full bitstream proof; W2a).
3. **Interpreter residual:** Lean `@[extern]` bodies are identity for elaborator; real frames only in AOT (LIMITS). CarbonadoTest `native_decide` covers non-compression formats + status maps.
4. **SLH1 wire:** magic `SLH1`, signature 7856 B, sidecar 7860 B — matches `src/crypto.rs` `SLH1_*` and AGENTS §2.3. Pure suite: length errors + `parseMagicAtExactLen` / `badSlhMagic` gate theorems; full-length build/parse + all-zero magic in `demo`.
5. **Bind-to-root + live SLH (R9 / G10):** Lean model requires signature message = Bao root (`verifyBoundToExpected`); wrong root → `verificationFailed`. Real SLH-DSA-SHA2-128s sign/verify is **linked** via flake pin `b309f444…` (same SSOT as `ref/bitcoinpqc` submodule target) into `libcarbonado_native.a` — C `carbonado_slh_*` + Lean `@[extern]`. Nested worktree emptiness is not a product residual when the flake fetch pin is present. Dual-suite product SLH may still use Rust `bitcoinpqc` composition.
6. **Optional drivers:** `ref/parity-harness/drivers/zstd-vectors`, `slh-vectors` for cross-oracle goldens (live FFI already in product AOT / libcarbonado).

## Adding a gate

1. Vectors under `ref/parity-harness/` or `CarbonadoTest/` goldens  
2. Nix derivation comparing Lean AOT vs ref binary/library  
3. Register in `flake.nix` `checks` and [SPEC-MATRIX.md](SPEC-MATRIX.md)  

## Submodule init

```bash
git submodule update --init --recursive
# Oracle bao-tree (Lean goldens / bao-vectors). Product cargo uses n0-computer PR 78 merge.
git -C ref/bao-tree checkout 02916e784bb0afe0fd5a73c291c8c5335865e166
```

CI must checkout recursively once submodules are recorded on the default branch.

## carbonado-rust freeze strategy (G1 / W5a — permanent policy: no product pin)

**Decision (closed 2026-07 W5a): do not add `ref/carbonado-rust`.**

Dual-backend model keeps **live** Rust under `src/` and `tests/` as first-class production + normative contract. A separate frozen product tree is **not required** and is **not** part of the dual-backend freeze.

| Policy | Detail |
|--------|--------|
| Product SSOT | Live `src/` + `tests/` (G8: both backends against the same suite) |
| What `ref/` pins | Third-party oracles only (bao-tree, zstd, bitcoinpqc, RustCrypto, blake3, reed-solomon-erasure, parity-harness, vendored crates) |
| `ref/carbonado-rust` | **Absent by policy** — do not invent a submodule or SHA |
| Why no product pin | (1) Dual-suite SSOT is the live tree, not a historical snapshot. (2) A product pin duplicates `src/`/`tests/`, confuses which tree is normative, and is unused by CI `dual-backend-lean`. (3) Third-party pins already freeze what Lean/goldens compare against. |
| Future archaeology | A release-specific historical checkout remains *possible* outside this policy if needed; it is **non-required** and must not replace live `src/`/`tests/` or demote Rust to “oracle only.” |
| Do not | Delete or demote live `src/` / `tests/` for “Lean purity”; treat Lean as a replacement that removes the Rust engine (G8 requires both). |

G1 status: **closed** with this permanent no-pin policy — see [GAPS.md](GAPS.md).
