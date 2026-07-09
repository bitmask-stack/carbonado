# AGENTS.md — Carbonado Development Guidelines

**Project:** Carbonado (bitmask-stack/carbonado)  
**Mission:** Apocalypse-resistant archival format for consensus-critical data, with a focus on Bitcoin quantum resistance.  
**Current Status (as of 2026-07):** Symmetric v2 stack (`CARBONADO20\n`, AES-256-CTR + HMAC-SHA512 EtM) stable. **P1:** `SLICE_LEN=4096`, keyed 4 KiB Bao groups, seekable slice verify. **P2:** streaming-first encode/decode. **P3:** segment sharding. **P4:** Adamantine 1.0 directory archives (see §7.1). FEC: reed-solomon-erasure RS 4/8. Outboard + scrub complete.

**Unified streaming stack (three independent axes — do not conflate):**
| Axis | Status |
|------|--------|
| **Streaming / memory** | Phase 1 fused sync path shipped (`SeekableSpool`, streaming EtM, stripe FEC). **M1:** non-FEC verification (c6) uses `SeekWriteAt` (O(chunk) RAM); FEC verification retains O(FEC body) shard buffers under segment-wide RS geometry (`finish_into` avoids a second full logical `Vec`). Residuals: FEC O(segment body), O(sidecar) outboard verify, async encoded-body spool. See [doc/STREAMING_PARALLELISM.md](doc/STREAMING_PARALLELISM.md). **Not** the same as Bao slice/stream verification. |
| **Concurrency** | Phase 2 optional `async` / `stream_decode_async` (disk spool bridge; WASM `NotImplemented`). |
| **Parallelism** | Phase 3 `parallel` feature (default on): `std::thread::scope` RS parity; WASM serial at runtime. No rayon; Tokio is not the CPU-parallel story. |

**PQC:** `bitcoinpqc` 0.4, SLH-DSA-**SHA2**-128s sidecars only (`SLH_DSA_SHA2_128S`). Dev SHAKE-128s sidecars are incompatible — re-sign.

---

## 1. Core Principles

- **Clean cryptographic break.** This version of Carbonado does **not** contain any code to read or write v1 ECIES-encrypted files. Old encrypted archives require external migration (use an older version of the tool to extract plaintext, then re-encode with the new symmetric primitives).
- "Backward compatibility / migration path" (from the original spec) refers **only** to preserving the non-crypto properties of the format:
  - Pipeline ordering (compress(zstd-20) → encrypt → FEC → bao and reverse)
  - Flat-file portability
  - WASM/browser support
  - Bao-based streaming verification and replication proofs
  - Forward error correction (4/8 RS model — see v1-vs-v2 rationale)
  - Content addressability via the outer bao hash
- **First-principles security.** All cryptographic decisions must be justifiable from security definitions (IND-CPA for CTR, INT-CTXT for EtM, PRF properties of HMAC-SHA512, domain separation, key independence).
- **HMAC-SHA512 is mandatory** for both authentication (full 64-byte tags) and all subkey derivation. No simple splits, no SHA-256-only KDFs for key material.

---

## Critical Rules to Avoid Previous Friction

These rules were added because the same misunderstandings have caused significant frustration and wasted effort:

**Production Readiness Tracking (2026-05-30 onward)**
- All remaining work required to reach "perfect and production ready" status is tracked in a single detailed todo list managed via the todo_write tool in the current session.
- New gaps discovered during audits (AES-CTR naming, nonce documentation, WASM realities, CI strictness, unwrap sites, etc.) must be immediately added as todos.
- The list is the source of truth. Status is updated in real time as items are completed with evidence (tests passing, clippy clean, docs written, etc.).
- Never batch-close multiple items. Mark one as completed only when it is verifiably done.
- The final gate (todo 29) requires a full pass against the original spec + every rule in this file.

1. **Clean Break is Non-Negotiable**
   - This library does **not** decode v1 ECIES files. Period.
   - "Backward compatibility" or "migration path" in the original spec means preserving the non-crypto format properties (pipeline, bao, zfec, flat file, WASM, etc.). It does **not** mean the code can read old encrypted containers.
   - If old v1 data is encountered, fail with a clear message directing the user to external migration.

2. **Option Presentation Discipline**
   - When offering choices, always present **one single, clearly numbered list**.
   - Never present multiple overlapping or conflicting lists in the same response.
   - Example format:
     ```
     **Next options:**
     1. Do X
     2. Do Y
     3. Do Z
     ```
   - The user has zero tolerance for ambiguity here.

3. **The `Header` Replacement Rule** (see expanded section below)

4. **Never Claim Completion While Spec-Mandated Components Are Stubs**
   - The core of the new design consists of the symmetric primitives (AES-256-CTR + full HMAC-SHA512 EtM with domain-separated subkeys) plus **SLH-DSA sidecars via bitcoinpqc** for post-quantum signatures. SLH-DSA is asymmetric by nature and is deliberately kept outside the main (symmetric) container as sidecars only. Key derivation from passphrases (e.g. Argon2id) is the caller's responsibility before supplying a 32-byte master key.
   - Do not mark work "final", "complete", or run "end-to-end verification" passes while any of those pillars remain placeholder functions or comments only.
   - If bitcoinpqc is listed as a dependency and the spec calls for SLH-DSA sidecars, real functions + minimal wiring + tests are required before any "done" language.
   - When in doubt, grep for `NotImplemented`, `slh_`, `placeholder`, and "stub" before claiming progress.

5. **Production Ready Bar (Zero Tolerance for Shortcuts)**
   - The user has explicitly set the requirement: "It needs to be perfect and production ready."
   - This means:
     - No remaining stubs or NotImplemented in any crypto path required by the spec.
     - All misleading names, outdated comments, and parameter lies fixed.
     - Full documentation of every security-relevant decision (nonce scope, subkey labels, single-nonce behavior, sidecar signing rules, CTR counter management, etc.).
     - Real benchmarks proving hardware acceleration claims.
     - WASM support either works cleanly or has precise documented limitations.
     - CI is strict (full clippy --all-targets --all-features -D warnings, relevant targets tested).
     - Error handling is complete and specific; no lossy or generic errors hiding crypto failures.
     - Zeroization of secret material where practical.
     - Test coverage includes adversarial, large-payload, and cross-layer cases.
     - No `.unwrap()` / `.expect()` in hot library paths that could panic on attacker-controlled input.
   - Before any release or "done" declaration, run a full manual gate against this file + the original specification.
   - Update this section whenever new production requirements are discovered.

5. **Do Not "Keep Things for Transition" Without Explicit Permission**
   - When the direction is "clean break," remove or replace the old implementation rather than carrying both versions forward unless the user specifically asks for a transition layer.

---

### The `Header` Type Replacement Rule (Critical)
When doing the v2 rewrite:
- **Do not** create a parallel `HeaderV2` type alongside the old `Header`.
- **Replace the existing `Header` struct in-place**: change its fields, `new()`, `try_from*`, `try_to_vec()`, etc. to the new symmetric design (HMAC-SHA512 auth, `payload_nonce`, `header_mac`, no secp pubkey/signature for new files). The single `MAGICNO` was updated to the v2 value.
- Keep the **type name** `Header` (API stability where reasonable).
- Old v1 ECIES-era logic inside `Header` (pubkey + Schnorr signing/parsing) must be removed or replaced, not preserved "for transition."
- If the user says "just replace it," they mean evolve the single `Header` type — not keep both versions.

Violating this rule has caused repeated confusion and rework.

---

## 2. Cryptographic Architecture (v2 — Current Target)

**This section is normative for the v2 symmetric design. All code changes, documentation, and audits must stay consistent with it.**

### 2.1 Core Encryption + Integrity (Symmetric: AES-256-CTR + HMAC-SHA512 EtM)

**Important**: The main Carbonado container uses only symmetric cryptography for its per-segment encryption layer. The optional hybrid paranoia layer (see below) places an inner (secp+ChaCha AEAD) inside an outer symmetric (AES-CTR + HMAC EtM) — the visible container is still wrapped by our symmetric primitives. SLH-DSA (see §2.3) is used exclusively for *sidecar* signatures and is not part of the per-segment format. This keeps the core container length-preserving, hardware-accelerated, and only Grover-resistant (as appropriate for symmetric crypto).

### v1 vs v2: Changes and Rationales (Normative Summary)

This section provides a thorough, decision-by-decision comparison between the original v1 (ECIES-based) design and the v2 symmetric design (AES-256-CTR + full HMAC-SHA512 EtM + keyed 4KB Bao + RS-based FEC). Every major change is listed with:
- What changed.
- The v1 behavior (for reference).
- The v2 behavior.
- **Why** (first-principles security arguments, performance, simplicity, hardware realities, quantum posture, reproducibility for archival/scrub, and alignment with AGENTS.md invariants and the original Surmount spec).

The overarching principle is a **clean cryptographic break** (see §1). v1 ECIES material (secp pubkeys, Schnorr sigs in header, ecies crate) is completely removed — no dual paths, no decode support for old files. Migration of old archives is always external. Non-crypto properties (zstd-20 compress → [encrypt] → FEC → bao pipeline shape, flat-file portability, WASM, Bao verifiability, content-addressable outer hash, 16 Format combos) are preserved.

#### High-Level Feature Comparison

| Area                  | v1 (ECIES era)                          | v2 (Symmetric)                                      | Key Rationale |
|-----------------------|-----------------------------------------|-----------------------------------------------------|---------------|
| Encryption primitive | ECIES (secp256k1 ECDH + AES-GCM hybrid) | AES-256-CTR (length-preserving stream)             | CTR for true length preservation + perfect parallelism (AES-NI/VAES). IND-CPA when nonce unique. ECIES had variable-length overhead and weaker hardware fit. |
| Authentication       | GCM (AEAD, 16B tag) + optional Schnorr | EtM with **full 64B HMAC-SHA512** (never truncated) | Strongest EtM provable security (INT-CTXT). Full tag + domain sep per AGENTS "full HMAC-SHA512" mandate and LUKS2 inspiration. Matches subkey primitive. |
| Key derivation       | ECDH + direct splits                    | HMAC-SHA512 BIP-32-style with domain labels (`aes-ctr`, `etm-hmac`, `header-auth`) | PRF security, domain separation, key independence. No simple splits. All key material from one 32/64B master. |
| Nonce / IV           | GCM IV (often content-derived or small) | 16B random from getrandom (high-level: 1 per archive) | CTR requires unique nonce per key (catastrophic reuse otherwise). Random + getrandom is simplest correct CSPRNG usage. |
| Header               | ~160B with secp pubkey + Schnorr sig   | 177B: MAGIC + payload_nonce + header_mac (64B) + bao hash + slh_pk + format + u32 chunk + lengths + meta | Separate header_mac (header-auth subkey) for integrity of public metadata. No secret key material. slh_pk moved to header (sig stays sidecar). |
| Post-Quantum sigs    | None (or ad-hoc)                        | SLH-DSA (SHA2-128s) **sidecars only** (`<hash>.cXX.slh`) | Sidecars preserve content-addressing and avoid bloat. bitcoinpqc 0.4 dogfooding per Surmount/BIP-360 mission. |
| Forward Error Correction | zfec 4/8 (non-deterministic scrub for >~8KB, vulnerable to hits across all 8 chunks) | reed-solomon-erasure (RS 4/8): deterministic encode, reproducible scrub, better tolerance for distributed corruption ("chaos rays") while keeping 4/8 model | RS (BCH subclass) for pure determinism (critical for scrub re-encode + bao hash compare) and stronger erasure properties against partial corruption in every shard. Kept 4/8 for storage model ("application RAID"), alignment with 4 KiB slices/Bao leaves, and user intuition. |
| Verifiability (Bao)  | bao 0.12/0.13 (1KB groups)             | bao-tree fork: 4KB groups (BlockSize log=2) + keyed on format byte | 4KB aligns with disk sectors + reduces tree overhead. Keyed roots make Bao hash multi-dimensional (commits to Format pipeline for markets). |
| Slice / chunk counts | u16 limits (~64MiB FEC cap)            | u32 (theoretical ~4GiB+ per segment)               | Removed artificial caps for large archives. P1: `SLICE_LEN=4096` (one slice = one 4 KiB Bao leaf). |
| Passphrase KDF       | Argon2id wrapper inside library        | Removed; caller responsibility (Argon2id recommended outside) | Keeps container security contract simple. Master key is 32/64B high-entropy material. |
| Magic number         | CARBONADO01 or similar (ECIES)         | CARBONADO20\n (stable v2); 02 was dev transitional | Signals official stabilized 2.0 format. Old magic → clear external migration error. |
| Version              | Pre-0.7 (ECIES)                        | 2.0.0 (post-FEC + docs stabilization)              | Marks end of fluid dev period. API now stable for semver. |
| Dependencies         | ecies + secp + ...                      | aes+ctr+hmac+sha2 + reed-solomon-erasure + bao-tree fork + bitcoinpqc (optional pqc) | Clean break removal of ECIES-only crates. Hardware-accel friendly. |
| Optional hybrid layer | (the only encryption was the ECIES hybrid) | Pure symmetric is default. Added *optional* inner secp256k1-ECDH + ChaCha20-Poly1305 AEAD wrapped by outer AES-CTR + HMAC-EtM (via new hybrid_* and ecc_aead_* APIs) | "Maximal paranoia" defense-in-depth: different cipher families, different key-gen (ECDH+derive vs pure HMAC labels), HMAC + AEAD. See dedicated rationale below. Pure sym path and Encrypted bit semantics unchanged for normal use. secp here is *not* for the main container (no pubkeys in headers etc.). |

#### Detailed Decision Rationales

**Encryption: ECIES → AES-256-CTR**
- v1 used hybrid ECIES (ECDH + AES-GCM). Variable overhead, not length-preserving, poorer AES-NI utilization on some paths.
- v2 uses pure AES-256-CTR (`Ctr128BE<Aes256>`). 
- **Why**: 
  - IND-CPA security when nonce never reused (proven reduction to PRP).
  - Exact length preservation (no IV/tag expansion in ciphertext stream itself).
  - Maximum parallelism (each block independent) → best VAES/AES-NI on Zen 5+ (target hardware).
  - Matches LUKS2 "aes-xts-plain64" philosophy adapted to flat-file.
  - Quantum: Grover gives only quadratic speedup (~128-bit PQ security for 256-bit key).
- Tradeoff: CTR alone provides no integrity (hence mandatory EtM below). Nonce must be unique (enforced by random + policy).
- See 2.1.1 for full first-principles argument.

**Authentication: GCM → Full HMAC-SHA512 EtM**
- v1 relied on GCM (16B tag).
- v2: Encrypt-then-MAC with **untruncated 64B HMAC-SHA512** (`Hmac<Sha512>`), domain "carbonado-v2-etm", tag prepended.
- **Why**:
  - EtM has the strongest provable security when MAC is secure PRF.
  - Full 64B per explicit design mandate ("full HMAC-SHA512") and historical Surmount spec. Provides 256-bit collision resistance.
  - Same primitive used for subkey derivation → implementation/analysis reuse.
  - MAC covers nonce + ct (binds them; prevents certain attacks).
- Never truncate (weakens security). Tag verified before any decryption.
- See 2.1.2.

**Key Separation: ECDH/direct → HMAC-SHA512 BIP-32 style**
- Labels: `aes-ctr`, `etm-hmac`, `header-auth`.
- **Why**: HMAC-SHA512 is a secure PRF. Domain separation ("carbonado-v2/" + label) prevents cross-use. Produces independent keys even from same master. Key independence invariant: compromise of one doesn't help others.
- Master key is always raw 32/64B (BIP-32 "I" output friendly). No KDF inside library core.
- See 2.1.3 and subkey registry.

**Nonce Handling**
- v2: 16B from getrandom (high-level: one per logical archive when Encrypted).
- **Why**: CTR security requires uniqueness per (key, operation). Random from OS CSPRNG is simplest correct way (no content-derived determinism risks). One-nonce-per-archive acceptable for archival (recommended <1TiB per master without rotation). Nonce is public (included in MACs).
- See "What is payload_nonce?" and 2.1.4.

**Header Model**
- Never encrypted (public metadata). Authenticated only via 64B `header_mac`.
- v2 layout includes `payload_nonce` (public), `slh_public_key` (public, for sidecar binding), u32 `chunk_index`.
- **Why**: Standard for container formats (LUKS2, age). Allows storage systems to parse/route without key. `header_mac` (separate subkey) gives integrity/auth before any processing. No secrets ever in header. Multi-dimensional Bao hash + keyed roots handle content vs container naming.
- See full "Header Visibility and Confidentiality Model".

**FEC: zfec-rs 4/8 → reed-solomon-erasure (RS 4/8)**
- v1/prior: zfec 4/8. Chunk-based. Scrub non-deterministic for >~8KB (re-encode didn't reliably match). Vulnerable if corruption distributed across all 8 chunks.
- v2: RS (BCH subclass) 4 data + 4 parity shards. Deterministic encode. Scrub uses search over good extracted shards + re-encode + bao hash oracle.
- **Why**:
  - Determinism required for reliable scrub (re-encode + compare bao root).
  - RS provides strong erasure coding: any 4/8 shards sufficient; better tolerance for partial/distributed "chaos ray" corruption within the shard model.
  - Kept exact 4/8 + concat layout + alignment (FEC_K * SLICE_LEN) to preserve storage model ("application RAID"), 4 KiB slice/Bao-leaf geometry, and user expectations.
  - Overhead ~2x same; reproducible for content addressing.
- Not finer-grained per-byte (would change on-disk + storage model; not required).
- See CHANGELOG.md and §7 CHIPs tracker for RS FEC rationale and status.

**Bao Verifiability**
- 1KB fixed groups → 4KB (BlockSize log=2) + keyed on format byte ("carbonado-v2/verification" + format).
- **Why**: 4KB = disk sector friendly, lower tree overhead for small/large files. Keyed roots make outer hash commit to the exact Format pipeline (multi-dimensional naming useful for markets: encrypted vs public variants produce distinguishable roots).
- Root still over body only; header_mac binds metadata.
- See "Keyed Bao idea" and 2.1.5.

**SLH-DSA Post-Quantum Signatures**
- v2: bitcoinpqc (FIPS-205 SLH-DSA-SHA2-128s), **sidecars only** (`<hash>.cXX.slh`), 32B public key stored in main Header.
- **Why**: Sidecars keep per-segment containers small and content-addressable. Sign the Bao root of the *processed container* (multi-dimensional). Matches Surmount quantum-resistance mission (Grover-resistant symmetric + hash-based PQ sigs).
- Entropy: 128B+ for keygen. `SecretKey` zeroizes.

**Other Decisions**
- Argon2id wrapper removed: caller supplies high-entropy master. Keeps library contract simple.
- u16 → u32 for verifiable/chunk slice counts: remove ~64MiB artificial cap.
- New magic `CARBONADO20\n` + v2.0.0: Signals stable post-overhaul format. Dev used 02.
- No v1 decode ever: explicit per clean-break rule.

**Hybrid paranoia layer (defense-in-depth addition)**
- Added (optional) `ecc_aead_encrypt` / `hybrid_*` etc. in `crypto`:
  - Inner: ephemeral secp256k1 ECDH + ChaCha20-Poly1305 (standard AEAD).
  - Wrap: feed the inner blob as plaintext into our existing `symmetric_encrypt_with_nonce` (AES-CTR + 64B HMAC EtM under master via derive_subkey).
- The high-level `file::encode` / `encoding::encode` `Encrypted` paths continue to do *pure* symmetric only. Hybrid is used explicitly by callers who supply recipient secp material.
- **Why double everything** (first-principles):
  - Different cipher families (block CTR stream vs stream ChaCha) reduce risk of a single catastrophic break or implementation flaw affecting all data.
  - Different key derivation paths: pure HMAC labels vs. ECDH shared secret fed through derive_subkey again ("doubling up on symmetric key generation mechanisms").
  - Different integrity primitives: HMAC-SHA512 EtM + Poly1305 (AEAD).
  - Ephemeral ECDH gives per-blob forward secrecy on the inner layer (useful even if outer master is long-lived).
  - Even though secp ECDH is classically broken by large quantum computers, the *outer* AES+HMAC layer (which is what the container format presents) retains its symmetric security properties. The hybrid is "ECC wrapped inside our symmetric".
  - Matches the user's explicit request for "doubling up on ciphers, symmetric key generation mechanisms, and incorporating both HMAC and AEAD approaches" for "maximal paranoia".
- Composition with pipeline and Header: the output of hybrid_* is the equivalent of an "encrypt" step result. Callers feed it to FEC/Bao stages and (if using Header) use the outer nonce + master for Header construction, typically with the Encrypted bit *clear* so that standard decode does not attempt a second pure-symmetric decrypt. The master still protects header_mac and the outer EtM.
- Invariant preserved: no secret key material in headers; clean separation; pure-sym path untouched.

**What Was Preserved (Non-Crypto Properties)**
- Pipeline ordering (with FEC now generalized).
- Flat-file, WASM, Bao streaming + slices (enhanced).
- 16 Format bitmasks (Encrypted lowest bit so unencrypted = even).
- Content addressability via outer (now keyed) bao hash.
- Zfec 4/8 *concept* (now RS 4/8).

All decisions are documented with first-principles arguments in this file (especially §2.1). Any future change must be justifiable the same way and recorded here.

---

### 2.1 Core Encryption + Integrity (Symmetric: AES-256-CTR + HMAC-SHA512 EtM)

- **Bulk encryption**: AES-256-CTR using the `aes` + `ctr` crates (`Ctr128BE<Aes256>`).
  - Full 128-bit counter block. The 16-byte nonce passed to the cipher is used as the initial counter value and incremented as a big-endian 128-bit integer.
  - Length-preserving (no padding, no IV prefix in the ciphertext itself when using the explicit-nonce path).
- **Authentication**: Encrypt-then-MAC (EtM) with **full 64-byte HMAC-SHA512** tags. Never truncate.
  - The MAC is computed as: `HMAC-SHA512(mac_key, "carbonado-v2-etm" || nonce || ciphertext)`.
  - Tag is prepended to ciphertext in the payload paths: `[tag(64) | ct]`.
- **Two distinct encryption entry points** (both must be understood):
  1. High-level `file::encode` / `file::decode` (Header path):
     - One 16-byte random nonce is generated **once per logical archive** (before any zfec/bao).
     - Encryption happens on the (optionally compressed) plaintext.
     - The nonce is stored in the Header (`payload_nonce` field) and protected by the separate header MAC.
     - Uses `symmetric_encrypt_with_nonce`.

**What is `payload_nonce`?** (direct answer)
It is the 16-byte AES-CTR nonce/IV for the *high-level symmetric encryption path only*. It is generated with `getrandom` inside `file::encode` when the `Encrypted` bit is set, used for both the CTR keystream *and* the payload EtM tag, then written into the Header so `file::decode` can use the identical value for decryption and for verifying the independent `header_mac`. It is **not** present in the low-level `encoding::encode` path (that path uses an internal random nonce prepended inside the ciphertext blob). One `payload_nonce` protects one entire logical Carbonado archive (one Header + body). Never reuse it with the same master key for a different encryption operation.
  2. Low-level `encoding::encode` / `decoding::decode`:
     - Calls `symmetric_encrypt`, which generates a fresh 16-byte nonce **per call** using `getrandom`.
     - Nonce is embedded inside the encrypted blob: `[nonce(16) | tag(64) | ct]`.
     - This blob is then fed to zfec + bao.
- **Nonce rules (critical invariants)**:
  - 128 bits of randomness from `getrandom` (OS CSPRNG or equivalent backend).
  - Must be unique per (master_key, encryption operation).
  - Nonce is **always** included in the EtM MAC input.
  - For the Header path: one nonce protects the entire logical payload of one `.cXX` file. This is acceptable for archival use but means a single (key, nonce) pair can cover many gigabytes.
  - **Recommended limit**: Do not encrypt more than ~2^40 bytes (~1 TiB) under the same master key without rotation. Beyond that, the probability of nonce collision (while still tiny) and counter wrap considerations become relevant for the truly paranoid.
  - CTR counter exhaustion: With a full 128-bit counter starting at a random value, practical files will never wrap the counter.
- **Key derivation**:
  - All subkeys (AES key material, payload MAC key, header MAC key) are derived with `derive_subkey(master, label)`:
    - `HMAC-SHA512(master, "carbonado-v2/" || label)` → 64 bytes.
  - Registered labels (must be unique and documented — see **Subkey Label Registry** above):
    - `aes-ctr`, `etm-hmac`, `header-auth` (master-key derived)
    - `ecc-chacha-poly` (hybrid: ECDH shared secret as PRF input)
    - `slh-dsa-seed`, `slh-dsa-seed-2` (convenience `slh_sign` only; not container security)
  - Domain separation via the `carbonado-v2/` prefix + explicit label prevents cross-use.
  - Keyed Bao uses `blake3::derive_key("carbonado-v2/verification", &[format])` — **not** `derive_subkey`.

**Note on HMAC-SHA512 choice (documented 2026 session)**:  
With a 256-bit (32-byte) master key, the security of subkey derivation is capped at ~256 bits regardless of whether HMAC-SHA256 or HMAC-SHA512 is used (PRF security follows the entropy of the input key). HMAC-SHA512 was retained for output size convenience (nice 64-byte results) and historical alignment with the "full HMAC-SHA512" mandate from the original design goals, not because it provides higher security than SHA256 would at this entropy level. Future minimality audits could consider HMAC-SHA256 if 32-byte tags were ever acceptable.

### 2.2 Header Authentication (separate from payload)

- Every v2 Header is authenticated with `compute_header_mac(master_key, auth_data)`.
- **Formula (normative):**
  ```text
  header_mac = HMAC-SHA512(header-auth subkey, auth_data)
  ```
- `auth_data` = `MAGICNO` || `payload_nonce` || `bao_hash` || `slh_public_key` || `format` || `chunk_index` (u32 LE) || `encoded_len` || `padding_len` || `metadata`
  - `MAGICNO` is `b"CARBONADO20\n"` (12 bytes).
- **No separate domain string** (e.g. no `carbonado-v2-header`). The leading `MAGICNO` in `auth_data` **is** the domain binding for header MAC.
- Uses the `header-auth` derived subkey (`derive_subkey(master, "header-auth")`).
- Verification happens in `file::decode` before any payload decryption or processing.
- This gives integrity/authenticity of the container metadata independently of the payload EtM.

**Breaking change (2.0.x maintenance):** Earlier dev builds prefixed `b"carbonado-v2-header"` before `auth_data`. Current normative construction MACs `auth_data` directly. All archives produced after this fix use the new formula.

### 2.3 Post-Quantum Signatures (SLH-DSA / SPHINCS+)

- Provided exclusively via the `bitcoinpqc` crate (FIPS-205 **SLH-DSA-SHA2-128s** parameter set; `Algorithm::SLH_DSA_SHA2_128S`).
- **Only as sidecars**. Never embedded inside per-segment `.c14d` / `.c15` Carbonado containers.
- **Parameter-set note:** Wire sizes match SHAKE-128s (32 B pk / 64 B sk / 7856 B sig) but the algorithms are **cryptographically incompatible**. Any sidecars produced under older SHAKE-128s builds must be re-signed under SHA2-128s.
- Intended use: signing manifests, catalogs, checkpoints, or high-level collections of Carbonado files.
- Sidecar format (updated per 2026-05-30 design clarification):
  - 4 bytes: `b"SLH1"` (versioned magic for this sidecar scheme).
  - 7856 bytes: SLH-DSA signature (raw, SHA2-128s) **only** — the public key is no longer duplicated here.
  - The 32-byte SLH-DSA public key **must** be stored in the main Carbonado `Header.slh_public_key` field of the referenced archive segment (or provided out-of-band alongside the signature).
  - The signature is over: the 32-byte Bao root hash of the target Carbonado container (or a higher-level manifest/catalog structure).

**Important clarification on what is being signed (multi-dimensional view)**:
The SLH-DSA signature is always over the Bao root hash that results from the *specific Format combination* chosen for that segment.

Because the 16 format combinations produce different processed forms, the meaning of "what the hash names" is format-dependent:
- With symmetric encryption enabled (`Encrypted` bit set): The hash primarily names the encrypted container.
- Without encryption: The hash can serve as a content-address for the transformed (e.g. compressed + verifiable + FEC) version of the data.

In this sense, the outer Bao hash (and any signature over it) is **multi-dimensional** — it addresses a particular (input + format pipeline) pair rather than raw plaintext or a single universal content identifier.

This is why the signature should not be viewed as a simple "CID substitute" for the original data. It provides strong authenticity for whatever specific processed object was produced under that format. Bao's slice-based verification further changes the classic content-addressing threat model.

Higher-level systems that want plaintext-level content addressing are expected to layer their own naming scheme on top (e.g. via manifests or catalogs that are themselves signed).
  - Optional future extension: include a domain string or the full filename for binding.
- Key sizes (SLH-DSA-SHA2-128s): 32B public, 64B secret, 7856B signature.
- Entropy for keygen: minimum 128 bytes of fresh randomness passed to `bitcoinpqc::generate_keypair`.
- SLH-DSA operations must zeroize secret key material on drop (the crate's `SecretKey` already does this).
- In the library: thin, well-documented wrappers in `crypto.rs` (`slh_dsa_*` functions) + re-exports of the necessary `bitcoinpqc` types for advanced callers. No automatic signing inside `file::encode`.

### 2.4 Key Derivation (Passphrases)

Carbonado itself does **not** perform passphrase-based key derivation.

The library expects a high-entropy 32-byte (or 64-byte) master key. All subkey derivation inside the library is performed with HMAC-SHA512 using domain-separated labels (see §2.1).

If a caller only has a passphrase, they are responsible for deriving a proper master key *before* calling into Carbonado, using a memory-hard KDF such as Argon2id (recommended), scrypt, or equivalent, with parameters appropriate to their threat model and hardware.

This design keeps the container format's security contract simple and explicit: security depends on the entropy and secrecy of the master key supplied to it.

### 2.5 Error Handling & NotImplemented

- `NotImplemented` must only be used for genuinely unimplemented optional features.
- All real crypto failures (bad key length, authentication failure, PQC errors, randomness failure, KDF failure) must have specific, actionable `CarbonadoError` variants.
- PQC errors from `bitcoinpqc::PqcError` are mapped to dedicated variants (added 2026-05-30).

### 2.6 Hardware Acceleration & Implementation Notes

- AES path: relies on the `aes` crate (AES-NI / VAES when `target-cpu=native` or appropriate target features).
- HMAC-SHA512: relies on `sha2` crate (SHA-NI acceleration on supported x86 CPUs).
- SLH-DSA (SHA2-128s): acceleration follows the host SHA-2 implementation in `bitcoinpqc` / underlying C; not tied to Carbonado's AES-NI/VAES path.
- All production benchmarks must be run with `RUSTFLAGS="-C target-cpu=native"`.

### 2.7 Invariants That Must Never Be Violated

1. No v1 ECIES decode paths exist anywhere.
2. The single `MAGICNO` (as of 2.0) is `CARBONADO20\n`. Old/dev magic (02) produces a clear error directing to external migration.
3. Every encrypted payload uses EtM with a full 64-byte HMAC-SHA512 tag that covers the nonce.
4. All key material separation uses HMAC-SHA512 with the registered labels above.
5. SLH-DSA signatures are sidecars only.
6. The Header (when present) is always authenticated before payload decryption.
7. Nonces are 16 random bytes from `getrandom` and never reused under the same master key for distinct encryption operations.

Violating any of the above requires an explicit exception recorded in this file and a new major version.

---

### Header (v2) — Detailed Layout (normative)

- 12 bytes: MAGIC (`CARBONADO20\n`)
- 16 bytes: `payload_nonce` (random 16-byte nonce for AES-CTR of this archive; see §2.1.5)
- 64 bytes: `header_mac` (HMAC-SHA512 using `header-auth` subkey over the fields below)
- 32 bytes: `hash` (Bao root)
- 32 bytes: `slh_public_key` (raw SLH-DSA public key; zeroed `[0u8;32]` when no sidecar signature is associated with this segment)
- 1 byte: `format`
- 4 bytes: `chunk_index` (u32 LE; supports up to 2^32 segments for enormous archives)
- 4 bytes: `encoded_len` (LE, verifiable bytes after bao/zfec)
- 4 bytes: `padding_len` (LE)
- 8 bytes: `metadata` (optional, zeroed when absent)

Total: 177 bytes.

The `header_mac` is computed over exactly: MAGIC || nonce || hash || slh_public_key || format || chunk_index (u32 LE) || encoded_len || padding_len || metadata.

This change (slh_public_key in the main header, signature only in the sidecar) was made to keep the public key with the content it authenticates while still treating the actual signature as a detachable sidecar.

### Header Visibility and Confidentiality Model (normative)

**The v2 Header is never encrypted.** It is public metadata that can (and usually must) be read by storage systems, indexers, replication software, and anyone who has the raw bytes of a `.cXX` file.

The only cryptographic protection on the Header is **integrity + authenticity** via the 64-byte `header_mac` (HMAC-SHA512 under the `header-auth` subkey). Verification of the header_mac happens in `file::decode` *before* any payload processing.

**What is in the Header (all public / non-secret):**
- `payload_nonce` (16 bytes): The AES-CTR nonce for this archive. In CTR (and all standard AEADs such as GCM, ChaCha20-Poly1305, etc.) the nonce/IV is **not secret material**. It must be unique and unpredictable, but it is transmitted in the clear alongside the ciphertext. Knowledge of the nonce alone gives an attacker nothing without the master key (or the derived AES subkey). It is included in the payload EtM tag and in the header_mac so that tampering can be detected.
- `hash` (Bao root): The content identifier for the *final processed form* of this segment under the chosen Format combination. Its meaning is multi-dimensional depending on which of the 16 format pipelines was applied.
- `slh_public_key` (32 bytes): A *public* key by definition. It is here so that verifiers can find the correct public key that corresponds to a detached SLH-DSA signature over the *encrypted container* (via its Bao root hash). See §2.3 for why we sign the encrypted object rather than the plaintext.
- `format`, `chunk_index`, `encoded_len`, `padding_len`, `metadata`: All operational metadata required to correctly process the body. None of these values are secret.

**What is NEVER in the Header (or anywhere in the container):**
- The 32-byte master key.
- Any derived subkeys (aes-ctr key material, etm-hmac key, header-auth key).
- Any plaintext or decrypted content.

**Security implication**: An observer who sees only the Header learns the Bao hash, the format bits, the chunk index (if sharded), approximate size, and (if present) which SLH-DSA public key will verify a sidecar signature. They learn nothing that helps them decrypt the payload. The `header_mac` ensures they cannot undetectably tamper with any of those fields.

This model is intentional and matches standard practice for encrypted container formats (LUKS2 header, age, cryptsetup, etc.). The design keeps the header small, parseable without the key, and useful for deduplication / routing while still binding it cryptographically to the master key via the header_mac.

Violating the rule "no secret key material ever appears in the Header or any other unauthenticated location" would be a critical bug.

#### `header_mac` is an authentication tag, not a secret (common misconception)

The 64-byte `header_mac` field **is stored in the cleartext header on disk** (bytes 28–91 of the 177-byte wire layout). This is **correct and intentional**.

| Concept | Secret? | Role |
|---------|---------|------|
| Master key (32 B) | **Yes** — never on disk | Root of all subkey derivation |
| `header-auth` subkey (64 B derived) | **Yes** — never on disk | HMAC key for header metadata |
| `header_mac` (64 B tag) | **No** — public like any MAC/AEAD tag | Proves `auth_data` was not tampered with under the master |
| `payload_nonce` (16 B) | **No** — public in CTR/AEAD designs | Unique IV for AES-CTR; useless without AES subkey |
| Payload EtM tag (64 B, in body when encrypted) | **No** — prepended to ciphertext | Proves body integrity under `etm-hmac` subkey |

**Why storing the MAC in the header is safe:** HMAC outputs are pseudorandom tags, not key material. Knowing `header_mac` does not let an attacker recover the master key, derive subkeys, or forge a valid tag for *modified* metadata without possessing the master key. Forgery resistance follows from the PRF property of HMAC-SHA512 under a secret `header-auth` subkey.

**What would be a critical bug:** placing the master key, any derived subkey, or plaintext inside the header (or anywhere unauthenticated).

#### Two-layer integrity model (header vs body)

Carbonado uses **separate** authentication for metadata and payload:

```text
Layer 1 — Header MAC (metadata):
  header_mac = HMAC-SHA512(header-auth subkey, auth_data)
  Verified in file::decode before any body processing.

Layer 2 — Payload EtM (body, when Encrypted bit set):
  tag = HMAC-SHA512(etm-hmac subkey, "carbonado-v2-etm" || nonce || ciphertext)
  Verified before AES-CTR decryption.

Layer 3 — Keyed Bao (body, when Bao bit set):
  Merkle root keyed on format byte; slice verify without full decode.
  Independent of header MAC; binds processed body to format pipeline.
```

Layers can combine. An encrypted+verifiable archive (e.g. c5, c15) uses header MAC + payload EtM + keyed Bao.

#### Threat model by master-key scenario

**Encrypted archive with a secret high-entropy master key**

- Header and `header_mac` are world-readable; payload ciphertext is opaque.
- Attacker cannot decrypt without the master key.
- Attacker cannot undetectably alter header fields (format, lengths, Bao hash, chunk index) — MAC verify fails.
- Attacker learns routing metadata (size, format, outer hash) — by design for storage/indexing.

**Public / unencrypted archive with conventional zero master (`[0u8; 32]`)**

- The CLI and library default to all-zero master when `--master` is omitted (public formats only).
- Anyone can compute valid `header_mac` values for metadata they choose, because the “key” is public.
- Header MAC is then **consistency checking for tooling**, not anti-malicious protection against strangers.
- For public verifiable formats (c4–c7, c12–c14), **body integrity** against third parties relies on **keyed Bao** (and FEC), optionally **SLH-DSA sidecars** for long-term authenticity — not on header MAC secrecy.

**Implication for system designers:** If you need metadata integrity verifiable by third parties without sharing a symmetric master, use SLH-DSA (or another asymmetric signature) over the Bao root or a manifest — not encryption of the header MAC field.

---

### Subkey Label Registry (normative)

All HMAC-SHA512 subkeys use: `HMAC-SHA512(master, "carbonado-v2/" || label)` → 64 bytes.

| Label | Scope | Usage |
|-------|-------|-------|
| `aes-ctr` | Master-key derived | First 32 bytes → AES-256-CTR key for payload encryption |
| `etm-hmac` | Master-key derived | Full 64 bytes → HMAC-SHA512 key for payload EtM |
| `header-auth` | Master-key derived | Full 64 bytes → HMAC-SHA512 key for Header `header_mac` |
| `ecc-chacha-poly` | **Hybrid only**: ECDH shared secret bytes as PRF input (not master key) | First 32 bytes → ChaCha20-Poly1305 key for inner AEAD blob |
| `slh-dsa-seed` | Convenience wrapper (`slh_sign` only) | First 64 bytes of stretched entropy for SLH-DSA keygen |
| `slh-dsa-seed-2` | Convenience wrapper (`slh_sign` only) | Second 64 bytes of stretched entropy for SLH-DSA keygen |

**Not HMAC subkeys (separate KDF):**

| Context string | KDF | Usage |
|----------------|-----|-------|
| `carbonado-v2/verification` | `blake3::derive_key("carbonado-v2/verification", &[format_byte])` | 32-byte keyed-Bao BLAKE3 key; public API: `crypto::carbonado_verification_key` |

**Payload EtM domain (not a subkey label):**

| String | Usage |
|--------|-------|
| `carbonado-v2-etm` | Prepended to EtM MAC input: `HMAC-SHA512(etm-hmac subkey, "carbonado-v2-etm" \|\| nonce \|\| ciphertext)`. Kept because payload blobs have no natural Carbonado header prefix (distinct from header MAC, which binds via leading `MAGICNO` in `auth_data`). |

No other labels or domain strings may be used without updating this registry and the implementation.

### Header MAC construction (normative summary)

```text
header_mac = HMAC-SHA512( derive_subkey(master, "header-auth"), auth_data )
auth_data  = MAGICNO || payload_nonce || bao_hash || slh_public_key || format
             || chunk_index_u32_le || encoded_len || padding_len || metadata
```

### Payload EtM (normative summary)

```text
tag = HMAC-SHA512( derive_subkey(master, "etm-hmac"), "carbonado-v2-etm" || nonce || ciphertext )
```

Implemented in `crypto.rs` (`symmetric_*`) and `stream/crypto_stream.rs` (streaming paths). Tag verified before decryption.

### Keyed Bao KDF (normative summary)

```text
bao_key = blake3::derive_key("carbonado-v2/verification", &[format_byte])
root    = keyed BLAKE3 Merkle root over processed body (4 KiB leaves, `BAO_BLOCK_SIZE`)
```

Separate from HMAC subkeys. Roots commit to the exact format pipeline (c0–c15). See `tests/bao_keyed_contract.rs`.

### Hybrid paranoia layer (normative summary)

Optional defense-in-depth APIs in `crypto.rs` (`ecc_aead_*`, `hybrid_*`):

1. **Inner**: Ephemeral secp256k1 ECDH → shared secret → `derive_subkey(shared_secret, "ecc-chacha-poly")` → ChaCha20-Poly1305 AEAD.
   - Inner blob layout: `[33-byte compressed eph pubkey | 12-byte nonce | ciphertext+poly1305 tag]`
2. **Outer**: Inner blob treated as plaintext → `symmetric_encrypt_with_nonce(master, outer_nonce, inner_blob)` (AES-256-CTR + HMAC-SHA512 EtM under master-derived subkeys).
3. **Encrypted bit semantics**: High-level `file::encode` with `Encrypted` set uses **pure symmetric only**. Hybrid replaces the encrypt step explicitly; callers typically leave `Encrypted` clear and pass hybrid output through FEC/Bao. Master key still protects outer EtM and `header_mac`.
4. **Verification order**: Outer EtM verified first; inner AEAD only on outer success.

### SLH-DSA sidecar wire format

- File naming convention: `<bao-root-hex>.cXX.slh`
- On-disk layout (7860 bytes total):
  - 4 bytes: `b"SLH1"` (`SLH1_MAGIC`)
  - 7856 bytes: raw SLH-DSA-SHA2-128s signature (`SLH1_SIGNATURE_LEN`)
- Public key **not** in sidecar — stored in `Header.slh_public_key` (32 bytes).
- Library helpers: `crypto::write_slh_sidecar`, `crypto::read_slh_sidecar`.

### OTS stub limitations (`ots` feature)

`ots::stamp_bao_root` / `verify_stamp` produce deterministic offline proofs (`CBOTSv1\0` magic inside a DER-like envelope). **Not production OpenTimestamps** — no network calendar submission. Suitable for CI, tests, and offline Bao-root binding until a real calendar client is integrated. See `src/ots.rs` rustdoc.

---

## 2.1 Cryptographic Security Model — First Principles and Invariants

This section provides the rigorous reasoning behind the v2 design. All implementation decisions must be justifiable against these arguments.

### 2.1.1 Bulk Encryption: AES-256-CTR

**Primitive**: AES-256 in Counter mode (CTR), using `Ctr128BE<Aes256>` from the RustCrypto `ctr` crate.

**Security Goal**: Confidentiality (IND-CPA).

**Reasoning**:
- CTR mode turns a block cipher into a stream cipher by encrypting a counter (nonce || counter).
- Security reduction: AES-256 is a pseudorandom permutation (PRP). When the nonce is never reused under the same key, the keystream is indistinguishable from random (under standard assumptions).
- **Critical Invariant**: The 16-byte nonce **must** be unique for every encryption performed under a given master key (across all time and all segments). Violation leads to keystream reuse, which is catastrophic (plaintext recovery via XOR).

**Why CTR instead of other modes** (per LUKS2-inspired design discussions):
- True length preservation (no expansion for the ciphertext itself).
- Excellent parallelism (every block is independent) → optimal AES-NI/VAES utilization on modern CPUs (Zen 5, etc.).
- Precomputable keystream in some pipelines.

**Quantum Note**: Grover's algorithm gives a quadratic speedup against brute-force. AES-256 retains ~128-bit post-quantum security against key search.

### 2.1.2 Authentication & Integrity: Full HMAC-SHA512 (EtM)

**Construction**: Encrypt-then-MAC (EtM) using `Hmac<Sha512>` (full 64-byte output, **never truncated** in the current design).

**Tag Placement**: The 64-byte tag is prepended to the ciphertext in the encrypted blob:
`[64-byte HMAC tag] [ciphertext]`

**Domain Separation String**: `b"carbonado-v2-etm"`

**Security Goals**:
- Integrity (INT-CTXT — ciphertext integrity)
- Authenticity
- Prevention of chosen-ciphertext attacks when combined with CTR

**Why full 64-byte HMAC-SHA512 (not truncated, not HMAC-SHA256)**:
- Matches the explicit design requirement from the LUKS2 reference ("upgrade to HMAC-SHA512").
- Provides 256-bit collision resistance in the tag.
- HMAC-SHA512 is the same primitive used for subkey derivation → implementation simplicity and analysis reuse.
- Truncation would weaken the "all authentication and integrity checks" mandate in the original spec.

**Why EtM (not MAC-then-Encrypt or Authenticated Encryption with Associated Data in other forms)**:
- EtM has the strongest provable security properties when the MAC is a secure PRF (HMAC-SHA512 is believed to be one).
- The MAC covers the nonce + ciphertext, binding them together.

**Critical Invariant**: The MAC **must** be verified before any decryption or further processing. Failure must result in an immediate `AuthenticationFailed` error with no partial output.

### 2.1.3 Key Derivation and Separation: HMAC-SHA512 (BIP-32 Style)

All key material separation is performed with:

```rust
I = HMAC-SHA512(master, "carbonado-v2/" || label)
```

Current registered labels (must be kept in sync with code — full table in **Subkey Label Registry**):
- `aes-ctr`, `etm-hmac`, `header-auth` (master-key derived)
- `ecc-chacha-poly` (hybrid inner AEAD)
- `slh-dsa-seed`, `slh-dsa-seed-2` (SLH convenience only)

**Rationale**:
- HMAC-SHA512 is a secure PRF under standard assumptions.
- Using the same primitive as the EtM MAC reduces the trusted computing base and analysis surface.
- The BIP-32-style construction (prefix + label) provides strong domain separation.
- Different labels produce independent 64-byte outputs → no key reuse across roles even if the master is the same.

**Key Independence Invariant**: Compromise of one derived key (e.g., the header MAC key) must not help an attacker recover the AES key or the EtM key.

### 2.1.4 Nonce Handling

**Current Rule**: The 16-byte nonce is generated randomly at the high-level `file::encode` layer (when encryption is enabled) and passed to `symmetric_encrypt_with_nonce`.

**Invariants**:
1. The nonce must be unique per (master_key, encryption operation).
2. For the high-level file path, the nonce is stored in the `Header` so that `file::decode` can use the exact same nonce with `symmetric_decrypt_with_nonce`.
3. The low-level `encoding::encode` path (used directly in some tests and streaming scenarios) still generates its own random nonce internally for backward compatibility of that API surface.

**Why random (not deterministic from content)**:
- Matches the behavior of the previous ECIES layer (non-deterministic ciphertexts).
- Stronger protection against related-key or pattern attacks in some scenarios.
- Simpler to implement correctly with a good RNG.

### 2.1.5 Overall Design Invariants (Must Never Be Violated in Code)

1. **Clean Break Invariant**: No code path may successfully decrypt or verify a v1 ECIES container. Any attempt must fail early and clearly.
2. **Key Separation Invariant**: All cryptographic keys used for different purposes (AES keystream, EtM tag, header MAC) must be derived via distinct labels through `derive_subkey`.
3. **MAC Before Decrypt Invariant**: The EtM tag must be verified successfully before any keystream is applied or plaintext is returned.
4. **Header MAC Invariant**: The `header_mac` must be verified (using the `header-auth` subkey) before trusting any metadata in a v2 `Header`.
5. **Nonce Uniqueness Invariant**: The implementation must never reuse a nonce under the same master key for encryption.
6. **Content vs. Container Invariant (multi-dimensional)**: The outer Bao hash always names the *final processed form* of the data after applying the selected Format pipeline (any combination of Zstd(level 20) + encryption + FEC + Bao). 

   **Important architectural detail**: The Bao root hash is computed **only over the body** (the bytes after all chosen transformations). The `Header` (including the `format` bitmask byte, `payload_nonce`, lengths, `slh_public_key`, etc.) is constructed *after* the hash and prepended on disk. Therefore the Bao hash does **not** cryptographically commit to any header fields, including the format bits that determined how the body was created.

   The only cryptographic binding of the format byte to the rest of the metadata is the `header_mac` (HMAC-SHA512 under the `header-auth` subkey). This is an authenticity/integrity MAC, not a content hash.

   **Could the Bao hash commit to the format (or more of the header)?**
   - It is architecturally possible, but it would require changing the current separation between header and body.
   - Common approaches include: (a) feeding a small prefix containing the format byte + other metadata into the Bao tree before the processed data, or (b) treating the root hash as the hash of a tiny manifest that includes the format.
   - Trade-offs: This would bind the processing parameters more tightly into the content identifier (useful for the multi-dimensional naming and market use cases discussed above), but it complicates the clean separation of the authenticated header and may affect streaming slice extraction properties.
   - Current design deliberately keeps the Bao tree over the raw processed bytes for maximum compatibility with the Bao library's streaming verification model.

   **Keyed Bao idea (explored 2026 session)**
   - Suggestion: Use a keyed variant of the Bao tree (keyed on the format bitmask byte, or a small header prefix) so that the root hash cryptographically commits to which processing pipeline was used.
   - This would be extremely useful for data markets (see §9), because different format combinations (especially encrypted vs public) would produce distinguishable roots even for related data.
   - **Endianness for key material**: All integer fields in Carbonado (and in the Bao format itself) are little-endian. If a keyed Bao implementation derives a 32-byte key from header fields, those fields should be serialized in LE order for consistency. A minimal implementation that only keys on the single-byte `format` bitmask has no endianness issues at all.
   - (Implemented) Original `bao` 0.13 lacked BlockSize and public keyed. Now using local SurmountSystems/bao-tree fork with BlockSize(2) for 4KB + keyed_hash on format byte (root commits to pipeline). See constants::BAO_BLOCK_SIZE and encoding::bao. Temporary fork pending upstream.

   Because there are 16 possible format combinations, the same logical input can produce up to 16 different Bao hashes. In this sense the naming is **multi-dimensional**:
   - When the `Encrypted` bit is set (symmetric encryption), the hash primarily names an *encrypted+protected container*.
   - When the `Encrypted` bit is clear (especially with `Bao`), the hash can legitimately function as a content-addressable identifier for that specific transformed view of the data (e.g. compressed + erasure-coded + verifiable form).

   SLH-DSA sidecar signatures are over whichever Bao root hash corresponds to the chosen format combination for that segment. The signature therefore attests to a particular (data + format pipeline) tuple. See §2.3 for more detail on the implications for "CID-like" usage and DDoS resistance.
7. **Chunk Index Width Invariant**: `chunk_index` is a full u32 (0..=u32::MAX). This enables sharding of extremely large logical files while keeping each segment independently verifiable and decryptable. Per-segment size is now limited only by the u32 `encoded_len` / `bytes_verifiable` fields in the Header and EncodeInfo (for both FEC and non-FEC paths). The previous artificial u16 slice-count caps have been removed (see "u32 Widening of Slice Verification" below).

### u32 Widening of Slice Verification (2026 session)

Per user request ("Yes, let's do that. u32."), the last remaining artificial u16 bookkeeping related to Bao slice counts and indices was widened:

- `EncodeInfo.verifiable_slice_count` and `chunk_slice_count`: `u16` → `u32`
- `extract_slice(index, hash, format)`, `verify_slice(index, count, hash, format)`: `u16` → `u32` (P1: keyed; require format byte + root hash)
- Internal arithmetic in `scrub`
- `InvalidVerifiableSliceCount` error payload

`SLICE_LEN` is `u32 = 4096` (one 4 KiB Bao leaf; P1 clean break from 1 KiB slices).

**Result**:
- FEC-protected segments are now limited only by the existing u32 length fields (~4 GiB verifiable per segment).
- With u32 slice indices, the theoretical verification range is ~4 TiB (far beyond what the Header lengths allow).
- The ~64 MiB cap that existed for c8–c15 formats is gone.

The change was made while still in the active 0.7 development series of the v2 cryptographic redesign (clean break), so it is treated as normal completion work rather than a post-stability semver event.

All previous "Remaining u16 Bookkeeping Limits" text has been superseded by this widening. Slice indices/counts are `u32`; `SLICE_LEN` is `u32 = 4096`.

These invariants are more important than any particular performance optimization.

### 2.1.6 Quantum Resistance Posture

- Symmetric primitives (AES-256-CTR + HMAC-SHA512): Grover gives only quadratic speedup → still strong (~128-bit security).
- Post-quantum signatures: Provided via `bitcoinpqc` (SLH-DSA / SPHINCS+) as **sidecar** signatures only. This matches the project's broader Bitcoin quantum-resistance mission (BIP-360 related work).
- No attempt is made to make the per-segment encryption itself post-quantum (that would require much larger overhead and different primitives). The design philosophy is "quantum-resistant where it matters most for the Surmount mission" (signatures for long-term authenticity) while keeping the bulk encryption efficient and hardware-accelerated.

---

## 3. What "Preserving Existing Capabilities" Means

We keep:
- Zstd (level 20) compression (optional)
- Forward error correction (RS 4/8)
- Bao streaming verification + slice extraction
- Format bitmask: the `Encrypted` variant (lowest bit) controls symmetric encryption. The bit position is deliberate so that even numeric format values indicate unencrypted data (easier for markets and tools to filter).
- WASM support
- Single flat-file model
- P2P/S3/HTTP compatibility at the storage layer

We do **not** keep:
- Any ability to decrypt old ECIES containers
- The old 160-byte ECIES header format for new files
- The `ecies` crate or its direct dependencies for encryption paths

---

## 4. Development Workflow & Discipline

### Task Tracking (Mandatory)
- Use the `todo_write` tool for all non-trivial work.
- Mark items **in_progress** one at a time.
- Only mark an item **completed** when it is fully done (tests green, clippy clean, relevant docs updated).
- Never batch completions.

### Code Changes
- Prefer small, reviewable changes.
- Every cryptographic change must be accompanied by reasoning in the commit message or a note in this file.
- Run `cargo clippy --lib -D warnings` and `cargo test` before considering a task done.

### Documentation
- `AGENTS.md` is the single source of truth for agents and future developers.
- Major design decisions, hard scope rules, and lessons from friction belong here immediately.
- Update this file (especially the "Critical Rules to Avoid Previous Friction" section) whenever the same class of misunderstanding occurs.
- When in doubt about scope (especially around "clean break" vs. legacy support), re-read sections 1 and the "Critical Rules" section before proposing options or writing code.

### CHIPs
- Normative specification work happens in the separate CHIPs repository (bitmask-stack/CHIPs or equivalent).
- This repo tracks a summary table (see section below) but does not author the official CHIPs.

---

## 5. Testing & Verification Expectations

- New crypto primitives must have direct unit tests (roundtrips, authentication failures, subkey independence, nonce handling).
- End-to-end tests must only exercise the new symmetric path.
- WASM lint (`cargo clippy --target wasm32-unknown-unknown`) must stay clean.
- Hardware acceleration behavior should be documented and (where practical) measured.

---

## 6. WASM / Browser Notes

- All new crypto crates were chosen with WASM compatibility in mind.
- Consumers using the library in the browser must enable the `js` feature on `getrandom` for randomness (nonce generation).
- High-memory Argon2id parameters can be problematic in browsers — document recommended parameters for client-side use.

---

## 7. CHIPs Tracker (Summary)

| Topic                              | Status     | Location / Owner          | Notes |
|------------------------------------|------------|---------------------------|-------|
| v2 Container Header Format         | Impl complete (2.0.0); CHIP deferred | AGENTS.md §2, `src/structs.rs` | 177-byte symmetric header; normative in-repo |
| Nonce & Subkey Derivation Details  | Impl complete (2.0.0); CHIP deferred | AGENTS.md §2.1 | HMAC-SHA512 labels; security arguments in AGENTS |
| SLH-DSA Sidecar Nomenclature       | Impl complete (2.0.0); CHIP deferred | AGENTS.md §2.3, `src/crypto.rs` | Sidecars only; `SLH1` magic |
| Migration Guidance (External)      | Impl complete (2.0.0); CHIP deferred | AGENTS.md §1 | Clean break; no v1 ECIES decode |
| Argon2id Parameter Recommendations | Superseded | 2026 session              | Removed from library; caller responsibility for KDF |
| Test Matrix (linux + wasm + others) | Completed | 2026-05-30                | Explicit CI matrix: native, musl, aarch64, wasm32 (pqc on/off) |
| v2.0 FEC Replacement (zfec -> reed-solomon-erasure) | Completed | 2026                      | RS 4/8 (k=4 data, 4 parity); det encode; tolerates any 4/8 shards (50% aligned); scrub combo search for distributed taints; see CHANGELOG.md and code |
| Inboard / Outboard Modes           | Completed  | 2026 (this run)           | High-level file:: + scrub_outboard + low-level; bare public + sidecars (.cXX.out/.par); header out-of-band for public. See CHANGELOG.md and code. |
| Carbonado 2.0 Magic + Version Bump | Completed  | 2026                      | New MAGICNO (CARBONADO20\n), crate 2.0.0; fluid dev period ended. See CHANGELOG.md and status block above. |
| Adamantine Directory Catalog v1.0   | Impl complete (2.1.0); CHIP deferred | carbonado 2.1.0 | Adamantine 1.0 + bundled Bao + heterogeneous segments; see §7.1 |
| Unified `carbonado` CLI (file + dir) | Completed | carbonado 2.0.0            | `encode`/`decode` routes `.adam.c14`/`.adam.c15`; `--encrypted` for c15; see §7.1 |

Update this table as work progresses. The real normative text lives in the CHIPs repo.

### 7.1 Adamantine Directory Catalog v1.0 (impl complete in-repo; CHIP deferred)

Implementation is complete in this repository (carbonado 2.1.0 directory redesign). External CHIP normative text drafting is explicitly deferred; behavior below reflects the shipped code. **Clean break:** dev `ADAMANTINE2\n` archives are rejected; nothing was published.

Directory archives use **catalog format c14/c15 only** (public/encrypted). Per-file segments are **heterogeneous** c12/c14 (public) or c13/c15 (encrypted) selected by [`directory/format_policy`](src/directory/format_policy.rs) (`infer` heuristic: compressible → c14/c15, incompressible → c12/c13). Legacy c4–c7 segment formats are rejected at encode/decode.

**Adamantine wire envelope** (`src/adamantine.rs`):
- Magic: `ADAMANTINE10\n` (13 bytes; version 1.0 encoded in magic, like `CARBONADO20\n`)
- `ADAMANTINE1\n` / `ADAMANTINE2\n` rejected → `UnsupportedAdamantineVersion`
- Header length: **19 bytes** (`ADAMANTINE_HEADER_LEN`)
- `carbonado_fmt`: `0x0E` (c14) or `0x0F` (c15) — catalog encryption only
- Flags: **u8** — bit 0 `REQUIRE_OTS` only (bits 1–7 reserved, must be zero → `InvalidAdamantineFlags`)
- No separate version bytes; no `ENCRYPTED`/`SHARDED`/`INBOARD`/`CENTRALIZED_BAO` flags (layout is normative for v1.0)

```text
Offset  Size  Field
0       13    magic            ADAMANTINE10\n
13      1     carbonado_fmt    0x0E | 0x0F
14      1     flags            u8 (bit0 REQUIRE_OTS = per-entry proofs required at decode; bits 1–7 reserved, must be 0)
15      4     payload_len      u32 LE
19      N     payload          see adamantine_payload
```

**Adamantine payload** (`src/adamantine_payload.rs`):
```text
[u32 LE rkyv_len][rkyv FilepackManifestWire][u32 LE bundle_len][per-segment verification_outboard + fec_parity blobs]
```
- DoS caps: `MAX_RKYV_PAYLOAD_LEN`, `MAX_BAO_BUNDLE_LEN`, `MAX_ADAMANTINE_PAYLOAD_LEN`
- Optional future `u8` bundle version byte documented for streaming; v1 omits it

**FilepackManifest v2** (`src/filepack_manifest.rs`):
- `FILEPACK_MANIFEST_VERSION = 2`; v1 rejected
- `format_level` = **catalog only** (c14 or c15); validated on decode
- `FilepackEntry.segment_format` per entry (c12/c14/c13/c15); encode-time policy checks return `SegmentFormatMismatch`; decode maps wire violations to `InvalidFilepackManifest`
- `SegmentRef.verification_outboard_offset` / `verification_outboard_len` and `fec_parity_offset` / `fec_parity_len` index into Adam payload bundle (0/0 FEC fields when absent)
- `catalog_bao_root` **not** in rkyv wire; bound from `.adam.c14`/`.adam.c15` filename via keyed Bao verify
- `catalog_ots_proof` on API struct only — stored in **COTS file trailer** after inboard catalog bytes (does not affect Bao root)
- Per-entry `ots_proof` in rkyv when `OtsPolicy.stamp_entries`; `REQUIRE_OTS` flag set when entry stamping enabled
- `REQUIRE_OTS` applies to **entry proofs only**; catalog proof verified when present in COTS trailer
- Legacy CBOR `filepack` (`src/filepack.rs`) remains **interop only**

**Directory archive layout (fixed v1.0):**
- **Catalog:** inboard headered `{catalog_root}.adam.c14` or `.adam.c15` (`CARBONADO20\n` + body); no `.out`/`.par`
- **Segments:** bare mains `{seg_root}.c12`/`.c14`/`.c13`/`.c15` only; verification outboard + FEC parity centralized in Adam payload bundle
- **No** directory `.out`, `.par`, or `.ots` sidecar files
- **Scrub:** directory segments are FEC-capable (c12–c15). Slice verification + FEC parity from the centralized bundle; `scrub_outboard` recovers corrupt bare mains within the RS 4/8 budget (≤4 shard taints). `MissingFecParity` when `Format::Fec` is set, `main_len > 0`, and `fec_parity_len` is zero (zero-byte mains use empty FEC slice at decode).
- **Decode extract:** `decode_directory` requires an empty or trusted output tree; see `file::decode_directory` rustdoc (TOCTOU if `outdir` contains symlinks).
- Catalog optional OTS: `[COTS][u32 LE len][proof]` appended after inboard catalog file bytes

**Directory decode error taxonomy:** reserve `InvalidFilepackManifest` for rkyv wire + semantic validation (including `segment_format` vs catalog encryption mismatches on decode). `SegmentFormatMismatch` is **encode-time only** (policy / `DirectoryEncodeOptions`). Other decode variants: `InvalidAdamantineFlags`, `SegmentMainLenMismatch`, `ContentBlake3Mismatch`, `DirectoryLayoutMismatch` (non-inboard catalog or headered segment mains), `CatalogBaoRootMismatch`, `OtsProofRequired` (entry), `OtsVerificationFailed`, `InvalidOtsProof`.

**Streaming + sharding:** large files shard via `encode_file_segments` / budget in `DirectoryEncodeOptions.segment_plaintext_budget` (default `DEFAULT_SEGMENT_PLAINTEXT_BUDGET`). Segment decode uses `decoding::decode_outboard` with verification + FEC parity slices from bundle.

**On-disk naming (directory mode)** — decimal suffixes:
- Catalog: `{catalog_bao_root_64hex}.adam.c14` or `.adam.c15`
- Segments: `{segment_bao_root_64hex}.c12`/`.c14`/`.c13`/`.c15` (heterogeneous per file)

**Single-file CLI** continues hex suffixes: `{hash}.c{format:02x}` (e.g. `.c0e` for format 14).

**Unified `carbonado` binary (directory):** `encode <dir>` defaults output to `{input}-archive/` (never `.`); `-o` required or uses that default. `--encrypted` for c15; no directory `--inboard`/`--outboard`/`--format`. `decode` routes `.adam.c14`/`.adam.c15` to `decode_directory`.

### 7.2 CLI key material handling (`src/bin/carbonado.rs`)

The `carbonado` binary is a thin wrapper over the library. It does **not** implement passphrase KDF, key files, or HSM integration. Key handling is deliberately minimal.

#### Input: `--master <64 hex chars>`

| Behavior | Detail |
|----------|--------|
| Format | Exactly 64 hexadecimal characters → 32 bytes (`parse_master`) |
| Omitted | Defaults to **`[0u8; 32]`** (all zeros) — valid for public/unencrypted formats |
| Required | When `Encrypted` bit is set (format odd: c1, c3, …, c15) or `--encrypted` directory mode |
| Rejected | All-zero master on encrypted paths (`reject_zero_encrypted_master`) |
| Not supported | Passphrases, key files, env vars, stdin prompts |

#### In-process lifetime

1. Clap parses `--master` into a `String` (hex digits live in heap until dropped).
2. `parse_master` decodes into a stack-allocated `[u8; 32]`.
3. The key is passed by reference (`&[u8; 32]`) into `encode_stream`, `decode_stream`, `encode_directory_with_options`, `stream_decode_outboard`, etc.
4. **The binary does not call `zeroize` on the key array or the hex `String` when the command finishes.** Secrets may remain in process memory until overwritten by the OS allocator.

#### Operational security implications (operator responsibility)

| Risk | Mitigation |
|------|------------|
| Shell history / `ps` argv exposure | Prefer env-file wrappers, `read -s`, or a small helper that KDFs a passphrase and execs with minimal argv visibility |
| Swap / core dumps | Use `mlock`/`zeroize` in your wrapper; the CLI does not mlock |
| Shared CI runners | Do not pass production keys on the command line in logs |
| Public archives | Omitting `--master` is intentional (zero key); see threat model above |

#### Library contract vs CLI

- **Library:** Accepts `&[u8; 32]` per call; does not retain caller keys after return. AGENTS §2.4: passphrase→key is caller responsibility (Argon2id recommended).
- **CLI:** Only hex master keys; no KDF. For production, derive a 32-byte key in your application and pass hex to `--master`, or call the library API directly with a zeroized buffer.

#### Directory vs single-file

- **Single-file encrypted:** `--format` with `Encrypted` bit + `--master` required.
- **Directory encrypted (c15):** `--encrypted --master` required; per-segment keys use the same master; directory outboard uses **embedded nonce** in bare mains (not header-path nonce per segment). See §7.1 directory encrypted outboard contract.

---

## 8. Hardware & Performance Notes

Target hardware (as referenced in design discussions):
- AMD Ryzen AI 7 PRO 350 (Zen 5) with full AES-NI + VAES and SHA extensions.
- LUKS2 reference configuration (`aes-xts-plain64` + `hmac-sha256` + `argon2id`) is the philosophical north star for the symmetric encryption + integrity layer, adapted to a portable flat-file container. Passphrase-to-key derivation (Argon2id etc.) is left to the caller / higher layer.

Benchmarks should be run with `RUSTFLAGS="-C target-cpu=native"` to observe acceleration.

---

## 9. Data Markets, Replication Incentives, and the Signal/Noise Problem (Open Consideration)

This section documents a fundamental tension that arises when Carbonado is used in decentralized storage markets (see https://github.com/bitmask-stack/carbonado/issues/10).

### The Core Problem

In a healthy storage market, price and incentives should favor **long-term replication of unique, valuable data** ("signal") over redundant or low-value bytes ("noise").

Carbonado's design creates several distortions:

- The 16 format combinations produce different Bao root hashes for the same logical input. The outer hash is therefore multi-dimensional — it names a specific `(data + processing pipeline)` tuple rather than raw content.
- When the `Encrypted` bit is set, the resulting blob is deliberately opaque. Storage providers and market mechanisms cannot easily determine:
  - Whether two encrypted blobs contain the same logical data (deduplication becomes impossible without the key).
  - The "value" or uniqueness of the underlying content.
- The bitmask was deliberately ordered with `Encrypted` as the lowest bit so that unencrypted format values are even. This was an intentional design choice to make it trivial for markets and tools to filter for variants where content is inspectable.
- Even in non-encrypted pipelines, compression + Zfec + Bao create transformed representations whose hashes do not directly reveal logical uniqueness to third parties.

The result: a market built purely on Carbonado containers may end up pricing and incentivizing storage of encrypted noise or redundant encrypted copies, while truly unique/valuable plaintext receives insufficient replication.

### Current Design Stance

Carbonado prioritizes:
- Strong privacy for the data owner.
- Durable, verifiable storage of *containers* (via Bao + Zfec + sidecar signatures).
- A clean separation between the container layer and higher-level concerns.

**Markets and the Encrypted bit** (important clarification): Decentralized storage markets that want to price and incentivize replication based on unique valuable content can only do so effectively on variants where the `Encrypted` bit is **off**. When the bit is set, the data is intentionally opaque to the market. This is by design — Carbonado prioritizes owner privacy over market transparency for encrypted data.

Higher-level structures (signed manifests, catalogs, or "data market descriptors") are the natural place to:
- Declare that multiple Carbonado segments contain related or identical logical content.
- Specify target replication factors for *logical* data.
- Allow markets to price based on uniqueness and value signals that the low-level containers deliberately hide.

### Open Questions / Tensions

- How can a market obtain credible signals of "uniqueness" or "value" without compromising the privacy/durability goals of the container format?
- Should there be recommended "public" format combinations (no encryption) specifically intended for data that wants to participate in transparent replication markets?
- Can higher-level manifests + SLH-DSA signatures provide enough structure for markets while keeping the individual containers private and self-contained?
- Is some form of optional, privacy-preserving uniqueness proof (e.g., via commitments or zero-knowledge techniques) desirable in the future?

This tension is acknowledged but not resolved in the current design. Carbonado is optimized first as an **apocalypse-resistant archival container**, with market incentive compatibility treated as a higher-layer concern.

---

## 10. Current Rough Edges (as of this writing)

**Updated post v2.0 outboard + polish (TDD/docs/gate work):**

Remaining open (documented; active work called out):
- **Pipeline memory residual (hard-break track):** fused encode/decode is O(chunk) spool + O(stripe) FEC encode; non-FEC verification decode is O(chunk) via `SeekWriteAt`; FEC verification decode retains O(FEC body) shard buffers (`FecInboardWriteAt`); outboard verify uses `PostOrderOutboard` + `ReadAt` (O(hash pair) per node); `stream_decode_async` fully spools encoded body to disk. Distinct from Bao **slice** verification (already O(slice) memory). See [doc/STREAMING_PARALLELISM.md](doc/STREAMING_PARALLELISM.md).
- **WASM:** `cargo clippy --target wasm32-unknown-unknown --no-default-features` is green (CI `lint-wasm`). **wasm32 + `pqc` probe (2026-07-08):** pointing global `CC_wasm32-unknown-unknown` at `libbitcoinpqc-bindings/wasm/clang-wasm32.sh` breaks **`zstd-sys`** (it tries to assemble `huf_decompress_amd64.S` with the wasm clang). Residual is build-env / dep CC scoping — not Carbonado crypto logic. Keep CI wasm lint **no-pqc** until bitcoinpqc (or zstd) wasm build is isolated.
- Bao crate: Surmount keyed bao-tree fork (`76-keyed-bao`), 4 KiB groups, `default-features = false` (no tokio/fs on wasm). Temporary until upstream.
- reed-solomon-erasure: upstream "looking for maintainers"; periodic re-eval (no runtime issues).
- (Perf: inboard `verify_slice` is O(slice) memory but O(N) encoded-byte I/O; outboard slice verify is O(slice) time+memory; scrub pre-check uses `verify_inboard_keyed` with O(1) retained decode memory (S5).)

Addressed in this polish pass (removed from active list):
- Header::new clippy allow + comments.
- Zeroization documentation.
- chunk_index=0 high-level behavior docs.
- .expect() in symmetric hot paths (replaced; TDD coverage test added).
- AGENTS rough edges list + §11 pruning (periodic hygiene).

See prior entries in git history for full context of resolved items.

All core cryptographic requirements from the original Surmount spec (symmetric AES-256-CTR + full HMAC-SHA512 EtM, SLH-DSA sidecars only, clean break, u32 chunk support, etc.) are now implemented and verified. Argon2id passphrase KDF was deliberately removed; callers derive high-entropy master keys outside the library (Argon2id recommended for passphrases).

---

**Last updated:** Post outboard completion + v2.0 final polish/gate (docs, TDD on rough edges like expect/Header/clippy, AGENTS prune, README expand, tests/clippy/fmt). See CHANGELOG.md + this §10 for status. (4KB keyed Bao, RS FEC, 2.0 magic stable.)

Major items completed in this session:
- Full symmetric v2 stack (AES-256-CTR + 64-byte HMAC-SHA512 EtM, header_mac, subkey derivation). Argon2id passphrase helper removed (callers must derive high-entropy master keys themselves).
- Real bitcoinpqc SLH-DSA (keygen/sign/verify + convenience wrappers) as sidecars only
- SLH-DSA public key moved into main `Header` (signature remains sidecar-only)
- `chunk_index` widened u8 → u32 in Header + full auth coverage
- `payload_nonce` semantics fully documented
- All u16 slice bookkeeping (`EncodeInfo`, `extract_slice`, `verify_slice`, `scrub`) widened to u32, removing the ~64 MiB FEC segment cap
- Bao migrated from bao 0.13 (1KB fixed) to bao-tree fork with BAO_BLOCK_SIZE=from_chunk_log(2) for 4KB groups + keyed roots bound to format byte. P1: SLICE_LEN=4096, seekable slice module. Prefix+response for size in verifiable.
- Theoretical max size calculation (≈17.18 billion GiB)
- Extensive hardening of AGENTS.md, rustdocs, tests, CI, examples, and removal of all legacy ECIES/Nostr material
- Full production verification gates passed repeatedly (strict clippy + tests)

Current rough edges are listed in section 10 above (some addressed via polish; remaining are documented limitations/deps). The cryptographic core + outboard required by the original Surmount specification + AGENTS is complete and gated.

When in doubt, re-read the original Surmount Systems specification dated 2026-05-30 and this file. Do not re-introduce ECIES decode paths.

---

## 11. v2.0 Plans (Completed)

All v2.0 stabilization items (2.0.0 + CARBONADO20\n magic, reed-solomon-erasure 4/8 FEC, full high-level `file::` outboard + `scrub_outboard` for bare public + sidecars + optional out-of-band Header, low-level) are complete. See [CHANGELOG.md](CHANGELOG.md) for release notes and historical rationale summary. See code (src/file.rs, src/decoding.rs, src/encoding.rs, tests/format.rs) and CHIPs tracker (section 7) for current state. Invariants in §11.4 below and AGENTS §2.1.5 are upheld.

### 11.4 Invariants That Must Survive (Normative)

(See also section 2.1.5.)
- Clean break from v1 ECIES (no decode paths ever).
- Single flat-file model for the primary data (even in outboard mode the main artifact is flat and portable; sidecars are optional companions).
- Bao (keyed, 4KB groups) remains the verifiability primitive.
- Format bitmask 4 bits / 16 combinations preserved.
- Header (when used) is public + header_mac authenticated; never contains key material.
- Non-crypto properties from section 1 (Zstd level 20 compression optional, FEC, bao streaming, WASM, content address via outer hash for the chosen format pipeline).
- Subkey derivation, EtM, CTR rules, etc. unchanged.
- SLH-DSA only as detachable sidecars.

### 11.5 CHIPs / Spec Work

The real normative details for FEC parameters, outboard sidecar on-disk layout, and 2.0 magic + header rules belong in the CHIPs repo. Update section 7 table when drafts exist.

Update the table in section 7 as work progresses.

---

Section 11 pruned post-completion. Retained only the invariants and CHIPs note for ongoing reference. Historical planning summarized in CHANGELOG.md. The final gate must pass against full spec + every AGENTS rule.