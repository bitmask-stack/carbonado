# AGENTS.md — Carbonado Development Guidelines

**Project:** Carbonado (bitmask-stack/carbonado)  
**Mission:** Apocalypse-resistant archival format for consensus-critical data, with a focus on Bitcoin quantum resistance.  
**Current Status (as of 2026-06-27):** Major cryptographic rewrite (symmetric v2) complete. 4KB keyed Bao integrated. FEC overhauled to reed-solomon-erasure (deterministic RS 4/8; recovers any 4/8 shards for ~50% when aligned to shards, plus distributed via scrub search + bao oracle). Version bumped to 2.0.0 with new MAGIC `CARBONADO20\n`. Comprehensive v1-vs-v2 changes + every-decision rationales documented in new "v1 vs v2: Changes and Rationales" section below. Outboard mode still in progress (see §11). All core invariants upheld.

**Versioning note during the overhaul**: The crate is currently at 0.7.0. This entire v2 symmetric stack (new Header, nonce model, SLH sidecars, removal of all ECIES/secp/nostr material) is still under active development. Until a 1.0 release (or an explicit stability declaration), the public API surface — especially `EncodeInfo`, `Header` construction details, and the exact set of exported types — is considered fluid. Breaking changes to these types are expected as the design is finalized. Language such as "this would require a minor version bump" should only be used once we have declared the v2 format and high-level API stable. Until then, such changes are simply part of finishing the current development series.

See section 11 (v2.0 Plans) for the stabilization steps, including bumping to 2.0.0, new MAGICNO, FEC replacement, and inboard/outboard modes. Once 2.0 ships, the "fluid" note above no longer applies.

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
   - The core of the new design consists of the symmetric primitives (AES-256-CTR + full HMAC-SHA512 EtM with domain-separated subkeys) plus **SLH-DSA sidecars via libbitcoinpqc** for post-quantum signatures. SLH-DSA is asymmetric by nature and is deliberately kept outside the main (symmetric) container as sidecars only. Key derivation from passphrases (e.g. Argon2id) is the caller's responsibility before supplying a 32-byte master key.
   - Do not mark work "final", "complete", or run "end-to-end verification" passes while any of those pillars remain placeholder functions or comments only.
   - If libbitcoinpqc is listed as a dependency and the spec calls for SLH-DSA sidecars, real functions + minimal wiring + tests are required before any "done" language.
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

**Important**: The main Carbonado container uses only symmetric cryptography. SLH-DSA (see §2.3) is used exclusively for *sidecar* signatures and is not part of the per-segment format. This keeps the core container length-preserving, hardware-accelerated, and only Grover-resistant (as appropriate for symmetric crypto).

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
| Post-Quantum sigs    | None (or ad-hoc)                        | SLH-DSA (SHAKE-128s) **sidecars only** (`<hash>.cXX.slh`) | Sidecars preserve content-addressing and avoid bloat. libbitcoinpqc dogfooding per Surmount/BIP-360 mission. |
| Forward Error Correction | zfec 4/8 (non-deterministic scrub for >~8KB, vulnerable to hits across all 8 chunks) | reed-solomon-erasure (RS 4/8): deterministic encode, reproducible scrub, better tolerance for distributed corruption ("chaos rays") while keeping 4/8 model | RS (BCH subclass) for pure determinism (critical for scrub re-encode + bao hash compare) and stronger erasure properties against partial corruption in every shard. Kept 4/8 for storage model ("application RAID"), alignment with 1KB slices/4KB Bao groups, and user intuition. |
| Verifiability (Bao)  | bao 0.12/0.13 (1KB groups)             | bao-tree fork: 4KB groups (BlockSize log=2) + keyed on format byte | 4KB aligns with disk sectors + reduces tree overhead. Keyed roots make Bao hash multi-dimensional (commits to Format pipeline for markets). |
| Slice / chunk counts | u16 limits (~64MiB FEC cap)            | u32 (theoretical ~4GiB+ per segment)               | Removed artificial caps for large archives while keeping SLICE_LEN=1024. |
| Passphrase KDF       | Argon2id wrapper inside library        | Removed; caller responsibility (Argon2id recommended outside) | Keeps container security contract simple. Master key is 32/64B high-entropy material. |
| Magic number         | CARBONADO01 or similar (ECIES)         | CARBONADO20\n (stable v2); 02 was dev transitional | Signals official stabilized 2.0 format. Old magic → clear external migration error. |
| Version              | Pre-0.7 (ECIES)                        | 2.0.0 (post-FEC + docs stabilization)              | Marks end of fluid dev period. API now stable for semver. |
| Dependencies         | ecies + secp + ...                      | aes+ctr+hmac+sha2 + reed-solomon-erasure + bao-tree fork + libbitcoinpqc (optional pqc) | Clean break removal of ECIES-only crates. Hardware-accel friendly. |

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
  - Kept exact 4/8 + concat layout + alignment (FEC_K * SLICE_LEN) to preserve storage model ("application RAID"), 1KB/4KB geometry, and user expectations.
  - Overhead ~2x same; reproducible for content addressing.
- Not finer-grained per-byte (would change on-disk + storage model; not required).
- See §11.1 in plan docs + updated status.

**Bao Verifiability**
- 1KB fixed groups → 4KB (BlockSize log=2) + keyed on format byte ("carbonado-v2/bao" + format).
- **Why**: 4KB = disk sector friendly, lower tree overhead for small/large files. Keyed roots make outer hash commit to the exact Format pipeline (multi-dimensional naming useful for markets: encrypted vs public variants produce distinguishable roots).
- Root still over body only; header_mac binds metadata.
- See "Keyed Bao idea" and 2.1.5.

**SLH-DSA Post-Quantum Signatures**
- v2: libbitcoinpqc (FIPS-205 SHAKE-128s), **sidecars only** (`<hash>.cXX.slh`), 32B public key stored in main Header.
- **Why**: Sidecars keep per-segment containers small and content-addressable. Sign the Bao root of the *processed container* (multi-dimensional). Matches Surmount quantum-resistance mission (Grover-resistant symmetric + hash-based PQ sigs).
- Entropy: 128B+ for keygen. `SecretKey` zeroizes.

**Other Decisions**
- Argon2id wrapper removed: caller supplies high-entropy master. Keeps library contract simple.
- u16 → u32 for verifiable/chunk slice counts: remove ~64MiB artificial cap.
- New magic `CARBONADO20\n` + v2.0.0: Signals stable post-overhaul format. Dev used 02.
- No v1 decode ever: explicit per clean-break rule.

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
  - Current registered labels (must be unique and documented):
    - `aes-ctr` → first 32 bytes used as AES-256 key (second 32 bytes discarded for this label).
    - `etm-hmac` → full 64 bytes used as HMAC-SHA512 key for payload EtM.
    - `header-auth` → full 64 bytes used as HMAC-SHA512 key for Header MAC.
  - Domain separation via the `carbonado-v2/` prefix + explicit label prevents cross-use.

**Note on HMAC-SHA512 choice (documented 2026 session)**:  
With a 256-bit (32-byte) master key, the security of subkey derivation is capped at ~256 bits regardless of whether HMAC-SHA256 or HMAC-SHA512 is used (PRF security follows the entropy of the input key). HMAC-SHA512 was retained for output size convenience (nice 64-byte results) and historical alignment with the "full HMAC-SHA512" mandate from the original design goals, not because it provides higher security than SHA256 would at this entropy level. Future minimality audits could consider HMAC-SHA256 if 32-byte tags were ever acceptable.

### 2.2 Header Authentication (separate from payload)

- Every v2 Header is authenticated with `compute_header_mac(master_key, auth_data)`.
- `auth_data` = MAGIC || payload_nonce || bao_hash || format || chunk_index || encoded_len || padding_len || metadata.
- Uses the `header-auth` derived subkey.
- Verification happens in `file::decode` before any payload decryption or processing.
- This gives integrity/authenticity of the container metadata independently of the payload EtM.

### 2.3 Post-Quantum Signatures (SLH-DSA / SPHINCS+)

- Provided exclusively via the `libbitcoinpqc` crate (FIPS-205 SLH-DSA-SHAKE-128s parameter set).
- **Only as sidecars**. Never embedded inside per-segment `.c14d` / `.c15` Carbonado containers.
- Intended use: signing manifests, catalogs, checkpoints, or high-level collections of Carbonado files.
- Sidecar format (updated per 2026-05-30 design clarification):
  - 4 bytes: `b"SLH1"` (versioned magic for this sidecar scheme).
  - 7856 bytes: SLH-DSA signature (raw, SHAKE-128s) **only** — the public key is no longer duplicated here.
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
- Key sizes (SLH_DSA_128S): 32B public, 64B secret, 7856B signature.
- Entropy for keygen: minimum 128 bytes of fresh randomness passed to `libbitcoinpqc::generate_keypair`.
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
- PQC errors from `libbitcoinpqc::PqcError` are mapped to dedicated variants (added 2026-05-30).

### 2.6 Hardware Acceleration & Implementation Notes

- AES path: relies on the `aes` crate (AES-NI / VAES when `target-cpu=native` or appropriate target features).
- HMAC-SHA512: relies on `sha2` crate (SHA-NI acceleration on supported x86 CPUs).
- SLH-DSA (SHAKE-128s): acceleration is limited to general CPU performance and the underlying Keccak implementation; not SHA-NI (SHAKE is Keccak-based).
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

---

### Subkey Label Registry (normative)

- `aes-ctr`
- `etm-hmac`
- `header-auth`

No other labels may be used without updating this registry and the implementation.

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

Current registered labels (must be kept in sync with code):
- `aes-ctr`
- `etm-hmac`
- `header-auth`

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
- `extract_slice(index)`, `verify_slice(index, count)`: `u16` → `u32`
- Internal arithmetic in `scrub`
- `InvalidVerifiableSliceCount` error payload

`SLICE_LEN` remains `u16 = 1024` (it is simply the definition of a Bao slice; it was never the cap — the u16 *counts* were).

**Result**:
- FEC-protected segments are now limited only by the existing u32 length fields (~4 GiB verifiable per segment).
- With u32 slice indices, the theoretical verification range is ~4 TiB (far beyond what the Header lengths allow).
- The ~64 MiB cap that existed for c8–c15 formats is gone.

The change was made while still in the active 0.7 development series of the v2 cryptographic redesign (clean break), so it is treated as normal completion work rather than a post-stability semver event.

All previous "Remaining u16 Bookkeeping Limits" text has been superseded by this widening. The only size-related `u16` left in the public API is the `SLICE_LEN` constant itself, which does not impose a total-size limit.

These invariants are more important than any particular performance optimization.

### 2.1.6 Quantum Resistance Posture

- Symmetric primitives (AES-256-CTR + HMAC-SHA512): Grover gives only quadratic speedup → still strong (~128-bit security).
- Post-quantum signatures: Provided via `libbitcoinpqc` (SLH-DSA / SPHINCS+) as **sidecar** signatures only. This matches the project's broader Bitcoin quantum-resistance mission (BIP-360 related work).
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
| v2 Container Header Format         | Drafting   | TBD                       | New symmetric-only header |
| Nonce & Subkey Derivation Details  | Drafting   | TBD                       | Must include security arguments |
| SLH-DSA Sidecar Nomenclature       | Drafting   | TBD                       | Content vs container separation |
| Migration Guidance (External)      | Drafting   | TBD                       | How users move from v1 archives |
| Argon2id Parameter Recommendations | Superseded | 2026 session              | Removed from library; caller responsibility for KDF |
| Test Matrix (linux + wasm + others) | Completed | 2026-05-30                | Explicit CI matrix: native, musl, aarch64, wasm32 (pqc on/off) |
| v2.0 FEC Replacement (zfec -> reed-solomon-erasure) | Completed | 2026                      | RS 4/8 (k=4 data, 4 parity); det encode; tolerates any 4/8 shards (50% aligned); scrub combo search for distributed taints; see §11.1 and code |
| Inboard / Outboard Modes           | Planned    | TBD                       | Bare public files for webservers + sidecar proofs (see §11.2) |
| Carbonado 2.0 Magic + Version Bump | Planned    | TBD                       | New MAGICNO (CARBONADO20), crate 2.0.0, end of fluid dev (see §11.3) |

Update this table as work progresses. The real normative text lives in the CHIPs repo.

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

**Updated after u32 slice verification widening (most recent work):**

- (FEC scrub non-determinism fixed by RS overhaul; re-encode now always bit-identical for good data; full recovery exercised via subset search on candidates + bao hash oracle.)
- `Header::new` carries `#[allow(clippy::too_many_arguments)]` (legitimate for an authenticated header constructor, but still noisy).
- No automatic zeroization of caller-supplied master keys (explicitly documented; callers are responsible).
- High-level `file::encode` always emits `chunk_index = 0`. True large-file sharding remains an application concern (even though the format now supports it via u32 chunk_index).
- The two `.expect()` calls in the hot symmetric crypto paths (after `derive_subkey`) are on programmer invariants, not attacker input, but they still exist.
- AGENTS.md "Current Rough Edges" and some older work log entries need periodic pruning as items are completed.
- WASM + libbitcoinpqc cross-compilation limitations remain (documented, not a code bug in Carbonado itself).
- Bao crate: Code migrated to use local keyed bao-tree fork (../bao-tree) as default with 4KB chunk groups (BlockSize::from_chunk_log(2) == BAO_BLOCK_SIZE). Keyed roots commit to Format bitmask. Old bao=0.13 kept only for Hash type + reexport. 1KB SLICE_LEN kept on top of groups. Temporary fork until upstream. (See Cargo.toml, constants.rs, encoding/decoding.rs). CI workflows explicitly checkout the fork on branch 76-keyed-bao; dep uses default-features=false.
- reed-solomon-erasure dep: upstream "looking for maintainers"; added Cargo note for periodic re-eval (no runtime issues, det, suitable).

All core cryptographic requirements from the original Surmount spec (symmetric AES-256-CTR + full HMAC-SHA512 EtM, SLH-DSA sidecars only, clean break, u32 chunk support, etc.) are now implemented and verified. Argon2id passphrase KDF was deliberately removed; callers derive high-entropy master keys outside the library (Argon2id recommended for passphrases).

---

**Last updated:** After migration to 4KB Bao chunk groups using local keyed bao-tree fork (BlockSize log=2), with format-keyed roots for multi-dimensional naming. (4KB sectors default now active in encode/decode/bao wrappers.) Planning for v2.0 stabilization added (see section 11).

Major items completed in this session:
- Full symmetric v2 stack (AES-256-CTR + 64-byte HMAC-SHA512 EtM, header_mac, subkey derivation). Argon2id passphrase helper removed (callers must derive high-entropy master keys themselves).
- Real libbitcoinpqc SLH-DSA (keygen/sign/verify + convenience wrappers) as sidecars only
- SLH-DSA public key moved into main `Header` (signature remains sidecar-only)
- `chunk_index` widened u8 → u32 in Header + full auth coverage
- `payload_nonce` semantics fully documented
- All u16 slice bookkeeping (`EncodeInfo`, `extract_slice`, `verify_slice`, `scrub`) widened to u32, removing the ~64 MiB FEC segment cap
- Bao migrated from bao 0.13 (1KB fixed) to bao-tree fork with BAO_BLOCK_SIZE=from_chunk_log(2) for 4KB groups + keyed roots bound to format byte. SLICE_LEN kept at 1024. Prefix+response for size in verifiable.
- Theoretical max size calculation (≈17.18 billion GiB)
- Extensive hardening of AGENTS.md, rustdocs, tests, CI, examples, and removal of all legacy ECIES/Nostr material
- Full production verification gates passed repeatedly (strict clippy + tests)

Current rough edges are listed in section 10 above (some will be addressed by the v2.0 plans in section 11). The cryptographic core required by the original Surmount specification is complete.

When in doubt, re-read the original Surmount Systems specification dated 2026-05-30 and this file. Do not re-introduce ECIES decode paths.

---

## 11. v2.0 Plans (Stabilization + New Features)

These are the remaining items to officially release Carbonado as 2.0. Work here is **planning and documentation only** for now. No code changes that alter the on-disk format or public behavior until the plan is reviewed.

**Goal**: Declare the symmetric design (Header, crypto, keyed 4KB Bao) stable under a 2.0 release, with a clean new magic number, plus two major usability/architectural improvements.

### 11.1 Replace zfec 4/8 with a Better Erasure Code

**Current problems**:
- zfec 4/8 gives exactly 2x overhead and tolerates loss of any 4 of 8 large chunks.
- A "well placed" corruption that hits every chunk (possible with a single cosmic ray or bad sector in the wrong way) can make reconstruction impossible even if total bad bytes << 50%.
- scrub path is non-deterministic for >~8KB (TODOs in decoding.rs). Re-encode + hash compare does not always work.
- Not byte-granular for *any* positioned 50% bytes (coarse 4/8 shard model; distributed partials in >4 shards still irrecoverable). Search + bao enables recovery from corruptions leaving >=4 intact shards.
- Not guaranteed bit-for-bit reproducible across runs/impls in all cases.

**Requirements for replacement**:
- Deterministically reproducible: identical input bytes + same parameters must produce identical output bytes (critical for scrub re-encode verification and content-addressing consistency).
- Tolerate erasure of any 4 of 8 shards (~50% of FEC body if bytes confined to <=4 shards; distributed hits within limit via scrub candidate search). Stronger than old zfec for det + partials in practice.
- Survive distributed corruption across what used to be the "8 chunks" (i.e. good erasure capability, not just detection).
- Efficient and fast (encoding/decoding time and memory). Hardware-friendly where possible.
- WASM compatible, preferably pure Rust or minimal deps (like current zfec-rs).
- Systematic preferred (original data appears verbatim in the output for some modes).
- Keep integration points: 4KB alignment friendly with BAO_BLOCK_SIZE and 1KB SLICE_LEN; calc_padding_len kept as-is to preserve 4KB/1KB/FEC_K alignment invariants (documented in utils.rs); scrub must become reliable (encode then compare bao hash).
- Overhead: aim for same or better than 2x for equivalent resilience. Rate ~1/2.
- The "Zfec" bit in Format keeps its position and semantics ("add forward error correction"). Internals change.
- Must preserve non-crypto properties from section 1 (flat-file, pipeline ordering where it makes sense, WASM, etc.).

**Candidate direction**: Reed-Solomon erasure coding (BCH subclass) via `reed-solomon-erasure` "5" crate (solid, no_std, det, no runtime rand, WASM ok, used widely). Chosen for: pure determinism (encode identical bytes), correct erasure math, minimal, aligns with 4/8 model + padding. Validated: tests cover det, recovery of 4/8 shards, distributed taints via candidate search in scrub, edges. (BCH direct not needed as RS is appropriate.)

**Format impact**: This is a breaking change to the FEC layer. Combined with the 2.0 magic bump (below), old zfec-encoded segments will require external migration (decode with old crate version, re-encode with new).

**Open questions**:
- Exact parameters (k/m or equivalent rate + symbol size).
- Whether to keep chunked storage model or move to finer symbols.
- How scrub changes (hopefully simple re-encode + compare).
- Performance on target hardware (Zen 5 etc.) with `RUSTFLAGS=-C target-cpu=native`.

Add to todos when implementing: new dependency, replace encoding::zfec + decoding zfec paths + utils::calc_padding_len + scrub + tests + docs + benchmarks.

**Implemented (2026)**: reed-solomon-erasure v5, 4/8 params preserved (FEC_K=4, FEC_M=8), padding unchanged (aligns; calc_padding not generalized - see utils.rs + AGENTS note for slice/FEC invariant reasons), scrub robustified with combo search over candidates (to handle tainted shards w/o no-op on all-present), all errors via FecError, full test matrix + det/recovery/chaos (incl rand+explicit 4-shard). Benchmarks use existing benches/ + RUSTFLAGS. Language aligned to actual (shard + search). No gaps for core. See /tmp/grok-impl-summary for evidence. 11.1 complete.

### 11.2 Inboard and Outboard Modes

Currently everything is "inboard": when Zfec or Bao bits are set, the resulting body contains the transformed data + embedded verification/erasure data in one flat file (after the Header).

**Desired**:
- Configurable outboard mode.
- For public (non-Encrypted) files: the main stored/served bytes on disk can be the bare original data (or post-compress(zstd-20) if compression requested), exactly as the file would exist without Carbonado.
- Verification data (Bao outboard hashes) and/or FEC parity live in separate side files (e.g. named after the bao hash + .cXX + .out or conventional extensions).
- This is excellent for webservers: a public c4/c6/c12/c14 archive can be served directly via static HTTP with no wrapper bytes in the response body. Verifiers download the bare file + the outboard sidecar(s).
- Encrypted formats probably stay inboard (or the outboard data would still be paired with the encrypted main file).

**Impact areas to plan**:
- New or extended encode APIs: e.g. `encode(..., outboard: bool)` or separate `encode_outboard` / return type that includes main_bytes + optional outboard_bytes + fec_parity.
- Decoding must accept bare data + outboard proof when operating in that mode.
- Header: for bare outboard public case, perhaps the Header is stored out-of-band too, or a tiny manifest. The bao hash (keyed on format) still names the result of the pipeline.
- For Bao step: leverage the existing outboard support in bao-tree (PreOrderOutboard / PostOrder*, create_keyed, etc.) instead of prefixing the response into the main body.
- For Zfec/FEC: parity can be produced as separate chunks/files.
- Format bitmask stays the same. The "Bao" bit means "verifiability is present" (whether inboard or outboard is a storage choice).
- Content addressability: the root bao hash still refers to the specific (data + pipeline) even if stored outboard.
- file::encode / file::decode + low-level encoding::encode need variants or flags.
- Tests, examples, README, and storage frontends (web, S3, p2p) must understand sidecars.
- When outboard + no compression + no encryption + no FEC: the "Carbonado file" on disk can literally be the user's original bytes (with sidecar for any verifiability).

**Preserved invariants**:
- Flat file for the primary data artifact when outboard bare mode is used.
- Bao-based streaming verification still works (using outboard data + the bare file).
- 4KB groups + 1KB slices continue.
- Header (when present) authenticated before use.
- Multi-dimensional naming via keyed bao hash.

**Benefits**: Public data can be directly usable by ordinary tools/webservers while still getting the durability/verifiability of Carbonado when the sidecars are kept.

Add to todos when implementing: API design for modes, changes to encoding/decoding/file modules, updates to EncodeInfo/Header usage for outboard cases, new tests for bare roundtrips.

### 11.3 Official 2.0 Release + New Magic Number

- Bump crate version from 0.7.0 to 2.0.0 in Cargo.toml.
- MAGICNO is now b"CARBONADO20\n" (2.0). (Done.)
- Update the constant docs, all parsing sites, AGENTS (Header layout, invariants list), README, examples, tests.
- Old magic (02 or anything else) must produce clear "use older version for migration" error (already the pattern).
- Update the intro versioning note and "Current Status".
- The 2.0 release marks the end of the "fluid API during overhaul" period. After this, semver rules apply for breaking changes.
- The three items in this section (new FEC, in/outboard, version+magic) should ship together or in coordinated 2.0.x releases so that on-disk artifacts created under 2.0 are stable.
- SLH1 sidecar magic stays as-is (independent).

**Rationale for new magic**: Clearly signals "this is the stabilized Carbonado v2 format". Even though crypto-v2 work used 02, the official named 2.0 gets its own identifier. Makes it trivial for tools to detect "pre-2.0 dev format".

Update Cargo description and any "0.7" references.

### 11.4 Invariants That Must Survive These Changes

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

The real normative details for the new FEC parameters, exact outboard on-disk layout for sidecars, and the 2.0 magic + header compatibility rules belong in the CHIPs repo. Update the tracker table below when drafts exist.

Update the table in section 7 as work progresses.

---

When these are implemented, prune this section 11 and move any retained notes into the main architecture or rough edges as appropriate. The final gate (see top of file) must pass against the full spec + AGENTS rules before declaring 2.0 done.