# Carbonado

> An apocalypse-resistant data storage format for the truly paranoid.

**Carbonado** is a single flat-file archival container format designed for long-term, consensus-critical data. It combines:

- **AES-256-CTR + full HMAC-SHA512 EtM** (v2 symmetric encryption)
- **SLH-DSA (FIPS-205)** post-quantum signatures as **sidecars only** (via `libbitcoinpqc`)
- **Bao** streaming verifiability
- **Reed-Solomon 4/8** (deterministic FEC replacement for classic zfec) forward error correction
- **Zstd (level 20)** compression (optional)

It is hardware-accelerated (AES-NI/VAES + SHA extensions), WASM-compatible, and makes **no attempt** to decode legacy v1 ECIES files — this is a clean cryptographic break.

See [AGENTS.md](AGENTS.md) for the normative security model, invariants, and production guidance.

[![Crates.io](https://img.shields.io/crates/v/carbonado?style=flat-square)](https://docs.rs/carbonado/latest/carbonado/)
[![docs.rs](https://img.shields.io/docsrs/carbonado?label=docs&style=flat-square)](https://docs.rs/carbonado/latest/carbonado/)
[![Build status](https://img.shields.io/github/actions/workflow/status/bitmask-stack/carbonado/rust.yaml?branch=main&style=flat-square)](https://github.com/bitmask-stack/carbonado/actions/workflows/rust.yaml)
[![License: MIT](https://img.shields.io/crates/l/carbonado?style=flat-square)](https://mit-license.org)
[![Telegram](https://img.shields.io/badge/telegram-invite-blue?style=flat-square)](https://t.me/+eQk5aQ5--iUxYzVk)

## Features

The Carbonado archival format has features to make it resistant against:

- Drive failure and Data loss
    - Uses [bao encoding](https://github.com/oconnor663/bao) so it can be uploaded to a remote peer, and random 4 KiB slices of that data can be periodically checked against a local hash to verify data replication and integrity. This way, copies can be distributed geographically; in case of a coronal mass ejection or solar flare, at most, only half the planet will be affected.
- Surveillance
    - Files are encrypted at-rest by default using the v2 symmetric scheme: **AES-256-CTR** for confidentiality (length-preserving) combined with **full HMAC-SHA512** (64-byte tags) in an Encrypt-then-MAC construction for integrity and authenticity. All key separation uses HMAC-SHA512 in a BIP-32-style construction. Callers supply a high-entropy 32-byte (or 64-byte) master key; passphrase derivation (e.g. Argon2id) is the caller's responsibility outside the library.
- Theft
    - Decoding is done by the client with their own keys, so it won't matter if devices where data is stored are taken or lost, even if the storage media is unencrypted.
- Digital obsolescence
    - All project code, dependencies, and programs will be vendored into a tarball and made available in Carbonado format with every release.
- Bit rot and cosmic rays
  - As a final encoding step, forward error correction codes are added using reed-solomon-erasure (RS 4/8 — deterministic, reproducible scrub, tolerant of distributed corruption across shards while preserving the classic 4-of-8 model). The exact reasons for switching implementations (while keeping the 4/8 numbers) are explained in the "Changes from v1 to v2" section above.

All without needing a blockchain, however, they can be useful for periodically checkpointing data in a durable place.

### Cryptographic Design (v2)

Carbonado v2 is a complete redesign of the cryptography compared to the original version (which we now call v1). The old design used ECIES, a hybrid of elliptic-curve key exchange and AES. We replaced the entire encrypted path with a fully symmetric design.

Here is what changed and why we made each decision:

- **Encryption**: We switched from ECIES to AES-256 in CTR mode.  
  CTR mode gives true length preservation (the ciphertext is exactly the same size as the plaintext) and is extremely parallel, which lets it take full advantage of AES-NI and VAES instructions on modern CPUs. ECIES had extra overhead and was harder to accelerate well.

- **Authentication / Integrity**: Instead of relying on GCM's built-in tag, we use Encrypt-then-MAC with a full 64-byte HMAC-SHA512 tag.  
  We chose the full untruncated tag because it gives much stronger security guarantees and matches the "full HMAC-SHA512" requirement from the original design goals. The same primitive is also used for key derivation, which keeps the code simpler and more consistent.

- **Key handling**: All sub-keys (for AES, for the MAC, for header authentication) are derived from a single master key using HMAC-SHA512 with explicit labels (following the BIP-32 style).  
  This gives strong domain separation and key independence. Compromising one derived key does not help an attacker with the others.

- **Nonces**: Nonces are always 16 fresh random bytes generated with getrandom. The high-level API generates one nonce per entire archive when encryption is enabled.  
  CTR mode is only secure if you never reuse a nonce with the same key. Random bytes from the OS is the simplest way to guarantee that.

- **Header format**: The header is now 177 bytes and is protected by its own 64-byte HMAC tag (using a dedicated derived key). It contains the payload nonce, the Bao hash, a slot for an SLH-DSA public key, the format bits, lengths, etc.  
  The header is deliberately not encrypted — it is public metadata. Storage systems need to be able to read it. We authenticate it instead so tampering is detectable.

- **Post-quantum signatures**: SLH-DSA signatures are only ever stored as separate sidecar files (e.g. `hash.c15.slh`). The 32-byte public key lives in the main header.  
  Keeping signatures outside the container keeps the main archive small and still content-addressable. We sign the Bao root of the processed container.

- **Forward error correction**: We replaced the old zfec library with reed-solomon-erasure, still using the classic 4-of-8 parameters.  
  The new implementation is fully deterministic, which makes scrubbing (recovering corrupted data) reliable even on large files. Reed-Solomon also handles the case where corruption is spread across multiple shards better than the previous code. We kept the exact 4/8 numbers because they match the existing storage model (you can lose half the shards), align with 4 KiB Bao slices/leaves and FEC shard geometry, and are familiar to users.

- **Bao verification layer**: We moved from the original bao crate's 1 KB groups to a fork that supports 4 KB groups (`SLICE_LEN=4096`), and we make the Bao root "keyed" on the format bits.  
  4 KB groups line up with typical disk sector sizes and reduce overhead. Keying the root on the format bits means different processing pipelines (encrypted vs unencrypted, compressed vs not, etc.) produce distinguishable roots. This is useful for storage markets.

- **Password hashing (Argon2id)**: We removed the built-in Argon2id helper.  
  Carbonado now expects you to give it a high-entropy 32-byte (or 64-byte) master key. If you only have a passphrase, you derive the key yourself with Argon2id (or similar) before calling the library. This makes the security contract of the container format simpler and more explicit.

- **Size limits and bookkeeping**: We widened several internal counters from 16-bit to 32-bit. The old limits artificially capped FEC-protected segments at roughly 64 MiB; there was no good reason for that cap anymore.

- **Compression**: Upgraded from the old Snappy to Zstd at level 20 while keeping the bit name/position (for format number stability).  
  Reason: Zstd gives far better compression ratios on the kinds of data people actually archive here (code, contracts, blobs). Level 20 is aggressive but still practical for encode time. Compression remains early in the pipeline so the size win multiplies through FEC and Bao. The "Snappy" Format bit still controls whether compression is applied.

- **Hybrid paranoia layer (new for v2)**: We added an inner AEAD using secp256k1 ECDH (ephemeral) + ChaCha20-Poly1305. The ECC blob is wrapped inside our outer AES-256-CTR + full HMAC-SHA512 EtM using the caller's master key and our derive_subkey/EtM machinery.  
  This doubles ciphers (AES-CTR + ChaCha20), key generation mechanisms (HMAC subkeys + ECDH + derive_subkey on the shared secret), and authentication approaches (HMAC-EtM outer + AEAD inner tag).  
  Use `carbonado::crypto::{hybrid_encrypt, hybrid_decrypt, SecpPublicKey, SecpSecretKey, ...}` (and the lower `ecc_aead_*` if desired).  
  **Composition**: hybrid replaces the encryption step. For full archives with header/FEC/Bao, run hybrid on (optionally compressed) data first, then continue with zfec/bao using a format that does *not* have the Encrypted bit set (standard decode paths will not attempt a pure-symmetric decrypt). On read, recover the hybrid-blob then call hybrid_decrypt with master + recipient secret. The outer EtM of the hybrid still uses your master key for the wrap. Pure symmetric (Encrypted bit) stays the default single-layer path. This is deliberate defense-in-depth for the truly paranoid.

- **Magic number and versioning**: We bumped the crate to version 2.0.0 and changed the magic number at the start of every file to `CARBONADO20\n`.  
  The old development magic (`CARBONADO02\n`) will be rejected with a clear error. This marks the point where the format is considered stabilized.

- **Clean break on old files**: The library will not read or write files created with the old ECIES design.  
  If you have old encrypted archives, you must extract them with an older version of the tools and re-encode them with a fresh master key. We made this decision so the code stays simple and we don't have to carry security baggage from the old design forever.

What stayed the same on purpose:
- Optional compression (the "Snappy" Format bit still enables it; now always Zstd level 20)
- The overall processing order (compress(zstd-20) → encrypt → error correction → add verifiability)
- Bao streaming verification and the ability to extract/verify small slices
- The 16 format levels (c0–c15)
- The flat-file format and full WASM support

All of these changes were made so Carbonado remains simple to reason about, runs fast on real hardware, produces reproducible results for scrubbing, and has a clean security story for long-term archival use.

### Quantum Resistance & Surmount Mission

The v2 design aligns with Surmount Systems’ focus on accelerating Bitcoin’s quantum resistance:

- Symmetric primitives (AES-256 + HMAC-SHA512) retain strong security against Grover’s algorithm (~128-bit post-quantum).
- Long-term authenticity for important manifests uses hash-based post-quantum signatures (SLH-DSA via libbitcoinpqc) as sidecars.
- The design prioritizes practical, hardware-accelerated primitives for bulk archival data while using conservative, quantum-resistant tools where they matter most for long-term verifiability.

### Migration from v1 / ECIES

**There is no in-library support for reading v1 ECIES files.** This is by design (clean cryptographic break).

To migrate:
1. Use an older version of the library (or compatible tooling) to extract plaintext.
2. Re-encode using the current v2 symmetric primitives with a proper 32-byte master key (derive it using Argon2id or equivalent outside the library if you only have a passphrase).

The non-crypto properties (Bao streaming verification, FEC, flat-file format, WASM, etc.) are preserved.

See the "Changes from v1 to v2" section above for the full list of differences and the reasons behind each one. Old encrypted files will not work with this version of the library.

### Master key handling

Carbonado expects a high-entropy 32-byte master key at the API boundary (`[u8; 32]` in Rust). The `carbonado` CLI `--master` flag accepts **64 hex characters** encoding those same 32 bytes. If omitted, the CLI uses an all-zero key (valid for public/unencrypted formats only). Passphrase derivation (e.g. Argon2id) is **the caller's responsibility** — the CLI does not run a KDF.

**CLI specifics:** see [AGENTS.md §7.2](AGENTS.md#72-cli-key-material-handling-srcbincarbonadors) (hex-only input, no zeroization after use, shell-history exposure). **Header security model:** the 64-byte `header_mac` in every archive is a public authentication *tag*, not a secret — see AGENTS.md "Header Visibility and Confidentiality Model".

After encoding or decoding in **your application**, zeroize the master key in process memory when you are done with it. The library does not retain caller-supplied keys beyond the scope of each call; the stock `carbonado` binary does not zeroize either.

```toml
# Cargo.toml (your application — not required by the carbonado crate itself)
[dependencies]
zeroize = "1"
```

```rust
use zeroize::Zeroize;

let mut master_key = [0u8; 32];
// ... load from KDF, HSM, or env ...

let encoded = carbonado::encode(&master_key, b"payload", 14)?;
// ... use encoded ...

master_key.zeroize();
```

Use the same pattern for any intermediate key material you derive before passing bytes to Carbonado.

### Sidecar Post-Quantum Signatures

SLH-DSA signatures (FIPS-205 via `libbitcoinpqc`) are supported **only as sidecars**. They are never stored inside the `.cXX` Carbonado segments.

Typical pattern:
- Encode your data → get a Bao hash.
- Sign the Bao hash (or a manifest containing it) with SLH-DSA.
- Distribute the signature as `<hash>.c15.slh` alongside the archive.

See the [examples/slh_dsa_sidecar.rs](examples/slh_dsa_sidecar.rs) for the exact on-disk sidecar format and how to use it.

### Unified `carbonado` binary (single file + directory)

The `carbonado` CLI encodes and decodes **both** single files and directory trees.

**Install:**

```bash
# From crates.io (once published)
cargo install carbonado

# From this repository
cargo install --path . --bin carbonado
# or
just install

# Build without installing
cargo build --release --bin carbonado
```

The shipped binary is named **`carbonado`**. Encrypted encode auto-creates a BIP39 mnemonic on first use (plaintext at `carbonado key path`); see `carbonado --help`.

**Man pages** (generated from the clap schema):

```bash
just gen-man          # write doc/man/carbonado*.1
just install-man      # install under ~/.local/share/man/man1
man -l doc/man/carbonado.1
```

Faster local builds can patch in a sibling `bao-tree` checkout: `just dev-local-bao` (see `.cargo/config.toml.example`).

**Examples:**

```bash
# Single file — inboard default (headered `{bao_root}.c{format:02x}`, e.g. .c0e for format 14)
carbonado encode myfile.bin --format 14

# Single file — outboard public c14 (bare main + `.out`/`.par` sidecars)
carbonado encode myfile.bin --outboard --format 14

# Encrypted inboard (format 15 requires a 64-hex master key)
carbonado encode secret.bin --format 15 --master <64hex>
carbonado decode <hash>.c0f --master <64hex> --output restored.bin

# Bare outboard decode (sidecar discovery; --format only for bare mains without a Carbonado header)
carbonado decode <hash>.c0e --format 14 --output restored.bin

# Directory (public c14; decimal suffixes on segments)
carbonado encode ./my-project --output ./archive-out
carbonado decode ./archive-out/<catalog-root>.adam.c14 --output ./restored

# Encrypted directory (c15 catalog + encrypted segments)
carbonado encode ./my-project --encrypted --master <64hex> --output ./archive-out
carbonado decode ./archive-out/<catalog-root>.adam.c15 --master <64hex> --output ./restored
```

| Mode | Input | Output layout |
|------|-------|---------------|
| Single file (default) | One file | Headered inboard `{bao_root}.c{format:02x}` (no `--outboard`) |
| Single file (`--outboard`) | One file | Bare public main + `.out`/`.par` sidecars (hex suffix, e.g. `.c0e`) |
| Directory (public) | Tree of files | Inboard `{catalog}.adam.c14` + bare heterogeneous segment mains (c4/c6) |
| Directory (`--encrypted`) | Tree of files | Inboard `{catalog}.adam.c15` + bare segment mains (c5/c7) |

**Decode flags:** Headered inboard `.c{fmt:02x}` files (default encode output) decode automatically from the embedded header — do not pass `--format`. The `--format`, `--hash`, `--padding`, and sidecar override flags apply only to **bare outboard** mains (no `CARBONADO20` header).

**Exit codes:** failures (missing input, invalid format/master, decode errors) return a non-zero exit status; success prints a summary line and exits 0.

Directory encode defaults to public c14 with output `{input}-archive/` (never `.`). Pass `--encrypted` for c15. Segment formats are auto-selected (compressible → c6/c7, incompressible → c4/c5). See [AGENTS.md §7.1](AGENTS.md#71-adamantine-directory-catalog-v10-impl-complete-in-repo-chip-deferred).

**Examples:** [dir_archival.rs](examples/dir_archival.rs) (directory roundtrip), [bare_serve.rs](examples/bare_serve.rs) (HTTP static server for bare `.c14` + sidecars).

### Streaming APIs & seekable verification

Carbonado 2.0 is **streaming-first**: buffer helpers in `encoding`/`decoding` delegate to `src/stream/`.

| API | Purpose |
|-----|---------|
| `file::encode_stream` / `file::decode_stream` | High-level inboard encode/decode from `Read`/`Write` |
| `stream_encode_buffer` / `stream_decode_buffer` | Buffer streaming roundtrip |
| `stream_encode_outboard_buffer` / `stream_decode_outboard_buffer` | Buffer streaming outboard roundtrip |
| `carbonado::stream::stream_encode_outboard` / `stream_decode_outboard` | File/streaming outboard encode/decode with sidecars |
| `verify_slice_outboard` | O(slice) verified read from bare main + `.out` sidecar (HTTP range friendly) |
| `verify_slice_inboard_seekable` | O(slice) verified read from inboard blob without full decode |
| `encode_shard_stream` / `decode_shards_stream` | Multi-segment sharding for large logical files |

- **HTTP range serving:** [`bare_serve`](examples/bare_serve.rs) serves bare `.c14` mains and uses `verify_slice_outboard` to satisfy `Range:` requests with cryptographically verified 4 KiB slices.
- **Directory sharding:** large files in directory archives are split via `encode_shard_stream`; `FilepackEntry.segments` lists multiple `SegmentRef` entries with contiguous `chunk_index` values.
- **Encrypted directories:** `carbonado encode <dir> --encrypted --master <64hex>` emits c15 catalog and c5/c7 segment mains.

### Directory archives (Adamantine 1.0 + rkyv FilepackManifest)

A directory archive is a **separate inboard catalog** plus **bare per-file segment mains** with Bao outboard data centralized in the Adamantine payload bundle:

| Artifact | Role |
|----------|------|
| `{catalog_bao_root}.adam.c14` / `.adam.c15` | Inboard headered catalog (`CARBONADO20\n` + Adamantine 1.0 payload) |
| `{segment_bao_root}.c4` / `.c6` / `.c5` / `.c7` | Bare segment mains (heterogeneous per file; no `.out`/`.par`) |

- **Catalog:** inboard `{catalog_bao_root_64hex}.adam.c14` (public) or `.adam.c15` (encrypted) — Adamantine 1.0 envelope around rkyv [`FilepackManifest`](src/filepack_manifest.rs) v2 + bundled segment Bao outboards.
- **Per-file segments:** bare mains only; format auto-selected (compressible → c6/c7, incompressible → c4/c5). Large files may span multiple segments (sharded `FilepackEntry`).
- **Optional OTS:** per-entry proofs in manifest; catalog proof in `COTS` trailer appended to catalog file (does not change Bao root).

**Canonical wire encoding:** rkyv `FilepackManifest` inside Adamantine 1.0 payload. Legacy CBOR [`filepack`](src/filepack.rs) remains **interop only**.

#### On-disk naming: decimal (directory) vs hex (single-file)

| Context | Suffix | Example |
|---------|--------|---------|
| Directory archives | Decimal `c14`/`c15` catalog; `c4`–`c7` segments | `abc…def.c6`, `abc…def.adam.c14` |
| Single-file / generic CLI outboard | Hex format byte `c{fmt:02x}` | format 14 → `abc…def.c0e` |

#### Adamantine 1.0 header (19 bytes + payload)

```text
Offset  Size  Field
0       13    magic            ADAMANTINE10\n
13      1     carbonado_fmt    0x0E | 0x0F
14      1     flags            u8 (REQUIRE_OTS bit 0; bits 1–7 reserved)
15      4     payload_len      u32 LE
19      N     payload          [rkyv_len][rkyv][bundle_len][bao blobs]
```

| Flag bit | Name | Meaning |
|----------|------|---------|
| 0 | `REQUIRE_OTS` | Per-entry OpenTimestamps proofs required at decode (`ots` feature) |
| 1–7 | *(reserved)* | Must be zero on encode; non-zero → `InvalidAdamantineFlags` |

`ADAMANTINE1\n` and dev `ADAMANTINE2\n` are rejected. Full normative rules: [AGENTS.md §7.1](AGENTS.md#71-adamantine-directory-catalog-v10-impl-complete-in-repo-chip-deferred).

### Documentation & Specs

- Full API documentation: [docs.rs/carbonado](https://docs.rs/carbonado)
- For developers and auditors: the full technical specification and rules are in [AGENTS.md](AGENTS.md)
- Formal specifications: [CHIPs](https://github.com/bitmask-stack/CHIPs) (in progress)

### Ecosystem & Frontends

Carbonado is designed to be useful across many storage and distribution layers. Planned or existing frontends include:

- [x] Bare HTTP example ([`bare_serve`](examples/bare_serve.rs) — static `.c14` + sidecars)
- [ ] S3-compatible object storage ([carbonado-node](https://github.com/bitmask-stack/carbonado-node))
- [ ] Storm
- [ ] Hypercore
- [ ] IPFS
- [ ] BitTorrent
- [ ] rsync
- [ ] SFTP

The reference implementations live in:
- [carbonado-node](https://github.com/bitmask-stack/carbonado-node)
- [carbonado-clients](https://github.com/bitmask-stack/carbonado-clients)

### Checkpoints

Carbonado clients can optionally use a Bitcoin-compatible HD wallet + specific derivation path to create on-chain OP_RETURN checkpoints. These human-readable YAML files reference Carbonado archives, record storage locations, and provide metadata for retrieval and verification.

## Applications

### Contracts

RGB contract consignments must be encoded in a consensus-critical manner that is also resistant to data loss, otherwise, they cannot be imported or spent.

### Content

Includes metadata for mime type and preview content, good for NFTs and UDAs, especially for taking full possession and self-hosting data, or paying peers to keep it safe, remotely.

### Code

Code, dependencies, and programs can be vendored and preserved wherever they are needed. This helps ensure data is accessible, even if there's no longer internet access, or package managers are offline.

## Development

Requires [just](https://github.com/casey/just), [ripgrep](https://github.com/BurntSushi/ripgrep) (`rg`), and a keyed `bao-tree` sibling at `../bao-tree` (branch `76-keyed-bao`):

```bash
just setup-bao-tree   # once, if ../bao-tree is missing
just                  # list recipes
just all              # everything (fmt, lint, tests, release build, source grep)
```

| Recipe | What it does |
|--------|----------------|
| `just fmt` | Formatting |
| `just lint` | Clippy **and** source checks (no v1 ECIES, prod `unwrap`, magic string, etc.) |
| `just test` | Full test suite |
| `just test-smoke` | Slice/streaming/sharding/bao contract tests |
| `just build` + `just test-cli` | Release binary + CLI tests |

CI runs the same recipes — see `.github/workflows/rust.yaml`.

## Benchmarks

Measured with Criterion (`benches/crypto_bench.rs`). Reproduce locally:

```bash
RUSTFLAGS="-C target-cpu=native" cargo bench --bench crypto_bench 2>&1 | tee /tmp/bench-out.txt
```

**Machine:** `x86_64` — AMD Ryzen AI 7 PRO 350 w/ Radeon 860M  
**Date:** 2026-07-04  
**Flags:** `RUSTFLAGS="-C target-cpu=native"`

| Group | Case | Payload | Throughput (median) |
|-------|------|---------|---------------------|
| `symmetric_etm` | encrypt+decrypt (format 1, EtM only) | 1 MB | **380 MiB/s** |
| `full_pipeline_level15` | encode+decode (c15) | 1 MB | **9.2 MiB/s** |
| `outboard_c14` | encode+decode (format 0x0E) | 1 MB | **9.2 MiB/s** |
| `outboard_c14` | encode+decode (format 0x0E) | 64 KB | **3.5 MiB/s** |
| `encode_directory` | encode only (`tests/samples`, 3 files, ~628 KB) | tree | **5.8 MiB/s** |
| `scrub_outboard` | recover corrupted main | 66 B fixture | **5.4 MiB/s** |

*Medians vary ±10–20% with CPU governor, background load, and thermal state; run locally for authoritative numbers.*

Symmetric EtM (format 1) isolates AES-256-CTR + HMAC-SHA512 EtM without compression/FEC/Bao. Full c14/c15 pipelines add Zstd, RS 4/8 FEC, and keyed Bao. `encode_directory` measures encode only (per-file c14 segments + Adamantine catalog write; no decode roundtrip). See `benches/crypto_bench.rs` for exact harnesses.

### Format overhead

Measured amplification for all 16 format levels (c0–c15) on a deterministic ~1 MiB compressible fixture is asserted in `tests/format_amplification.rs`. Run with `--nocapture` to print the matrix:

```bash
cargo test --test format_amplification -- --nocapture
```

Documented bounds (1 MiB compressible fixture, `net_amp = body_len / input_len`): passthrough c0 ≈ 1.0×; encrypt-only c1 ≈ 1.00006× (+64 B EtM tag); RS 4/8 FEC on full input (c8/c12) ≈ 2.0× (`FEC_M/FEC_K`); Bao-only c4 ≈ 1.015×; compress+FEC (c10/c15) ≈ 0.03× (one 16 KiB padded stripe × 2 / 1 MiB). On-disk size adds the 177-byte authenticated header (`Header::LEN`).

## Comparisons

### Ethereum

On Ethereum, all contract code is replicated by nodes for all addresses at all times. This results in scalability problems, is prohibitively expensive for larger amounts of data, and exposes all data for all contract users, in addition to the possibility it can be altered for all users without their involvement at any time.

Carbonado was designed for encoding data for digital assets of arbitrary length, which is to be kept off-chain, encrypted, and safe.

### IPFS

IPFS stores data into a database called BadgerDS, encoded in IPLD formats, which isn't the same as a simple, portable flat file format that can be transferred and stored out-of-band of any server, service, or node. If the storage backend is swapped out, IPFS is a perfectly fine way to transfer data across a P2P network. Carbonado will support an IPFS frontend.

### Filecoin

Carbonado uses Bao stream verification based on the performant [Blake3 hash algorithm](https://github.com/BLAKE3-team/BLAKE3), to establish a statistical proof of replication (which can be proven repeatedly over time). Filecoin instead uses zk-SNARKs, which are notoriously computationally expensive, often recommending GPU acceleration. In addition, Filecoin requires a blockchain, whereas Carbonado does not. Carbonado is a direct alternative to Filecoin, and so no compatibility is needed.

### Storm

Storm is great, but it has a file size limit of 16MB, and while files can be split into chunks, they're stored directly in an embedded database, and not in flat files. Carbonado will support a Storm frontend.

## Error correction

Carbonado v2 uses **reed-solomon-erasure (RS 4/8)**: deterministic encode, reproducible scrub, and tolerance for loss of any 4 of 8 shards (~50% aligned; distributed corruption handled via scrub shard search). Bao provides integrity detection on the decoded payload. The 4/8 model matches the storage layout (half the shards can fail), aligns with 4 KiB slice/Bao-leaf geometry, and is familiar from classic erasure-coded archives.

Scrubbing tries combinations of available shards until a re-encode matches the expected Bao root — useful when you are down to partial copies. Scrub should be rare with reliable media, CoW filesystems that detect bitrot, or intact replicas.

**Legacy note:** v1 used zfec (4/8, as in [Tahoe-LAFS](https://tahoe-lafs.org/trac/tahoe-lafs)). zfec scrub was non-deterministic on larger inputs and weaker against distributed corruption; RS replaced it in v2 (see the v1-to-v2 changes section above).

Outboard mode (for public formats): `file::encode_outboard` / low-level `encode_outboard` return bare main (no Carbonado header wrapper) + sidecars (`.cXX.out` for Bao, `.cXX.par` for FEC parity). Use `decode_outboard` (or `scrub_outboard`) with sidecars; header optional/out-of-band for public bare serving. Encrypted remains inboard. See `file.rs` docs and tests.

**Outboard usage (bare public serving + sidecars):**
- For non-Encrypted levels (even c# like 0/2/4/6/8/10/12/14): `encode_outboard` (or `file::encode_outboard`) yields bare `main` (serve directly from webserver/S3/P2P; no magic header) + optional `bao_outboard` (.cXX.out sidecar) and `fec_parity` (.cXX.par).
- `decode_outboard(master, &hash, main, bao_side, fec_side, pad, fmt)` or high-level `file::decode_outboard` (pass optional out-of-band header bytes for mac verification on public too).
- Sidecar naming: `<bao-root-hex>.cXX.out` (Bao outboard data), `<bao-root-hex>.cXX.par` (FEC parity shards). Use hash from EncodeInfo/OutboardEncoded or header for discovery.
- `scrub_outboard` recovers using parity + re-verifies via bao outboard (Bao bit required).
- Encrypted always inboard (headered .cXX); use regular `file::encode`/`decode`.
- Keyed Bao root commits to exact format pipeline (different c# => different roots for same data).
- See tests/format.rs (bare roundtrips, error cases for missing/tampered sides, 0-byte, c# matrix) and examples/basic_roundtrip.rs for code.

For pure no-master bare verification/serving (public), low-level encode/decode_outboard can be used with zero master where applicable, but high-level file paths are preferred for header auth when available.

Running scrub on an input that has no errors in it actually returns an error; this is to prevent the need for unnecessary writes of bytes that don't need to be scrubbed. This is useful in append-only datastores and metered cloud storage scenarios.

The 4/8 RS parameters mean only 4 valid shards are needed while 8 are stored — half can fail. This roughly doubles payload size (on top of encryption and Bao overhead). Shard size aligns with 4 KiB Bao slice/leaf geometry (`SLICE_LEN=4096`).

Carbonado now uses 4 KiB chunk groups for Bao trees (via the local keyed bao-tree fork at BlockSize log=2). Slices for verification are 4 KiB content units (`SLICE_LEN=4096`, one slice = one Bao leaf). This aligns with 4 KiB SSD/HDD sectors and reduces tree overhead for small and large files. The root hash is keyed on the format bitmask for multi-dimensional naming.

Storage providers will not need to use RAID to protect storage volumes so long as `carbonadod` is configured to store archive chunks on 8 separate storage volumes. In case a volume fails, scrubbing will recover the missing data. When data is served, only 4 of the chunks are needed. This results in a sort of user-level "application RAID", which is inline with Carbonado's design principles of being a flexible format with user-friendly configuration options. It's designed to be as approachable for "Uncle Jim" hobbyists to use as it is for professional mining datacenters bagged in FIL or XCH.

## Terminology

Files are split into segments of a maximum of 1MB input length (configurable via `DirectoryEncodeOptions.segment_plaintext_budget` / `encode_shard_stream`). This was chosen because it aligns well with the IPFS IPLD, Storm, and BitTorrent frontends. These segments are tracked and combined separately using catalog files, which may also store additional metadata about the files needed for specific storage frontends. Chunks are used for error correction, and can be stored separately on separate volumes. Slices are relevant to stream verification, are hardcoded to be 4 KiB in size (`SLICE_LEN=4096`), and are also a reference to Rust byte slices (references to an array of unsighted 8-bit integers).

In summary: File of n MB -> n MB / 1MB Catalog Segments -> 8x FEC (RS) shards -> >=1MB / 8x / (4 KiB slices on 4 KiB Bao groups)

Only chunks are stored separately on-disk. Slices are referenced in-memory, and how segments are streamed is frontend-specific. Segmentation also helps with computational parallelization, reduces node memory requirements, and helps spread IO load across storage volumes.
