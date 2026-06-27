# Carbonado

> An apocalypse-resistant data storage format for the truly paranoid.

**Carbonado** is a single flat-file archival container format designed for long-term, consensus-critical data. It combines:

- **AES-256-CTR + full HMAC-SHA512 EtM** (v2 symmetric encryption)
- **Argon2id** key derivation helper
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
    - Uses [bao encoding](https://github.com/oconnor663/bao) so it can be uploaded to a remote peer, and random 1KB slices of that data can be periodically checked against a local hash to verify data replication and integrity. This way, copies can be distributed geographically; in case of a coronal mass ejection or solar flare, at most, only half the planet will be affected.
- Surveillance
    - Files are encrypted at-rest by default using the v2 symmetric scheme: **AES-256-CTR** for confidentiality (length-preserving) combined with **full HMAC-SHA512** (64-byte tags) in an Encrypt-then-MAC construction for integrity and authenticity. All key separation uses HMAC-SHA512 in a BIP-32-style construction. A master key (32 or 64 bytes recommended) can be provided directly or derived via Argon2id.
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
  The new implementation is fully deterministic, which makes scrubbing (recovering corrupted data) reliable even on large files. Reed-Solomon also handles the case where corruption is spread across multiple shards better than the previous code. We kept the exact 4/8 numbers because they match the existing storage model (you can lose half the shards), align nicely with Bao's 1 KB slices and 4 KB groups, and are familiar to users.

- **Bao verification layer**: We moved from the original bao crate's 1 KB groups to a fork that supports 4 KB groups, and we make the Bao root "keyed" on the format bits.  
  4 KB groups line up with typical disk sector sizes and reduce overhead. Keying the root on the format bits means different processing pipelines (encrypted vs unencrypted, compressed vs not, etc.) produce distinguishable roots. This is useful for storage markets.

- **Password hashing (Argon2id)**: We removed the built-in Argon2id helper.  
  Carbonado now expects you to give it a high-entropy 32-byte (or 64-byte) master key. If you only have a passphrase, you derive the key yourself with Argon2id (or similar) before calling the library. This makes the security contract of the container format simpler and more explicit.

- **Size limits and bookkeeping**: We widened several internal counters from 16-bit to 32-bit.  

- **Compression**: Upgraded from the old Snappy to Zstd at level 20 while keeping the bit name/position (for format number stability).  
  Reason: Zstd gives far better compression ratios on the kinds of data people actually archive here (code, contracts, blobs). Level 20 is aggressive but still practical for encode time. Compression remains early in the pipeline so the size win multiplies through FEC and Bao.

- **Compression**: We upgraded the optional compression step from Snappy to Zstd at level 20 (the "Snappy" Format bit still controls whether it is applied, preserving the format numbers cX).  
  It still runs early so savings compound before FEC doubles the data and before Bao. Level 20 was selected for excellent ratios on real archival payloads with acceptable encode/decode speed.
  The old limits artificially capped FEC-protected segments at roughly 64 MiB. There was no good reason for that cap anymore.

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

### Sidecar Post-Quantum Signatures

SLH-DSA signatures (FIPS-205 via `libbitcoinpqc`) are supported **only as sidecars**. They are never stored inside the `.cXX` Carbonado segments.

Typical pattern:
- Encode your data → get a Bao hash.
- Sign the Bao hash (or a manifest containing it) with SLH-DSA.
- Distribute the signature as `<hash>.c15.slh` alongside the archive.

See the [examples/slh_dsa_sidecar.rs](examples/slh_dsa_sidecar.rs) for the exact on-disk sidecar format and how to use it.

### Documentation & Specs

- Full API documentation: [docs.rs/carbonado](https://docs.rs/carbonado)
- For developers and auditors: the full technical specification and rules are in [AGENTS.md](AGENTS.md)
- Formal specifications: [CHIPs](https://github.com/bitmask-stack/CHIPs) (in progress)

### Ecosystem & Frontends

Carbonado is designed to be useful across many storage and distribution layers. Planned or existing frontends include:

- [x] HTTP / S3-compatible object storage
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

## Comparisons

### Ethereum

On Ethereum, all contract code is replicated by nodes for all addresses at all times. This results in scalability problems, is prohibitively expensive for larger amounts of data, and exposes all data for all contract users, in addition to the possibility it can be altered for all users without their involvement at any time.

Carbonado was was designed for encoding data for digital assets of arbitrary length, which is to be kept off-chain, encrypted, and safe.

### IPFS

IPFS stores data into a database called BadgerDS, encoded in IPLD formats, which isn't the same as a simple, portable flat file format that can be transferred and stored out-of-band of any server, service, or node. If the storage backend is swapped out, IPFS is a perfectly fine way to transfer data across a P2P network. Carbonado will support an IPFS frontend.

### Filecoin

Carbonado uses Bao stream verification based on the performant [Blake3 hash algorithm](https://github.com/BLAKE3-team/BLAKE3), to establish a statistical proof of replication (which can be proven repeatedly over time). Filecoin instead uses zk-SNARKs, which are notoriously computationally expensive, often recommending GPU acceleration. In addition, Filecoin requires a blockchain, whereas Carbonado does not. Carbonado is a direct alternative to Filecoin, and so no compatibility is needed.

### Storm

Storm is great, but it has a file size limit of 16MB, and while files can be split into chunks, they're stored directly in an embedded database, and not in flat files. Carbonado will support a Storm frontend.

## Error correction

Some decisions were made in how error correction is handled. A chunking forward error correction algorithm was used, called Zfec (4/8), which is used in [Tahoe-LAFS](https://tahoe-lafs.org/trac/tahoe-lafs). Similar to how RAID 5 and 6 stripes parity bits across a storage array, Zfec encodes bits in such a manner where only k valid of m total chunks are needed to reconstruct the original. This becomes more complicated by the fact that Zfec does not have integrity checks built-in. Bao is used to verify the integrity of the decoded input; if the integrity check fails, we can't be quite sure which chunk failed. So, there are two ways to handle this; either create a hash for each chunk and persist it in a safe place out-of-band, or, try each combination of chunks until a combination is found that works. The latter approach is used here, since the need for scrubbing should hopefully be a relatively rare occurrence, especially if reliable storage media is used, a CoW filesystem set to scrub for bitrot, or there's an entire copy that's good. However, if you're down to your last copy, and all you have is the hash (name of the file) and some good chunks, the scrub method in this crate should help, even if it can be computationally-intensive.

**Note (v2.0)**: FEC uses reed-solomon-erasure (RS 4/8) -- deterministic, reproducible for scrub, tolerates loss of any 4 of 8 shards (~50% aligned; distributed within via scrub search). Bao provides detection. Old zfec was replaced for these reasons (see the v1-to-v2 changes section above).

Running scrub on an input that has no errors in it actually returns an error; this is to prevent the need for unnecessary writes of bytes that don't need to be scrubbed. This is useful in append-only datastores and metered cloud storage scenarios.

The values 4/8 were chosen for Zfec's k of m parameters, meaning, only 4 valid chunks are needed, but 8 chunks are provided. Half of the chunks could fail to decode. This doubles the size of the data, on top of the encryption and integrity-checking, but such is the price of paranoia. Also, a non-prime k is needed to align chunk size with Bao slice size.

Carbonado now uses 4KB chunk groups for Bao trees (via the local keyed bao-tree fork at BlockSize log=2). Slices for verification remain 1KB content units. This aligns even better with 4KB SSD/HDD sectors and reduces tree overhead for small and large files. The root hash is keyed on the format bitmask for multi-dimensional naming.

Storage providers will not need to use RAID to protect storage volumes so long as `carbonadod` is configured to store archive chunks on 8 separate storage volumes. In case a volume fails, scrubbing will recover the missing data. When data is served, only 4 of the chunks are needed. This results in a sort of user-level "application RAID", which is inline with Carbonado's design principles of being a flexible format with user-friendly configuration options. It's designed to be as approachable for "Uncle Jim" hobbyists to use as it is for professional mining datacenters bagged in FIL or XCH.

## Terminology

Files are split into segments of a maximum of 1MB input length. This was chosen because it aligns well with the IPFS IPLD, Storm, and BitTorrent frontends. These segments are tracked and combined separately using catalog files, which may also store additional metadata about the files needed for specific storage frontends. Chunks are used for error correction, and can be stored separately on separate volumes. Slices are relevant to stream verification, are hardcoded to be 1KB in size, and are also a reference to Rust byte slices (references to an array of unsighted 8-bit integers).

In summary: File of n MB -> n MB / 1MB Catalog Segments -> 8x FEC (RS) shards -> >=1MB / 8x / (1KB slices on 4KB Bao groups)

Only chunks are stored separately on-disk. Slices are referenced in-memory, and how segments are streamed is frontend-specific. Segmentation also helps with computational parallelization, reduces node memory requirements, and helps spread IO load across storage volumes.
