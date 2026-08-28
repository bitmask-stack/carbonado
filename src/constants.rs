use bao_tree::BlockSize;
use bitmask_enum::bitmask;
use serde::{Deserialize, Serialize};

/// "Magic number" used by the Carbonado file format (v2 symmetric, stable as of 2.0).
/// 12 bytes: "CARBONADO", version 20, plus a newline character.
pub const MAGICNO: &[u8; 12] = b"CARBONADO20\n";

/// Bao slice length for extract/verify (content chunks). One 4KB slice equals one
/// Bao leaf at `BAO_BLOCK_SIZE` (BlockSize log=2) — the verifiable/FEC geometry unit.
pub const SLICE_LEN: u32 = 4096;

/// Default Bao tree block size for 4KB chunk groups (aligns with SSD/HDD sectors,
/// reduces tree overhead, improves max segment size). Uses n0-computer/bao-tree keyed hashing.
pub const BAO_BLOCK_SIZE: BlockSize = BlockSize::from_chunk_log(2);
/// FEC data shards (k)
pub const FEC_K: usize = 4;
/// FEC total shards (m)
pub const FEC_M: usize = 8;

/// Logical bytes in one RS stripe: four 4 KiB data leaves (`FEC_K * SLICE_LEN`).
pub const FEC_STRIPE_LOGICAL_LEN: u32 = SLICE_LEN * FEC_K as u32;
/// Inboard bytes in one RS stripe: eight 4 KiB leaves (4 data + 4 parity).
pub const FEC_STRIPE_INBOARD_LEN: u32 = SLICE_LEN * FEC_M as u32;

/// Level-20 `windowLog` reference only. Encoder level is caller input, not a silent default.
/// Tests and the Lean AOT demo may pass `20` explicitly.
pub const ZSTD_LEVEL20: i32 = 20;

/// Zstandard frame magic, little-endian `0xFD2FB528`
/// (Lean `zstdMagic`; `ref/zstd/doc/zstd_compression_format.md`).
pub const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

/// Product frames do not set `Content_Checksum_flag` (Lean `zstdContentChecksum`).
pub const ZSTD_CONTENT_CHECKSUM: bool = false;

/// RFC 8878 zstd dictionary magic (`MAGIC_DICTIONARY` / `0xEC30A437` little-endian).
pub const ZSTD_DICTIONARY_MAGIC: [u8; 4] = [0x37, 0xa4, 0x30, 0xec];

/// No-dictionary `Dictionary_ID_flag` (Lean `zstdDictionaryIdFlag` when no dict is supplied).
pub const ZSTD_DICTIONARY_ID_FLAG: u8 = 0;

/// Level-20 `windowLog` from `ref/zstd` `ZSTD_defaultCParameters[0][20]`
/// (srcSize > 256 KiB, and streaming `copy_encode` with unknown size).
/// Lean `zstdLevel20WindowLogLarge`.
pub const ZSTD_LEVEL20_WINDOW_LOG_LARGE: u32 = 25;

/// ## Bitmask for Carbonado formats c0-c15
///
/// | Format | Encryption | Compression | Verifiability | Error correction | Use-cases |
/// |-----|----|----|----|----|----|
/// | c0  |    |    |    |    | Marks a file as scanned by Carbonado |
/// | c1  | ✅ |    |    |    | Symmetrically encrypted incompressible throwaway append-only data streams such as CCTV footage |
/// | c2  |    | ✅ |    |    | Rotating public logs |
/// | c3  | ✅ | ✅ |    |    | Symmetrically encrypted + compressed private archives |
/// | c4  |    |    | ✅ |    | Unencrypted incompressible data such as NFT/UDA image assets |
/// | c5  | ✅ |    | ✅ |    | Symmetrically encrypted private media backups |
/// | c6  |    | ✅ | ✅ |    | Compiled binaries |
/// | c7  | ✅ | ✅ | ✅ |    | Symmetrically encrypted full drive backups |
/// | c8  |    |    |    | ✅ | Television broadcasts |
/// | c9  | ✅ |    |    | ✅ | Symmetrically encrypted transmissions |
/// | c10 |    | ✅ |    | ✅ | Compressed data streaming over lossy channels such as UDP |
/// | c11 | ✅ | ✅ |    | ✅ | Symmetrically encrypted device-local Catalogs |
/// | c12 |    |    | ✅ | ✅ | Publicly-available archived media |
/// | c13 | ✅ |    | ✅ | ✅ | Georedundant private media backups |
/// | c14 |    | ✅ | ✅ | ✅ | Source code, token genesis, blockchain data |
/// | c15 | ✅ | ✅ | ✅ | ✅ | Contract data |
///
/// These operations correspond to the following implementations (v2 symmetric model):
///
/// | Bit name in enum | Meaning when set |
/// |-------|-------|
/// | Encryption | Apply symmetric encryption (AES-256-CTR + HMAC-SHA512 EtM) |
/// | Compression | Apply Zstd compression (level is encoder input) |
/// | Verification | Add streaming verifiability (keyed Bao, 4 KiB leaves) |
/// | Fec | Add forward error correction (reed-solomon-erasure 4/8) |
///
/// While the low-level functions are called in a different order (see [encoding::encode](crate::encode)), the bitmask order is designed to be intuitive for users choosing a format level.
///
/// Verifiability is needed to pay others for storing or hosting your files, but it inhibits use-cases for mutable or append-only data other than snapshots, since the hash will change so frequently. Bao encoding does not have a large overhead, about 5% at most.
///
/// Any data that is verifiable but also unencrypted is instead authenticated via the v2 header MAC (HMAC-SHA512 derived from the master key). This is useful for signed compiled binaries or hosted web content.
#[bitmask(u8)]
#[derive(Serialize, Deserialize)]
pub enum Format {
    Encryption,
    Compression,
    Verification,
    Fec,
}
