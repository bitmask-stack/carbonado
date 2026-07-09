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
/// reduces tree overhead, improves max segment size). Uses the local keyed bao-tree fork.
pub const BAO_BLOCK_SIZE: BlockSize = BlockSize::from_chunk_log(2);
/// FEC data shards (k)
pub const FEC_K: usize = 4;
/// FEC total shards (m)
pub const FEC_M: usize = 8;

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
/// | Compression | Apply Zstd compression at level 20 |
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
