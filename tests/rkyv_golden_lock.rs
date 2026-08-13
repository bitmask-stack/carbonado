//! W3 golden lock: fixture `.bin` files must match Rust `rkyv::to_bytes` **and**
//! the Lean-embedded `golden*Hex` constants in `Carbonado/RkyvFilepack.lean`.
//!
//! Regen (updates bins + prints hex to sync into Lean):
//! ```bash
//! cargo run --example dump_rkyv_r9 --features backend-rust
//! ```

use std::fs;
use std::path::PathBuf;

use carbonado::filepack_manifest::*;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rkyv")
        .join(name)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn assert_bin_hex(name: &str, lean_hex: &str) {
    let bytes = fs::read(fixture(name)).unwrap_or_else(|e| panic!("read {name}: {e}"));
    let got = hex(&bytes);
    assert_eq!(
        got, lean_hex,
        "fixture {name} drifted from Lean golden*Hex — run dump_rkyv_r9 and update both sides"
    );
}

fn seg(root_fill: u8, main_len: u64, chunk: u32, vo: u32) -> SegmentRef {
    SegmentRef {
        segment_bao_root: [root_fill; 32],
        chunk_index: chunk,
        main_len,
        verification_outboard_offset: vo,
        verification_outboard_len: 64,
        fec_parity_offset: vo + 64,
        fec_parity_len: 128,
    }
}

/// Must stay bit-identical to `Carbonado/RkyvFilepack.lean` golden*Hex (Issue 3 lock).
mod lean_hex {
    pub const EMPTY: &str = "020000000efbffffff00000000";
    pub const SINGLE: &str = concat!(
        "1111111111111111111111111111111111111111111111111111111111111111",
        "00000000640000000000000000000000400000004000000080000000",
        "612e747874ffffff",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "0e9bffffff01000000000000000000000000",
        "020000000ec1ffffff01000000",
    );
    pub const MULTI_OTS: &str = concat!(
        "1111111111111111111111111111111111111111111111111111111111111111",
        "00000000640000000000000000000000400000004000000080000000",
        "622f6c6f6e6765722d706174682d6e616d652e747874",
        "4444444444444444444444444444444444444444444444444444444444444444",
        "00000000c80000000000000000000000400000004000000080000000",
        "abcdef01",
        "612e747874ffffff",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "0e45ffffff01000000000000000000000000",
        "9600000070ffffff",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "0e5dffffff010000000190ffffff04000000",
        "020000000e87ffffff02000000",
    );
    pub const PATH_INLINE_8: &str = concat!(
        "1111111111111111111111111111111111111111111111111111111111111111",
        "00000000640000000000000000000000400000004000000080000000",
        "3132333435363738",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "0e9bffffff01000000000000000000000000",
        "020000000ec1ffffff01000000",
    );
    pub const PATH_OOL_9: &str = concat!(
        "313233343536373839",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "00000000640000000000000000000000400000004000000080000000",
        "89000000bbffffff",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "0e9bffffff01000000000000000000000000",
        "020000000ec1ffffff01000000",
    );
    pub const TWO_SEGMENTS: &str = concat!(
        "1111111111111111111111111111111111111111111111111111111111111111",
        "00000000640000000000000000000000400000004000000080000000",
        "1212121212121212121212121212121212121212121212121212121212121212",
        "010000003200000000000000c0000000400000000001000080000000",
        "612e747874ffffff",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "0e5fffffff02000000000000000000000000",
        "020000000ec1ffffff01000000",
    );
    pub const OTS_FIRST_ONLY: &str = concat!(
        "1111111111111111111111111111111111111111111111111111111111111111",
        "00000000640000000000000000000000400000004000000080000000",
        "dead",
        "4444444444444444444444444444444444444444444444444444444444444444",
        "00000000c80000000000000000000000400000004000000080000000",
        "612e747874ffffff",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "0e5dffffff010000000190ffffff02000000",
        "622e747874ffffff",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "0e61ffffff01000000000000000000000000",
        "020000000e87ffffff02000000",
    );
    pub const RKYV_CFP2_PREFIX: &str = concat!(
        "4346503211111111111111111111111111111111111111111111111111111111",
        "00000000640000000000000000000000400000004000000080000000",
        "612e747874ffffff",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "0e9bffffff01000000000000000000000000",
        "020000000ec1ffffff01000000",
    );
}

#[test]
fn fixture_bins_match_lean_hex_constants() {
    assert_bin_hex("empty_manifest.bin", lean_hex::EMPTY);
    assert_bin_hex("single_entry.bin", lean_hex::SINGLE);
    assert_bin_hex("multi_entry_ots.bin", lean_hex::MULTI_OTS);
    assert_bin_hex("path_inline_8.bin", lean_hex::PATH_INLINE_8);
    assert_bin_hex("path_ool_9.bin", lean_hex::PATH_OOL_9);
    assert_bin_hex("two_segments.bin", lean_hex::TWO_SEGMENTS);
    assert_bin_hex("ots_first_only.bin", lean_hex::OTS_FIRST_ONLY);
    assert_bin_hex("rkyv_cfp2_prefix.bin", lean_hex::RKYV_CFP2_PREFIX);
}

#[test]
fn rust_rkyv_to_bytes_matches_fixtures() {
    let empty = FilepackManifest {
        version: FILEPACK_MANIFEST_VERSION,
        format_level: FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
        catalog_bao_root: [0u8; 32],
        catalog_ots_proof: None,
        entries: vec![],
    };
    assert_eq!(
        empty.to_bytes().unwrap(),
        fs::read(fixture("empty_manifest.bin")).unwrap()
    );

    let e1 = FilepackEntry {
        rel_path: "a.txt".into(),
        content_blake3: [0x22; 32],
        segment_format: 0x0E,
        segments: vec![seg(0x11, 100, 0, 0)],
        ots_proof: None,
    };
    let single = FilepackManifest {
        version: FILEPACK_MANIFEST_VERSION,
        format_level: FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
        catalog_bao_root: [0x33; 32],
        catalog_ots_proof: None,
        entries: vec![e1.clone()],
    };
    assert_eq!(
        single.to_bytes().unwrap(),
        fs::read(fixture("single_entry.bin")).unwrap()
    );

    let e2 = FilepackEntry {
        rel_path: "b/longer-path-name.txt".into(),
        content_blake3: [0x33; 32],
        segment_format: 0x0E,
        segments: vec![seg(0x44, 200, 0, 0)],
        ots_proof: Some(vec![0xAB, 0xCD, 0xEF, 0x01]),
    };
    let multi = FilepackManifest {
        version: FILEPACK_MANIFEST_VERSION,
        format_level: FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
        catalog_bao_root: [0x55; 32],
        catalog_ots_proof: None,
        entries: vec![e1, e2],
    };
    assert_eq!(
        multi.to_bytes().unwrap(),
        fs::read(fixture("multi_entry_ots.bin")).unwrap()
    );

    // CFP2-prefix rkyv regression fixture
    let mut cfp2_root = [0x11u8; 32];
    cfp2_root[0..4].copy_from_slice(b"CFP2");
    let e_cfp2 = FilepackEntry {
        rel_path: "a.txt".into(),
        content_blake3: [0x22; 32],
        segment_format: 0x0E,
        segments: vec![SegmentRef {
            segment_bao_root: cfp2_root,
            chunk_index: 0,
            main_len: 100,
            verification_outboard_offset: 0,
            verification_outboard_len: 64,
            fec_parity_offset: 64,
            fec_parity_len: 128,
        }],
        ots_proof: None,
    };
    let m_cfp2 = FilepackManifest {
        version: FILEPACK_MANIFEST_VERSION,
        format_level: FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
        catalog_bao_root: [0; 32],
        catalog_ots_proof: None,
        entries: vec![e_cfp2],
    };
    let b = m_cfp2.to_bytes().unwrap();
    assert_eq!(&b[0..4], b"CFP2");
    assert_eq!(b, fs::read(fixture("rkyv_cfp2_prefix.bin")).unwrap());
}

#[test]
fn rel_path_max_is_utf8_bytes() {
    // Rust SSOT: MAX_REL_PATH_LEN is byte length.
    let mut s = String::new();
    while s.len() < MAX_REL_PATH_LEN {
        s.push('你'); // 3 UTF-8 bytes
    }
    // May overshoot slightly; trim to exact max bytes without splitting a char.
    while s.len() > MAX_REL_PATH_LEN {
        s.pop();
    }
    assert!(s.len() <= MAX_REL_PATH_LEN);
    assert!(FilepackManifest::validate_rel_path(&s).is_ok());

    s.push('你');
    assert!(s.len() > MAX_REL_PATH_LEN);
    assert!(FilepackManifest::validate_rel_path(&s).is_err());
}
