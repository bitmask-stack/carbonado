//! FilepackManifest v3 golden dump helper (maintainer); not part of product CLI.
//!
//! Writes `tests/fixtures/rkyv/*.bin` and prints hex for `tests/rkyv_golden_lock.rs`.

use carbonado::filepack_manifest::*;
use std::path::Path;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
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
        dict_offset: 0,
        dict_len: 0,
    }
}

fn write_named(dir: &Path, name: &str, bytes: &[u8]) {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap_or_else(|e| panic!("write {name}: {e}"));
    println!("{name} LEN={}", bytes.len());
    println!("{name} HEX={}", hex(bytes));
}

fn main() {
    let dir = Path::new("tests/fixtures/rkyv");
    std::fs::create_dir_all(dir).expect("fixtures dir");

    let empty = FilepackManifest {
        version: FILEPACK_MANIFEST_VERSION,
        format_level: FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
        catalog_bao_root: [0u8; 32],
        catalog_ots_proof: None,
        entries: vec![],
    };
    write_named(dir, "empty_manifest.bin", &empty.to_bytes().expect("empty"));

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
    write_named(dir, "single_entry.bin", &single.to_bytes().expect("single"));

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
    write_named(
        dir,
        "multi_entry_ots.bin",
        &multi.to_bytes().expect("multi"),
    );

    let path8 = FilepackManifest {
        version: FILEPACK_MANIFEST_VERSION,
        format_level: FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
        catalog_bao_root: [0u8; 32],
        catalog_ots_proof: None,
        entries: vec![FilepackEntry {
            rel_path: "12345678".into(),
            content_blake3: [0x22; 32],
            segment_format: 0x0E,
            segments: vec![seg(0x11, 100, 0, 0)],
            ots_proof: None,
        }],
    };
    write_named(dir, "path_inline_8.bin", &path8.to_bytes().expect("path8"));

    let path9 = FilepackManifest {
        version: FILEPACK_MANIFEST_VERSION,
        format_level: FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
        catalog_bao_root: [0u8; 32],
        catalog_ots_proof: None,
        entries: vec![FilepackEntry {
            rel_path: "123456789".into(),
            content_blake3: [0x22; 32],
            segment_format: 0x0E,
            segments: vec![seg(0x11, 100, 0, 0)],
            ots_proof: None,
        }],
    };
    write_named(dir, "path_ool_9.bin", &path9.to_bytes().expect("path9"));

    let two = FilepackManifest {
        version: FILEPACK_MANIFEST_VERSION,
        format_level: FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
        catalog_bao_root: [0u8; 32],
        catalog_ots_proof: None,
        entries: vec![FilepackEntry {
            rel_path: "a.txt".into(),
            content_blake3: [0x22; 32],
            segment_format: 0x0E,
            segments: vec![seg(0x11, 100, 0, 0), seg(0x12, 50, 1, 192)],
            ots_proof: None,
        }],
    };
    write_named(dir, "two_segments.bin", &two.to_bytes().expect("two"));

    let ots_first = FilepackManifest {
        version: FILEPACK_MANIFEST_VERSION,
        format_level: FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
        catalog_bao_root: [0u8; 32],
        catalog_ots_proof: None,
        entries: vec![
            FilepackEntry {
                rel_path: "a.txt".into(),
                content_blake3: [0x22; 32],
                segment_format: 0x0E,
                segments: vec![seg(0x11, 100, 0, 0)],
                ots_proof: Some(vec![0xDE, 0xAD]),
            },
            FilepackEntry {
                rel_path: "b.txt".into(),
                content_blake3: [0x33; 32],
                segment_format: 0x0E,
                segments: vec![seg(0x44, 200, 0, 0)],
                ots_proof: None,
            },
        ],
    };
    write_named(
        dir,
        "ots_first_only.bin",
        &ots_first.to_bytes().expect("ots_first"),
    );

    let mut cfp2_root = [0x11u8; 32];
    cfp2_root[0..4].copy_from_slice(b"CFP2");
    let cfp2 = FilepackManifest {
        version: FILEPACK_MANIFEST_VERSION,
        format_level: FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
        catalog_bao_root: [0; 32],
        catalog_ots_proof: None,
        entries: vec![FilepackEntry {
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
                dict_offset: 0,
                dict_len: 0,
            }],
            ots_proof: None,
        }],
    };
    write_named(dir, "rkyv_cfp2_prefix.bin", &cfp2.to_bytes().expect("cfp2"));
}
