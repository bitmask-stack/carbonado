//! R9 golden dump helper (maintainer); not part of product CLI.
use carbonado::filepack_manifest::*;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let seg = |root_fill: u8, main_len: u64| SegmentRef {
        segment_bao_root: [root_fill; 32],
        chunk_index: 0,
        main_len,
        verification_outboard_offset: 0,
        verification_outboard_len: 64,
        fec_parity_offset: 64,
        fec_parity_len: 128,
    };
    let e1 = FilepackEntry {
        rel_path: "a.txt".into(),
        content_blake3: [0x22; 32],
        segment_format: 0x0E,
        segments: vec![seg(0x11, 100)],
        ots_proof: None,
    };
    let e2 = FilepackEntry {
        rel_path: "b/longer-path-name.txt".into(), // >8 bytes → out-of-line string
        content_blake3: [0x33; 32],
        segment_format: 0x0E,
        segments: vec![seg(0x44, 200)],
        ots_proof: Some(vec![0xAB, 0xCD, 0xEF, 0x01]),
    };
    let m = FilepackManifest {
        version: FILEPACK_MANIFEST_VERSION,
        format_level: FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
        catalog_bao_root: [0x55; 32],
        catalog_ots_proof: None,
        entries: vec![e1, e2],
    };
    let b = m.to_bytes().expect("to_bytes");
    println!("MULTI_LEN={}", b.len());
    println!("MULTI_HEX={}", hex(&b));
    std::fs::write("tests/fixtures/rkyv/multi_entry_ots.bin", &b).expect("write");
    println!("wrote tests/fixtures/rkyv/multi_entry_ots.bin");
}
