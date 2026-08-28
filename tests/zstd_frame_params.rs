//! Zstd frame-header parameters named by Lean `Carbonado.Compress`.
//!
//! These tests **read the frame** (magic + `Frame_Header_Descriptor` bits,
//! optional window descriptor, optional content size). They do **not** claim
//! cross-engine compressed-block identity (W2a permanent residual).
//!
//! Fail-closed if G9 `outboard_c14` fixtures are missing.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use carbonado::constants::{
    ZSTD_CONTENT_CHECKSUM, ZSTD_DICTIONARY_ID_FLAG, ZSTD_LEVEL20, ZSTD_LEVEL20_WINDOW_LOG_LARGE,
    ZSTD_MAGIC,
};
use carbonado::stream::compress::compress_buffer;

use common::zstd_frame::{ParsedZstdFrameHeader, ZstdFrameError, parse_zstd_frame_header};

/// Lean AOT `ZSTD_compress` level-20 golden for `hello` (`Carbonado.Main`).
const LEAN_HELLO_LEVEL20: &[u8] = &[
    0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x05, 0x29, 0x00, 0x00, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
];

/// Lean AOT `ZSTD_compress` level-20 golden for empty input.
const LEAN_EMPTY_LEVEL20: &[u8] = &[0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x00, 0x01, 0x00, 0x00];

fn g9_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/g9")
}

fn require_file(path: &Path) -> Vec<u8> {
    assert!(
        path.is_file(),
        "missing committed zstd frame fixture {}",
        path.display()
    );
    fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn assert_product_shared_flags(h: &ParsedZstdFrameHeader) {
    assert!(!h.unused_bit, "Unused_bit must be 0 (Lean zstdUnusedBit)");
    assert!(
        !h.reserved_bit,
        "Reserved_bit must be 0 (Lean zstdReservedBit)"
    );
    assert_eq!(
        h.content_checksum, ZSTD_CONTENT_CHECKSUM,
        "Content_Checksum_flag (Lean zstdContentChecksum)"
    );
    assert_eq!(
        h.dictionary_id_flag, ZSTD_DICTIONARY_ID_FLAG,
        "Dictionary_ID_flag (Lean zstdDictionaryIdFlag)"
    );
    assert_eq!(h.dictionary_id, None);
}

#[test]
fn rust_constants_match_lean_spec() {
    const {
        assert!(ZSTD_LEVEL20 == 20);
        assert!(matches!(ZSTD_MAGIC, [0x28, 0xb5, 0x2f, 0xfd]));
        assert!(!ZSTD_CONTENT_CHECKSUM);
        assert!(ZSTD_DICTIONARY_ID_FLAG == 0);
        assert!(ZSTD_LEVEL20_WINDOW_LOG_LARGE == 25);
    }
}

#[test]
fn parse_rejects_truncated_bad_magic_reserved() {
    assert_eq!(
        parse_zstd_frame_header(&[]).unwrap_err(),
        ZstdFrameError::TruncatedHeader
    );
    assert_eq!(
        parse_zstd_frame_header(&[0x28, 0xb5, 0x2f, 0xfd]).unwrap_err(),
        ZstdFrameError::TruncatedHeader
    );
    assert_eq!(
        parse_zstd_frame_header(&[0x00, 0x01, 0x02, 0x03, 0x20]).unwrap_err(),
        ZstdFrameError::BadMagic
    );
    assert_eq!(
        parse_zstd_frame_header(&[0x28, 0xb5, 0x2f, 0xfd, 0x08]).unwrap_err(),
        ZstdFrameError::ReservedBitSet
    );
}

#[test]
fn bulk_level20_hello_matches_lean_aot_golden() {
    let frame = zstd::bulk::Compressor::new(ZSTD_LEVEL20)
        .expect("compressor")
        .compress(b"hello")
        .expect("compress hello");
    assert_eq!(
        frame.as_slice(),
        LEAN_HELLO_LEVEL20,
        "zstd-sys 1.5.7 ZSTD_compress must match Lean AOT hello golden"
    );
    let h = parse_zstd_frame_header(&frame).expect("parse hello");
    assert_eq!(&frame[..4], &ZSTD_MAGIC);
    assert_product_shared_flags(&h);
    assert!(h.single_segment, "Lean productBufferSmallFrameOk");
    assert_eq!(h.content_size_flag, 0);
    assert_eq!(h.content_size, Some(5));
    assert_eq!(h.window_descriptor, None);
    assert_eq!(h.descriptor, 0x20);
}

#[test]
fn bulk_level20_empty_matches_lean_aot_golden() {
    let frame = zstd::bulk::Compressor::new(ZSTD_LEVEL20)
        .expect("compressor")
        .compress(b"")
        .expect("compress empty");
    assert_eq!(
        frame.as_slice(),
        LEAN_EMPTY_LEVEL20,
        "zstd-sys 1.5.7 ZSTD_compress must match Lean AOT empty golden"
    );
    let h = parse_zstd_frame_header(&frame).expect("parse empty");
    assert_product_shared_flags(&h);
    assert!(h.single_segment);
    assert_eq!(h.content_size, Some(0));
    assert_eq!(h.descriptor, 0x20);
}

#[test]
fn product_compress_buffer_frame_params() {
    let frame = compress_buffer(b"hello", ZSTD_LEVEL20).expect("compress_buffer hello");
    assert_eq!(&frame[..4], &ZSTD_MAGIC);
    let h = parse_zstd_frame_header(&frame).expect("parse product hello");
    assert_product_shared_flags(&h);
    assert!(
        !h.single_segment,
        "copy_encode leaves Single_Segment clear (differs from Lean AOT one-shot frames)"
    );
    assert_eq!(h.content_size, None);
    assert_eq!(h.window_log, Some(ZSTD_LEVEL20_WINDOW_LOG_LARGE));
    assert_eq!(h.window_descriptor, Some(0x78));
    assert_ne!(
        frame.as_slice(),
        LEAN_HELLO_LEVEL20,
        "streaming rust frame must still differ from Lean AOT hello golden"
    );
}

#[test]
fn g9_outboard_c14_fixtures_match_lean_named_params() {
    let rust_main = g9_root().join("rust/outboard_c14/main.bin");
    let lean_main = g9_root().join("lean/outboard_c14/main.bin");
    let rust = require_file(&rust_main);
    let lean = require_file(&lean_main);
    assert!(
        rust.len() >= 6,
        "rust c14 main too short for a zstd frame header"
    );
    assert!(
        lean.len() >= 6,
        "lean c14 main too short for a zstd frame header"
    );

    let rh = parse_zstd_frame_header(&rust).expect("parse rust c14");
    let lh = parse_zstd_frame_header(&lean).expect("parse lean c14");
    assert_eq!(&rust[..4], &ZSTD_MAGIC);
    assert_eq!(&lean[..4], &ZSTD_MAGIC);
    assert_product_shared_flags(&rh);
    assert_product_shared_flags(&lh);

    assert_eq!(lh.descriptor, 0x20, "Lean AOT G9 c14 descriptor");
    assert!(lh.single_segment);
    assert_eq!(lh.content_size, Some(26), "g9_matrix_v1 plaintext len");
    assert_eq!(lh.window_descriptor, None);

    assert_eq!(rh.descriptor, 0x00, "Rust streaming G9 c14 descriptor");
    assert!(!rh.single_segment);
    assert_eq!(rh.content_size, None);
    assert_eq!(rh.window_log, Some(ZSTD_LEVEL20_WINDOW_LOG_LARGE));
    assert_eq!(rh.window_descriptor, Some(0x78));
    assert_eq!(rh.window_size, Some(1u64 << 25));

    assert_eq!(
        rh.header_len, lh.header_len,
        "both G9 c14 headers are 6 bytes (desc+window vs desc+FCS)"
    );
    assert_eq!(
        &rust[rh.header_len..],
        &lean[lh.header_len..],
        "G9 c14 compressed blocks match; residual is the frame header only"
    );
}

#[test]
fn stream_copy_encode_unknown_size_window_log_25() {
    let mut frame = Vec::new();
    zstd::stream::copy_encode(b"hello" as &[u8], &mut frame, ZSTD_LEVEL20).expect("copy_encode");
    let h = parse_zstd_frame_header(&frame).expect("parse copy_encode");
    assert_eq!(&frame[..4], &ZSTD_MAGIC);
    assert_product_shared_flags(&h);
    assert!(!h.single_segment);
    assert_eq!(h.window_log, Some(ZSTD_LEVEL20_WINDOW_LOG_LARGE));
}
