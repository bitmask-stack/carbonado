//! Tests for directory segment format policy (`infer` heuristic).

use carbonado::{
    directory::{
        format_policy::{
            is_likely_incompressible, resolve_catalog_format, SegmentFormatPolicy,
            SEGMENT_FORMAT_ENCRYPTED_RAW, SEGMENT_FORMAT_PUBLIC_COMPRESSED,
            SEGMENT_FORMAT_PUBLIC_RAW,
        },
        SEGMENT_FORMAT_ENCRYPTED_COMPRESSED,
    },
    error::CarbonadoError,
    filepack_manifest::{
        FILEPACK_MANIFEST_FORMAT_LEVEL_ENCRYPTED, FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
    },
};

#[test]
fn infer_jpeg_is_incompressible() {
    let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
    assert!(is_likely_incompressible(&jpeg));
}

#[test]
fn infer_text_is_compressible() {
    assert!(!is_likely_incompressible(b"plain text source code\n"));
}

#[test]
fn auto_public_text_gets_c14() {
    let fmt = SegmentFormatPolicy::Auto
        .resolve_segment_format(false, b"hello world\n")
        .expect("c14");
    assert_eq!(fmt, SEGMENT_FORMAT_PUBLIC_COMPRESSED);
}

#[test]
fn auto_public_jpeg_gets_c12() {
    let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
    let fmt = SegmentFormatPolicy::Auto
        .resolve_segment_format(false, &jpeg)
        .expect("c12");
    assert_eq!(fmt, SEGMENT_FORMAT_PUBLIC_RAW);
}

#[test]
fn auto_encrypted_text_gets_c15() {
    let fmt = SegmentFormatPolicy::Auto
        .resolve_segment_format(true, b"secret notes\n")
        .expect("c15");
    assert_eq!(fmt, SEGMENT_FORMAT_ENCRYPTED_COMPRESSED);
}

#[test]
fn force_raw_encrypted_gets_c13() {
    let fmt = SegmentFormatPolicy::ForceRaw
        .resolve_segment_format(true, b"anything")
        .expect("c13");
    assert_eq!(fmt, SEGMENT_FORMAT_ENCRYPTED_RAW);
}

#[test]
fn force_c12_rejects_encrypted_catalog() {
    let err = SegmentFormatPolicy::ForceC12
        .resolve_segment_format(true, b"x")
        .unwrap_err();
    assert!(
        matches!(
            err,
            CarbonadoError::SegmentFormatMismatch(ref m)
                if m.contains("does not match catalog encryption=true")
        ),
        "got {err:?}"
    );
}

#[test]
fn resolve_catalog_format_c14_c15() {
    assert_eq!(
        resolve_catalog_format(false),
        FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC
    );
    assert_eq!(
        resolve_catalog_format(true),
        FILEPACK_MANIFEST_FORMAT_LEVEL_ENCRYPTED
    );
}
