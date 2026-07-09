//! E2E tests for Adamantine 1.0 directory archives (bundled Bao, heterogeneous segments).

mod common;

#[cfg(feature = "ots")]
use carbonado::ots::{verify_stamp, OtsPolicy};
use carbonado::{
    adamantine::{
        decode_adamantine, encode_adamantine, ADAMANTINE_CARBONADO_FMT_ENCRYPTED,
        ADAMANTINE_CARBONADO_FMT_PUBLIC, ADAMANTINE_FLAG_REQUIRE_OTS, ADAMANTINE_MAGIC,
    },
    adamantine_payload::{
        build_adamantine_payload, fec_slice_from_bundle, split_adamantine_payload,
        verification_slice_from_bundle,
    },
    decode_outboard,
    directory::format_policy::{
        SegmentFormatPolicy, SEGMENT_FORMAT_PUBLIC_COMPRESSED, SEGMENT_FORMAT_PUBLIC_RAW,
    },
    encode_outboard,
    error::CarbonadoError,
    file::{
        decode, decode_directory, encode_directory, encode_directory_with_options,
        DirectoryEncodeOptions, DIRECTORY_ARCHIVE_FORMAT, DIRECTORY_ARCHIVE_FORMAT_ENCRYPTED,
        DIRECTORY_TEST_SEGMENT_BUDGET,
    },
    filepack_manifest::{
        FilepackEntry, FilepackManifest, FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
        FILEPACK_MANIFEST_VERSION, MAX_SEGMENT_MAIN_LEN,
    },
    scrub_outboard,
};
use common::assert_trees_equal;
use std::fs;
use std::path::{Path, PathBuf};

const ZERO_KEY: [u8; 32] = [0u8; 32];
const TEST_MASTER: [u8; 32] = [0xAB; 32];

fn samples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples")
}

fn tempdir(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("carbonado_dir_test_{name}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create tempdir");
    dir
}

fn adam_catalog_path(enc_dir: &Path, root: &[u8; 32], format: u8) -> PathBuf {
    enc_dir.join(format!("{}.adam.c{format}", hex32(root)))
}

struct TamperedCatalogParts {
    adam_flags: u8,
    bundle: Vec<u8>,
}

fn load_catalog_manifest_and_parts(
    catalog_path: &Path,
    catalog_root: &[u8; 32],
) -> (FilepackManifest, TamperedCatalogParts) {
    let (_, body) = decode(&ZERO_KEY, &fs::read(catalog_path).expect("read")).expect("decode");
    let (adam_payload, hdr) = decode_adamantine(&body).expect("adam");
    let (rkyv, bundle) = split_adamantine_payload(&adam_payload).expect("split");
    let manifest = FilepackManifest::from_bytes_with_root(&rkyv, *catalog_root).expect("manifest");
    (
        manifest,
        TamperedCatalogParts {
            adam_flags: hdr.flags,
            bundle: bundle.to_vec(),
        },
    )
}

fn write_tampered_catalog(
    enc_dir: &Path,
    manifest: &FilepackManifest,
    parts: &TamperedCatalogParts,
) -> PathBuf {
    let rkyv = manifest.to_bytes().expect("rkyv");
    let payload = build_adamantine_payload(&rkyv, &parts.bundle).expect("payload");
    let adam = encode_adamantine(&payload, ADAMANTINE_CARBONADO_FMT_PUBLIC, parts.adam_flags);
    let (encoded, _) =
        carbonado::file::encode(&ZERO_KEY, &adam, DIRECTORY_ARCHIVE_FORMAT, None).expect("encode");
    let header =
        carbonado::file::Header::try_from(&encoded[..carbonado::file::Header::LEN]).expect("hdr");
    let root = *header.hash.as_bytes();
    let path = adam_catalog_path(enc_dir, &root, DIRECTORY_ARCHIVE_FORMAT);
    fs::write(&path, &encoded).expect("write tampered catalog");
    path
}

fn assert_inboard_catalog(path: &Path) {
    use carbonado::constants::MAGICNO;
    let bytes = fs::read(path).expect("read catalog");
    assert!(
        bytes.len() > carbonado::file::Header::LEN && &bytes[0..12] == MAGICNO,
        "catalog must be inboard: {}",
        path.display()
    );
}

fn count_bare_segment_mains(enc_dir: &Path) -> usize {
    fs::read_dir(enc_dir)
        .expect("read_dir")
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.ends_with(".c12")
                || name.ends_with(".c13")
                || name.ends_with(".c14")
                || name.ends_with(".c15")
        })
        .count()
}

fn assert_no_bare_segment_mains(enc_dir: &Path) {
    assert_eq!(
        count_bare_segment_mains(enc_dir),
        0,
        "expected no bare segment mains in {}",
        enc_dir.display()
    );
}

fn assert_no_directory_sidecars(enc_dir: &Path) {
    for entry in fs::read_dir(enc_dir).expect("read_dir") {
        let path = entry.expect("entry").path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        assert!(
            !name.ends_with(".out") && !name.ends_with(".par") && !name.ends_with(".ots"),
            "unexpected directory sidecar: {}",
            path.display()
        );
    }
}

#[test]
fn directory_roundtrip_samples() {
    let src = samples_dir();
    let enc_dir = tempdir("enc");
    let dec_dir = tempdir("dec");

    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode_directory");
    assert!(archive.entry_count >= 3);

    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );
    assert_inboard_catalog(&catalog_path);
    assert_no_directory_sidecars(&enc_dir);

    decode_directory(&ZERO_KEY, &catalog_path, &dec_dir).expect("decode_directory");
    assert_trees_equal(&src, &dec_dir);
}

#[test]
fn directory_encrypted_roundtrip() {
    let src = samples_dir();
    let enc_dir = tempdir("enc_enc");
    let dec_dir = tempdir("dec_enc");

    let options = DirectoryEncodeOptions {
        encrypted: true,
        ..DirectoryEncodeOptions::default()
    };
    let archive =
        encode_directory_with_options(&TEST_MASTER, &src, &enc_dir, options).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT_ENCRYPTED,
    );
    assert_inboard_catalog(&catalog_path);
    decode_directory(&TEST_MASTER, &catalog_path, &dec_dir).expect("decode");
    assert_trees_equal(&src, &dec_dir);
}

#[test]
fn heterogeneous_segment_formats_auto() {
    let src = tempdir("hetero_src");
    fs::write(src.join("text.txt"), b"compressible text payload for c14").expect("write");
    let png = samples_dir().join("content.png");
    fs::copy(&png, src.join("content.png")).expect("copy png");

    let enc_dir = tempdir("hetero_enc");
    let dec_dir = tempdir("hetero_dec");
    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );

    let (_, body) =
        decode(&ZERO_KEY, &fs::read(&catalog_path).expect("read")).expect("decode catalog");
    let (adam_payload, _) = decode_adamantine(&body).expect("adamantine");
    let (rkyv, _) = split_adamantine_payload(&adam_payload).expect("split");
    let index =
        FilepackManifest::from_bytes_with_root(&rkyv, archive.catalog_bao_root).expect("manifest");

    let text_entry = index
        .entries
        .iter()
        .find(|e| e.rel_path == "text.txt")
        .expect("text");
    let png_entry = index
        .entries
        .iter()
        .find(|e| e.rel_path == "content.png")
        .expect("png");
    assert_eq!(text_entry.segment_format, SEGMENT_FORMAT_PUBLIC_COMPRESSED);
    assert_eq!(png_entry.segment_format, SEGMENT_FORMAT_PUBLIC_RAW);

    decode_directory(&ZERO_KEY, &catalog_path, &dec_dir).expect("decode");
    assert_trees_equal(&src, &dec_dir);
}

#[test]
fn force_compressed_segment_policy() {
    let src = tempdir("force_src");
    let png = samples_dir().join("content.png");
    fs::copy(&png, src.join("content.png")).expect("copy");

    let enc_dir = tempdir("force_enc");
    let options = DirectoryEncodeOptions {
        segment_format_policy: SegmentFormatPolicy::ForceCompressed,
        ..DirectoryEncodeOptions::default()
    };
    let archive =
        encode_directory_with_options(&ZERO_KEY, &src, &enc_dir, options).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );
    let (_, body) = decode(&ZERO_KEY, &fs::read(&catalog_path).expect("read")).expect("decode");
    let (adam_payload, _) = decode_adamantine(&body).expect("adam");
    let (rkyv, _) = split_adamantine_payload(&adam_payload).expect("split");
    let index =
        FilepackManifest::from_bytes_with_root(&rkyv, archive.catalog_bao_root).expect("manifest");
    assert_eq!(
        index.entries[0].segment_format,
        SEGMENT_FORMAT_PUBLIC_COMPRESSED
    );
}

#[test]
fn multi_segment_sharding_roundtrip() {
    let src = tempdir("shard_src");
    let big = vec![0xCDu8; (DIRECTORY_TEST_SEGMENT_BUDGET * 2 + 1) as usize];
    fs::write(src.join("big.bin"), &big).expect("write");

    let enc_dir = tempdir("shard_enc");
    let dec_dir = tempdir("shard_dec");
    let options = DirectoryEncodeOptions {
        segment_plaintext_budget: DIRECTORY_TEST_SEGMENT_BUDGET,
        ..DirectoryEncodeOptions::default()
    };
    let archive =
        encode_directory_with_options(&ZERO_KEY, &src, &enc_dir, options).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );

    let (_, body) = decode(&ZERO_KEY, &fs::read(&catalog_path).expect("read")).expect("decode");
    let (adam_payload, _) = decode_adamantine(&body).expect("adam");
    let (rkyv, _) = split_adamantine_payload(&adam_payload).expect("split");
    let index =
        FilepackManifest::from_bytes_with_root(&rkyv, archive.catalog_bao_root).expect("manifest");
    assert_eq!(index.entries[0].segments.len(), 3);

    decode_directory(&ZERO_KEY, &catalog_path, &dec_dir).expect("decode");
    assert_eq!(fs::read(dec_dir.join("big.bin")).expect("read"), big);
}

#[test]
fn directory_decode_rejects_out_of_range_bao_bundle_offset() {
    let src = tempdir("bundle_bad_src");
    fs::write(src.join("one.txt"), b"hello").expect("write");
    let enc_dir = tempdir("bundle_bad_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );

    let (manifest, mut parts) =
        load_catalog_manifest_and_parts(&catalog_path, &archive.catalog_bao_root);
    let seg = &manifest.entries[0].segments[0];
    let ver_end = seg
        .verification_outboard_offset
        .saturating_add(seg.verification_outboard_len);
    parts.bundle.truncate(ver_end.saturating_sub(1) as usize);

    let err = manifest
        .validate_bao_bundle_refs(parts.bundle.len())
        .unwrap_err();
    assert!(
        matches!(
            err,
            CarbonadoError::InvalidFilepackManifest(ref m) if m.contains("exceeds bundle length")
        ),
        "out-of-range verification_outboard must fail validate_bao_bundle_refs, got {err:?}"
    );

    let tampered = write_tampered_catalog(&enc_dir, &manifest, &parts);
    let err = decode_directory(&ZERO_KEY, &tampered, &tempdir("ver_oor_dec")).unwrap_err();
    assert!(
        matches!(
            err,
            CarbonadoError::InvalidFilepackManifest(ref m) if m.contains("exceeds bundle length")
        ),
        "decode_directory must reject out-of-range verification_outboard, got {err:?}"
    );
}

#[test]
fn directory_decode_rejects_out_of_range_fec_parity_offset() {
    let src = tempdir("fec_bad_src");
    fs::write(src.join("one.txt"), b"hello").expect("write");
    let enc_dir = tempdir("fec_bad_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );

    let (manifest, mut parts) =
        load_catalog_manifest_and_parts(&catalog_path, &archive.catalog_bao_root);
    let seg = &manifest.entries[0].segments[0];
    let fec_end = seg.fec_parity_offset.saturating_add(seg.fec_parity_len);
    parts.bundle.truncate(fec_end.saturating_sub(1) as usize);

    let err = manifest
        .validate_bao_bundle_refs(parts.bundle.len())
        .unwrap_err();
    assert!(
        matches!(
            err,
            CarbonadoError::InvalidFilepackManifest(ref m) if m.contains("fec_parity range")
        ),
        "out-of-range fec_parity must fail validate_bao_bundle_refs, got {err:?}"
    );

    let tampered = write_tampered_catalog(&enc_dir, &manifest, &parts);
    let err = decode_directory(&ZERO_KEY, &tampered, &tempdir("fec_oor_dec")).unwrap_err();
    assert!(
        matches!(
            err,
            CarbonadoError::InvalidFilepackManifest(ref m) if m.contains("fec_parity range")
        ),
        "decode_directory must reject out-of-range fec_parity, got {err:?}"
    );
}

#[test]
fn zero_byte_file_roundtrip() {
    let src = tempdir("zero_byte_src");
    fs::write(src.join("empty.bin"), &[] as &[u8]).expect("write empty");
    let enc_dir = tempdir("zero_byte_enc");
    let dec_dir = tempdir("zero_byte_dec");
    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );
    decode_directory(&ZERO_KEY, &catalog_path, &dec_dir).expect("decode zero-byte file");
    assert_eq!(fs::read(dec_dir.join("empty.bin")).expect("read"), b"");
}

#[test]
fn directory_decode_rejects_missing_fec_parity_in_bundle() {
    let src = tempdir("miss_fec_src");
    fs::write(src.join("one.txt"), b"payload").expect("write");
    let enc_dir = tempdir("miss_fec_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );

    let (mut manifest, parts) =
        load_catalog_manifest_and_parts(&catalog_path, &archive.catalog_bao_root);
    manifest.entries[0].segments[0].fec_parity_len = 0;

    let err = manifest
        .validate_bao_bundle_refs(parts.bundle.len())
        .unwrap_err();
    assert!(
        matches!(err, CarbonadoError::MissingFecParity),
        "zero fec_parity_len on non-empty segment must be MissingFecParity, got {err:?}"
    );

    let tampered = write_tampered_catalog(&enc_dir, &manifest, &parts);
    let err = decode_directory(&ZERO_KEY, &tampered, &tempdir("miss_fec_dec")).unwrap_err();
    assert!(
        matches!(err, CarbonadoError::MissingFecParity),
        "decode_directory E2E must return MissingFecParity, got {err:?}"
    );
}

#[test]
fn directory_decode_rejects_legacy_c4_segment_format() {
    let src = tempdir("legacy_src");
    fs::write(src.join("one.txt"), b"x").expect("write");
    let enc_dir = tempdir("legacy_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );

    let (mut manifest, parts) =
        load_catalog_manifest_and_parts(&catalog_path, &archive.catalog_bao_root);
    manifest.entries[0].segment_format = 0x04;

    let err = manifest.validate().unwrap_err();
    assert!(
        matches!(err, CarbonadoError::InvalidFilepackManifest(ref m) if m.contains("c4–c7")),
        "legacy c4 segment_format must be rejected, got {err:?}"
    );

    let tampered = write_tampered_catalog(&enc_dir, &manifest, &parts);
    let err = decode_directory(&ZERO_KEY, &tampered, &tempdir("legacy_c4_dec")).unwrap_err();
    assert!(
        matches!(err, CarbonadoError::InvalidFilepackManifest(ref m) if m.contains("c4–c7")),
        "decode_directory E2E must reject legacy c4, got {err:?}"
    );
}

#[test]
fn directory_decode_rejects_fec_geometry_mismatch() {
    let src = tempdir("fec_geom_src");
    fs::write(src.join("one.txt"), b"hello geometry test").expect("write");
    let enc_dir = tempdir("fec_geom_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );

    let (mut manifest, parts) =
        load_catalog_manifest_and_parts(&catalog_path, &archive.catalog_bao_root);
    manifest.entries[0].segments[0].fec_parity_len = 1;

    let err = manifest
        .validate_bao_bundle_refs(parts.bundle.len())
        .unwrap_err();
    assert!(
        matches!(
            err,
            CarbonadoError::InvalidFilepackManifest(ref m) if m.contains("fec_parity_len")
        ),
        "fec geometry mismatch must fail validate_bao_bundle_refs, got {err:?}"
    );

    let tampered = write_tampered_catalog(&enc_dir, &manifest, &parts);
    let err = decode_directory(&ZERO_KEY, &tampered, &tempdir("fec_geom_dec")).unwrap_err();
    assert!(
        matches!(
            err,
            CarbonadoError::InvalidFilepackManifest(ref m) if m.contains("fec_parity_len")
        ),
        "decode_directory E2E must reject fec geometry mismatch, got {err:?}"
    );
}

#[test]
fn encode_rejects_segment_main_over_max_len() {
    use std::io::Write as _;

    let src = tempdir("oversized_src");
    let path = src.join("huge.bin");
    let mut f = fs::File::create(&path).expect("create huge");
    let chunk = vec![0xABu8; 1024 * 1024];
    let chunks = (MAX_SEGMENT_MAIN_LEN / chunk.len() as u64) as usize + 2;
    for _ in 0..chunks {
        f.write_all(&chunk).expect("write chunk");
    }
    f.flush().expect("flush");

    let enc_dir = tempdir("oversized_enc");
    let options = DirectoryEncodeOptions {
        segment_format_policy: SegmentFormatPolicy::ForceC12,
        ..DirectoryEncodeOptions::default()
    };
    let err = encode_directory_with_options(&ZERO_KEY, &src, &enc_dir, options).unwrap_err();
    assert!(
        matches!(
            err,
            CarbonadoError::InvalidFilepackManifest(ref m)
                if m.contains("encoded segment main exceeds maximum")
        ),
        "encode must reject segment main over MAX_SEGMENT_MAIN_LEN, got {err:?}"
    );
}

#[test]
fn directory_decode_rejects_non_contiguous_fec_parity_offset() {
    let src = tempdir("contig_src");
    fs::write(src.join("one.txt"), b"hello overlap test").expect("write");
    let enc_dir = tempdir("contig_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );

    let (mut manifest, parts) =
        load_catalog_manifest_and_parts(&catalog_path, &archive.catalog_bao_root);
    manifest.entries[0].segments[0].fec_parity_offset =
        manifest.entries[0].segments[0].verification_outboard_offset + 1;

    let err = manifest
        .validate_bao_bundle_refs(parts.bundle.len())
        .unwrap_err();
    assert!(
        matches!(
            err,
            CarbonadoError::InvalidFilepackManifest(ref m) if m.contains("contiguously")
        ),
        "non-contiguous fec_parity_offset must be rejected, got {err:?}"
    );

    let tampered = write_tampered_catalog(&enc_dir, &manifest, &parts);
    let err = decode_directory(&ZERO_KEY, &tampered, &tempdir("contig_dec")).unwrap_err();
    assert!(
        matches!(
            err,
            CarbonadoError::InvalidFilepackManifest(ref m) if m.contains("contiguously")
        ),
        "decode_directory E2E must reject non-contiguous fec_parity_offset, got {err:?}"
    );
}

#[test]
fn decode_rejects_segment_format_suffix_mismatch() {
    let src = tempdir("suffix_src");
    fs::copy(samples_dir().join("content.png"), src.join("content.png")).expect("copy");
    let enc_dir = tempdir("suffix_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );

    let (_, body) = decode(&ZERO_KEY, &fs::read(&catalog_path).expect("read")).expect("decode");
    let (adam_payload, _) = decode_adamantine(&body).expect("adam");
    let (rkyv, _) = split_adamantine_payload(&adam_payload).expect("split");
    let manifest =
        FilepackManifest::from_bytes_with_root(&rkyv, archive.catalog_bao_root).expect("manifest");
    let entry = manifest
        .entries
        .iter()
        .find(|e| e.rel_path == "content.png")
        .expect("content.png");
    assert_eq!(entry.segment_format, SEGMENT_FORMAT_PUBLIC_RAW);
    let seg = &entry.segments[0];
    let correct_path = enc_dir.join(format!(
        "{}.c{}",
        hex32(&seg.segment_bao_root),
        entry.segment_format
    ));
    let wrong_path = enc_dir.join(format!("{}.c14", hex32(&seg.segment_bao_root)));
    fs::rename(&correct_path, &wrong_path).expect("rename segment to wrong suffix");

    let err = decode_directory(&ZERO_KEY, &catalog_path, &tempdir("suffix_dec")).unwrap_err();
    assert!(
        matches!(
            err,
            CarbonadoError::DirectoryLayoutMismatch(ref m)
                if m.contains("format suffix does not match manifest segment_format")
        ),
        "decode_directory must reject on-disk format suffix mismatch, got {err:?}"
    );
}

#[test]
fn directory_decode_rejects_bundle_range_overlap() {
    let src = tempdir("overlap_src");
    let big = vec![0xCDu8; (DIRECTORY_TEST_SEGMENT_BUDGET * 2 + 1) as usize];
    fs::write(src.join("big.bin"), &big).expect("write");
    let enc_dir = tempdir("overlap_enc");
    let options = DirectoryEncodeOptions {
        segment_plaintext_budget: DIRECTORY_TEST_SEGMENT_BUDGET,
        ..DirectoryEncodeOptions::default()
    };
    let archive =
        encode_directory_with_options(&ZERO_KEY, &src, &enc_dir, options).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );

    let (mut manifest, parts) =
        load_catalog_manifest_and_parts(&catalog_path, &archive.catalog_bao_root);
    assert!(
        manifest.entries[0].segments.len() >= 2,
        "overlap test requires a multi-segment archive"
    );
    let first_fec_end = {
        let first = &manifest.entries[0].segments[0];
        first.fec_parity_offset.saturating_add(first.fec_parity_len)
    };
    {
        let second = &mut manifest.entries[0].segments[1];
        second.verification_outboard_offset = first_fec_end.saturating_sub(1);
        second.fec_parity_offset = second
            .verification_outboard_offset
            .saturating_add(second.verification_outboard_len);
    }

    let err = manifest
        .validate_bao_bundle_refs(parts.bundle.len())
        .unwrap_err();
    assert!(
        matches!(
            err,
            CarbonadoError::InvalidFilepackManifest(ref m) if m.contains("overlap")
        ),
        "overlapping bundle ranges must be rejected, got {err:?}"
    );

    let tampered = write_tampered_catalog(&enc_dir, &manifest, &parts);
    let err = decode_directory(&ZERO_KEY, &tampered, &tempdir("overlap_dec")).unwrap_err();
    assert!(
        matches!(
            err,
            CarbonadoError::InvalidFilepackManifest(ref m) if m.contains("overlap")
        ),
        "decode_directory E2E must reject bundle overlap, got {err:?}"
    );
}

#[test]
fn decode_rejects_tampered_catalog_body_returns_verification_failed() {
    let src = tempdir("tamper_body_src");
    fs::write(src.join("one.txt"), b"x").expect("write");
    let enc_dir = tempdir("tamper_body_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );

    let mut bytes = fs::read(&catalog_path).expect("read catalog");
    if bytes.len() > carbonado::file::Header::LEN + 32 {
        bytes[carbonado::file::Header::LEN + 16] ^= 0xFF;
    }
    let tampered = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );
    fs::write(&tampered, &bytes).expect("write tampered");

    let err = decode_directory(&ZERO_KEY, &tampered, &tempdir("tamper_body_dec")).unwrap_err();
    assert!(
        matches!(
            err,
            CarbonadoError::OutboardVerificationFailed(_) | CarbonadoError::AuthenticationFailed
        ),
        "tampered catalog body must not map to CatalogBaoRootMismatch; got {err:?}"
    );
}

#[test]
fn encode_rollback_removes_segments_on_symlink_error() {
    let src = tempdir("symlink_src");
    fs::write(src.join("good.txt"), b"hello").expect("write");
    #[cfg(unix)]
    std::os::unix::fs::symlink(src.join("good.txt"), src.join("link")).expect("symlink");
    #[cfg(not(unix))]
    {
        // Non-Unix: skip symlink semantics; covered by catalog rollback test below.
        return;
    }

    let enc_dir = tempdir("symlink_enc");
    let err = encode_directory(&ZERO_KEY, &src, &enc_dir).unwrap_err();
    assert!(matches!(err, CarbonadoError::SymlinkNotAllowed(_)));
    assert_no_bare_segment_mains(&enc_dir);
}

#[test]
#[cfg(debug_assertions)]
fn encode_rollback_removes_segments_on_catalog_assembly_failure() {
    use carbonado::file::directory_encode_test_hooks::arm_catalog_write_failure;

    let src = tempdir("cat_fail_src");
    fs::write(src.join("one.txt"), b"payload").expect("write");
    let enc_dir = tempdir("cat_fail_enc");
    arm_catalog_write_failure();
    let err = encode_directory(&ZERO_KEY, &src, &enc_dir).unwrap_err();
    assert!(matches!(err, CarbonadoError::StdIoError(_)));
    assert_no_bare_segment_mains(&enc_dir);
    assert!(
        fs::read_dir(&enc_dir)
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .all(|e| { !e.file_name().to_string_lossy().contains(".adam.c") }),
        "catalog artifact must not remain after failed assembly"
    );
}

#[test]
fn empty_directory_roundtrip() {
    let src = tempdir("empty_src");
    let enc_dir = tempdir("empty_enc");
    let dec_dir = tempdir("empty_dec");

    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode empty");
    assert_eq!(archive.entry_count, 0);
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );
    decode_directory(&ZERO_KEY, &catalog_path, &dec_dir).expect("decode empty");
    assert_trees_equal(&src, &dec_dir);
}

#[test]
fn encode_rejects_zero_master_on_encrypted() {
    let src = tempdir("zero_key_src");
    fs::write(src.join("one.txt"), b"x").expect("write");
    let enc_dir = tempdir("zero_key_enc");
    let options = DirectoryEncodeOptions {
        encrypted: true,
        ..DirectoryEncodeOptions::default()
    };
    let err = encode_directory_with_options(&ZERO_KEY, &src, &enc_dir, options).unwrap_err();
    assert!(matches!(err, CarbonadoError::ZeroMasterKeyNotAllowed));
}

#[test]
fn decode_rejects_nonzero_master_on_public() {
    let src = tempdir("nz_key_src");
    fs::write(src.join("one.txt"), b"x").expect("write");
    let enc_dir = tempdir("nz_key_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );
    let dec_dir = tempdir("nz_key_dec");
    let err = decode_directory(&TEST_MASTER, &catalog_path, &dec_dir).unwrap_err();
    assert!(matches!(
        err,
        CarbonadoError::EncryptedDirectoryNotRequested
    ));
}

#[test]
fn decode_rejects_path_traversal_writes_no_files() {
    let src = tempdir("mal_src");
    fs::write(src.join("one.txt"), b"hello").expect("write source");
    let enc_dir = tempdir("mal_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode");
    let good_catalog = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );

    let (_, body) = decode(&ZERO_KEY, &fs::read(&good_catalog).expect("read")).expect("decode");
    let (adam_payload, hdr) = decode_adamantine(&body).expect("adam");
    let (rkyv, bundle) = split_adamantine_payload(&adam_payload).expect("split");
    let good_index =
        FilepackManifest::from_bytes_with_root(&rkyv, archive.catalog_bao_root).expect("index");
    let entry = good_index.entries.first().expect("one entry");

    let malicious = FilepackManifest {
        version: FILEPACK_MANIFEST_VERSION,
        format_level: FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
        catalog_bao_root: [0u8; 32],
        catalog_ots_proof: None,
        entries: vec![FilepackEntry {
            rel_path: "../escape.txt".into(),
            content_blake3: entry.content_blake3,
            segment_format: entry.segment_format,
            segments: entry.segments.clone(),
            ots_proof: None,
        }],
    };
    let mal_rkyv = malicious.to_bytes().expect("malicious rkyv");
    let mal_payload = build_adamantine_payload(&mal_rkyv, &bundle).expect("build payload");
    let mal_adam = encode_adamantine(&mal_payload, ADAMANTINE_CARBONADO_FMT_PUBLIC, hdr.flags);
    let (mal_encoded, _) =
        carbonado::file::encode(&ZERO_KEY, &mal_adam, DIRECTORY_ARCHIVE_FORMAT, None)
            .expect("encode malicious catalog");
    let mal_header =
        carbonado::file::Header::try_from(&mal_encoded[..carbonado::file::Header::LEN])
            .expect("header");
    let mal_root = *mal_header.hash.as_bytes();
    let mal_catalog = adam_catalog_path(&enc_dir, &mal_root, DIRECTORY_ARCHIVE_FORMAT);
    fs::write(&mal_catalog, &mal_encoded).expect("write malicious catalog");

    let dec_dir = tempdir("mal_dec");
    let err = decode_directory(&ZERO_KEY, &mal_catalog, &dec_dir).unwrap_err();
    assert!(
        matches!(
            err,
            CarbonadoError::InvalidFilepackManifest(ref msg) if msg.contains("..")
        ),
        "got {err:?}"
    );
    assert!(
        fs::read_dir(&dec_dir)
            .map(|mut d| d.next())
            .expect("read_dir")
            .is_none(),
        "decode_directory must not write files on path traversal"
    );
}

#[test]
fn decode_rejects_oversized_segment_without_reading_full_file() {
    let src = tempdir("oversize_src");
    fs::write(src.join("one.txt"), b"small payload").expect("write");
    let enc_dir = tempdir("oversize_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );

    let catalog_bytes = fs::read(&catalog_path).expect("read catalog");
    let (_, body) = decode(&ZERO_KEY, &catalog_bytes).expect("decode catalog");
    let (adam_payload, _) = decode_adamantine(&body).expect("adam");
    let (rkyv, _) = split_adamantine_payload(&adam_payload).expect("split");
    let index =
        FilepackManifest::from_bytes_with_root(&rkyv, archive.catalog_bao_root).expect("index");
    let entry = &index.entries[0];
    let seg = &entry.segments[0];
    let seg_path = enc_dir.join(format!(
        "{}.c{}",
        hex32(&seg.segment_bao_root),
        entry.segment_format
    ));
    let expected_len = seg.main_len;

    // Sparse extend on disk without materializing trailing bytes.
    let f = fs::OpenOptions::new()
        .write(true)
        .open(&seg_path)
        .expect("open segment");
    f.set_len(expected_len.saturating_add(50_000_000))
        .expect("set_len");
    assert!(
        fs::metadata(&seg_path).expect("metadata").len() > expected_len,
        "segment file should be larger than manifest main_len"
    );

    let dec_dir = tempdir("oversize_dec");
    let err = decode_directory(&ZERO_KEY, &catalog_path, &dec_dir).unwrap_err();
    match err {
        CarbonadoError::SegmentMainLenMismatch {
            rel_path,
            chunk_index: 0,
        } => assert_eq!(rel_path, "one.txt"),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn decode_rejects_content_blake3_mismatch() {
    let src = tempdir("blake3_src");
    fs::write(src.join("one.txt"), b"original").expect("write");
    let enc_dir = tempdir("blake3_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );

    let (_, body) = decode(&ZERO_KEY, &fs::read(&catalog_path).expect("read")).expect("decode");
    let (adam_payload, hdr) = decode_adamantine(&body).expect("adam");
    let (rkyv, bundle) = split_adamantine_payload(&adam_payload).expect("split");
    let mut index =
        FilepackManifest::from_bytes_with_root(&rkyv, archive.catalog_bao_root).expect("index");
    index.entries[0].content_blake3 = [0xFF; 32];
    let bad_rkyv = index.to_bytes().expect("to_bytes");
    let bad_payload = build_adamantine_payload(&bad_rkyv, &bundle).expect("payload");
    let bad_adam = encode_adamantine(&bad_payload, ADAMANTINE_CARBONADO_FMT_PUBLIC, hdr.flags);
    let (bad_encoded, _) =
        carbonado::file::encode(&ZERO_KEY, &bad_adam, DIRECTORY_ARCHIVE_FORMAT, None)
            .expect("re-encode");
    let bad_header =
        carbonado::file::Header::try_from(&bad_encoded[..carbonado::file::Header::LEN])
            .expect("header");
    let bad_root = *bad_header.hash.as_bytes();
    let bad_catalog = adam_catalog_path(&enc_dir, &bad_root, DIRECTORY_ARCHIVE_FORMAT);
    fs::write(&bad_catalog, &bad_encoded).expect("write bad catalog");

    let dec_dir = tempdir("blake3_dec");
    let err = decode_directory(&ZERO_KEY, &bad_catalog, &dec_dir).unwrap_err();
    assert!(matches!(err, CarbonadoError::ContentBlake3Mismatch(_)));
}

#[test]
fn adamantine_v1_magic_and_header_len() {
    let wrapped = encode_adamantine(b"payload", ADAMANTINE_CARBONADO_FMT_PUBLIC, 0);
    assert_eq!(&wrapped[0..13], ADAMANTINE_MAGIC);
    assert_eq!(wrapped[13], ADAMANTINE_CARBONADO_FMT_PUBLIC);
    assert_eq!(
        wrapped.len(),
        carbonado::adamantine::ADAMANTINE_HEADER_LEN + 7
    );
}

#[test]
fn adamantine_rejects_dev_v2_magic() {
    let mut bytes = encode_adamantine(b"x", ADAMANTINE_CARBONADO_FMT_PUBLIC, 0);
    bytes[0..12].copy_from_slice(b"ADAMANTINE2\n");
    let err = decode_adamantine(&bytes).unwrap_err();
    assert!(matches!(
        err,
        CarbonadoError::UnsupportedAdamantineVersion { major: 2, minor: 0 }
    ));
}

#[test]
fn adamantine_rejects_invalid_catalog_fmt() {
    let mut bytes = encode_adamantine(b"x", ADAMANTINE_CARBONADO_FMT_PUBLIC, 0);
    bytes[13] = 6;
    let err = decode_adamantine(&bytes).unwrap_err();
    assert!(matches!(
        err,
        CarbonadoError::InvalidAdamantineCarbonadoFormat(6)
    ));
}

#[test]
fn single_file_encode_decode_regression() {
    let sample = samples_dir().join("content.png");
    let data = fs::read(&sample).expect("read sample");
    let outdir = tempdir("single");

    let oenc = encode_outboard(&ZERO_KEY, &data, DIRECTORY_ARCHIVE_FORMAT).expect("encode");
    let root = *oenc.hash.as_bytes();
    let hhex = hex32(&root);
    let main_path = outdir.join(format!("{}.c{:02x}", hhex, DIRECTORY_ARCHIVE_FORMAT));
    fs::write(&main_path, &oenc.main).expect("write main");
    if let Some(ob) = &oenc.verification_outboard {
        fs::write(
            outdir.join(format!("{}.c{:02x}.out", hhex, DIRECTORY_ARCHIVE_FORMAT)),
            ob,
        )
        .expect("write out");
    }

    let rec = decode_outboard(
        &ZERO_KEY,
        &root,
        &oenc.main,
        oenc.verification_outboard.as_deref(),
        oenc.fec_parity.as_deref(),
        oenc.info.padding_len,
        DIRECTORY_ARCHIVE_FORMAT,
    )
    .expect("decode");
    assert_eq!(rec, data);
}

#[cfg(feature = "ots")]
#[test]
fn ots_entry_and_catalog_wire_roundtrip() {
    let src = tempdir("ots_src");
    fs::write(src.join("one.txt"), b"ots test payload").expect("write");

    let enc_dir = tempdir("ots_enc");
    let dec_dir = tempdir("ots_dec");
    let options = DirectoryEncodeOptions {
        ots_policy: Some(OtsPolicy {
            stamp_entries: true,
            stamp_catalog: true,
        }),
        ..DirectoryEncodeOptions::default()
    };
    let archive =
        encode_directory_with_options(&ZERO_KEY, &src, &enc_dir, options).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );
    assert_no_directory_sidecars(&enc_dir);

    let catalog_bytes = fs::read(&catalog_path).expect("read");
    assert!(
        catalog_bytes.windows(4).any(|w| w == b"COTS"),
        "catalog file should contain COTS trailer when stamp_catalog is set"
    );
    let (_, body) = decode(&ZERO_KEY, &catalog_bytes).expect("decode");
    let (adam_payload, hdr) = decode_adamantine(&body).expect("adam");
    assert_ne!(hdr.flags & ADAMANTINE_FLAG_REQUIRE_OTS, 0);
    let (rkyv, _) = split_adamantine_payload(&adam_payload).expect("split");
    let index =
        FilepackManifest::from_bytes_with_root(&rkyv, archive.catalog_bao_root).expect("index");
    let proof = index.entries[0].ots_proof.as_ref().expect("entry ots");
    let primary_root = index.entries[0].segments[0].segment_bao_root;
    assert!(
        verify_stamp(proof, &primary_root)
            .expect("verify entry")
            .valid
    );
    let catalog_ots = catalog_ots_proof_from_cots_trailer(&catalog_bytes).expect("catalog ots");
    assert!(
        verify_stamp(&catalog_ots, &archive.catalog_bao_root)
            .expect("verify catalog")
            .valid
    );

    decode_directory(&ZERO_KEY, &catalog_path, &dec_dir).expect("decode");
    assert_eq!(
        fs::read(dec_dir.join("one.txt")).expect("read"),
        b"ots test payload"
    );
}

#[cfg(feature = "ots")]
#[test]
fn decode_rejects_tampered_entry_ots_proof() {
    let src = tempdir("ots_tamper_src");
    fs::write(src.join("one.txt"), b"tamper me").expect("write");
    let enc_dir = tempdir("ots_tamper_enc");
    let dec_dir = tempdir("ots_tamper_dec");
    let options = DirectoryEncodeOptions {
        ots_policy: Some(OtsPolicy {
            stamp_entries: true,
            stamp_catalog: false,
        }),
        ..DirectoryEncodeOptions::default()
    };
    let archive =
        encode_directory_with_options(&ZERO_KEY, &src, &enc_dir, options).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );

    let (_, body) = decode(&ZERO_KEY, &fs::read(&catalog_path).expect("read")).expect("decode");
    let (adam_payload, hdr) = decode_adamantine(&body).expect("adam");
    let (rkyv, bundle) = split_adamantine_payload(&adam_payload).expect("split");
    let mut index =
        FilepackManifest::from_bytes_with_root(&rkyv, archive.catalog_bao_root).expect("index");
    let proof = index.entries[0].ots_proof.as_mut().expect("proof");
    if let Some(byte) = proof.first_mut() {
        *byte ^= 0xFF;
    }
    let tampered_rkyv = index.to_bytes().expect("to_bytes");
    let tampered_payload = build_adamantine_payload(&tampered_rkyv, &bundle).expect("payload");
    let tampered_adam = encode_adamantine(
        &tampered_payload,
        ADAMANTINE_CARBONADO_FMT_PUBLIC,
        hdr.flags,
    );
    let (tampered_encoded, _) =
        carbonado::file::encode(&ZERO_KEY, &tampered_adam, DIRECTORY_ARCHIVE_FORMAT, None)
            .expect("re-encode");
    let tampered_header =
        carbonado::file::Header::try_from(&tampered_encoded[..carbonado::file::Header::LEN])
            .expect("header");
    let tampered_root = *tampered_header.hash.as_bytes();
    let tampered_catalog = adam_catalog_path(&enc_dir, &tampered_root, DIRECTORY_ARCHIVE_FORMAT);
    fs::write(&tampered_catalog, &tampered_encoded).expect("write tampered");

    let err = decode_directory(&ZERO_KEY, &tampered_catalog, &dec_dir).unwrap_err();
    assert!(matches!(err, CarbonadoError::OtsVerificationFailed));
}

/// Extract catalog OTS proof from optional `COTS` file trailer (mirrors on-disk layout).
fn catalog_ots_proof_from_cots_trailer(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() < carbonado::file::Header::LEN + 8 {
        return None;
    }
    let max_scan = carbonado::filepack_manifest::MAX_OTS_PROOF_LEN + 8;
    let scan_start = bytes
        .len()
        .saturating_sub(max_scan)
        .max(carbonado::file::Header::LEN);
    for i in (scan_start..=bytes.len().saturating_sub(8)).rev() {
        if bytes.get(i..i + 4)? != b"COTS" {
            continue;
        }
        let ots_len = u32::from_le_bytes(bytes[i + 4..i + 8].try_into().ok()?) as usize;
        if ots_len > carbonado::filepack_manifest::MAX_OTS_PROOF_LEN {
            return None;
        }
        if i + 8 + ots_len == bytes.len() {
            return Some(bytes[i + 8..].to_vec());
        }
    }
    None
}

#[test]
fn decode_rejects_invalid_adamantine_flags() {
    let src = tempdir("flags_src");
    fs::write(src.join("one.txt"), b"x").expect("write");
    let enc_dir = tempdir("flags_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );
    let (_, body) = decode(&ZERO_KEY, &fs::read(&catalog_path).expect("read")).expect("decode");
    let (payload, _) = decode_adamantine(&body).expect("adam");
    let wrapped = encode_adamantine(&payload, ADAMANTINE_CARBONADO_FMT_PUBLIC, 0x02);
    let (encoded, _) =
        carbonado::file::encode(&ZERO_KEY, &wrapped, DIRECTORY_ARCHIVE_FORMAT, None).expect("enc");
    let header =
        carbonado::file::Header::try_from(&encoded[..carbonado::file::Header::LEN]).expect("hdr");
    let root = *header.hash.as_bytes();
    let bad_catalog = adam_catalog_path(&enc_dir, &root, DIRECTORY_ARCHIVE_FORMAT);
    fs::write(&bad_catalog, &encoded).expect("write");
    let err = decode_directory(&ZERO_KEY, &bad_catalog, &tempdir("flags_dec")).unwrap_err();
    assert!(matches!(err, CarbonadoError::InvalidAdamantineFlags(0x02)));
}

#[test]
fn decode_rejects_catalog_bao_root_filename_mismatch() {
    let src = tempdir("root_src");
    fs::write(src.join("one.txt"), b"x").expect("write");
    let enc_dir = tempdir("root_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );
    let bytes = fs::read(&catalog_path).expect("read");
    let wrong_root = [0xCDu8; 32];
    let wrong_path = adam_catalog_path(&enc_dir, &wrong_root, DIRECTORY_ARCHIVE_FORMAT);
    fs::write(&wrong_path, &bytes).expect("write wrong name");
    let err = decode_directory(&ZERO_KEY, &wrong_path, &tempdir("root_dec")).unwrap_err();
    assert!(matches!(err, CarbonadoError::CatalogBaoRootMismatch));
}

#[test]
fn decode_rejects_adamantine_format_filename_mismatch() {
    let src = tempdir("fmt_src");
    fs::write(src.join("one.txt"), b"x").expect("write");
    let enc_dir = tempdir("fmt_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );
    let (_, body) = decode(&ZERO_KEY, &fs::read(&catalog_path).expect("read")).expect("decode");
    let (payload, _) = decode_adamantine(&body).expect("adam");
    let wrapped = encode_adamantine(&payload, ADAMANTINE_CARBONADO_FMT_ENCRYPTED, 0);
    let (encoded, _) =
        carbonado::file::encode(&ZERO_KEY, &wrapped, DIRECTORY_ARCHIVE_FORMAT, None).expect("enc");
    let header =
        carbonado::file::Header::try_from(&encoded[..carbonado::file::Header::LEN]).expect("hdr");
    let root = *header.hash.as_bytes();
    let mismatched = adam_catalog_path(&enc_dir, &root, DIRECTORY_ARCHIVE_FORMAT);
    fs::write(&mismatched, &encoded).expect("write");
    let err = decode_directory(&ZERO_KEY, &mismatched, &tempdir("fmt_dec")).unwrap_err();
    assert!(matches!(
        err,
        CarbonadoError::AdamantineFormatFilenameMismatch {
            header: ADAMANTINE_CARBONADO_FMT_ENCRYPTED,
            filename: DIRECTORY_ARCHIVE_FORMAT
        }
    ));
}

#[test]
fn decode_rejects_non_inboard_catalog_layout() {
    let src = tempdir("layout_src");
    fs::write(src.join("one.txt"), b"x").expect("write");
    let enc_dir = tempdir("layout_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );
    fs::write(&catalog_path, b"not-a-carbonado-header").expect("overwrite");
    let err = decode_directory(&ZERO_KEY, &catalog_path, &tempdir("layout_dec")).unwrap_err();
    assert!(matches!(
        err,
        CarbonadoError::DirectoryLayoutMismatch(ref msg) if msg.contains("inboard")
    ));
}

#[test]
fn decode_rejects_missing_segment_file() {
    let src = tempdir("miss_src");
    fs::write(src.join("one.txt"), b"payload").expect("write");
    let enc_dir = tempdir("miss_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );
    let (_, body) = decode(&ZERO_KEY, &fs::read(&catalog_path).expect("read")).expect("decode");
    let (adam_payload, _) = decode_adamantine(&body).expect("adam");
    let (rkyv, _) = split_adamantine_payload(&adam_payload).expect("split");
    let index =
        FilepackManifest::from_bytes_with_root(&rkyv, archive.catalog_bao_root).expect("index");
    let seg = &index.entries[0].segments[0];
    let seg_name = format!(
        "{}.c{}",
        hex32(&seg.segment_bao_root),
        index.entries[0].segment_format
    );
    fs::remove_file(enc_dir.join(&seg_name)).expect("remove segment");
    let err = decode_directory(&ZERO_KEY, &catalog_path, &tempdir("miss_dec")).unwrap_err();
    assert!(matches!(err, CarbonadoError::MissingSegment(_)));
}

#[test]
fn decode_rejects_segment_main_len_mismatch() {
    let src = tempdir("len_src");
    fs::write(src.join("one.txt"), b"payload").expect("write");
    let enc_dir = tempdir("len_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );
    let (_, body) = decode(&ZERO_KEY, &fs::read(&catalog_path).expect("read")).expect("decode");
    let (adam_payload, _) = decode_adamantine(&body).expect("adam");
    let (rkyv, _) = split_adamantine_payload(&adam_payload).expect("split");
    let index =
        FilepackManifest::from_bytes_with_root(&rkyv, archive.catalog_bao_root).expect("index");
    let entry = &index.entries[0];
    let seg = &entry.segments[0];
    let seg_path = enc_dir.join(format!(
        "{}.c{}",
        hex32(&seg.segment_bao_root),
        entry.segment_format
    ));
    let mut bytes = fs::read(&seg_path).expect("read seg");
    bytes.truncate(bytes.len().saturating_sub(1));
    fs::write(&seg_path, &bytes).expect("truncate seg");
    let err = decode_directory(&ZERO_KEY, &catalog_path, &tempdir("len_dec")).unwrap_err();
    assert!(matches!(
        err,
        CarbonadoError::SegmentMainLenMismatch {
            rel_path,
            chunk_index: 0
        } if rel_path == entry.rel_path
    ));
}

#[test]
fn decode_rejects_oversized_adamantine_bundle_len() {
    use carbonado::adamantine_payload::MAX_BAO_BUNDLE_LEN;

    let src = tempdir("dos_src");
    fs::write(src.join("one.txt"), b"x").expect("write");
    let enc_dir = tempdir("dos_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );
    let (_, body) = decode(&ZERO_KEY, &fs::read(&catalog_path).expect("read")).expect("decode");
    let (adam_payload, hdr) = decode_adamantine(&body).expect("adam");
    let (rkyv, _) = split_adamantine_payload(&adam_payload).expect("split");
    let mut evil = Vec::new();
    evil.extend_from_slice(&(rkyv.len() as u32).to_le_bytes());
    evil.extend_from_slice(&rkyv);
    evil.extend_from_slice(&((MAX_BAO_BUNDLE_LEN as u32).wrapping_add(1)).to_le_bytes());
    let evil_adam = encode_adamantine(&evil, ADAMANTINE_CARBONADO_FMT_PUBLIC, hdr.flags);
    let (encoded, _) =
        carbonado::file::encode(&ZERO_KEY, &evil_adam, DIRECTORY_ARCHIVE_FORMAT, None)
            .expect("enc");
    let header =
        carbonado::file::Header::try_from(&encoded[..carbonado::file::Header::LEN]).expect("hdr");
    let root = *header.hash.as_bytes();
    let evil_catalog = adam_catalog_path(&enc_dir, &root, DIRECTORY_ARCHIVE_FORMAT);
    fs::write(&evil_catalog, &encoded).expect("write");
    let err = decode_directory(&ZERO_KEY, &evil_catalog, &tempdir("dos_dec")).unwrap_err();
    assert!(matches!(
        err,
        CarbonadoError::InvalidAdamantinePayloadTooLarge { .. }
    ));
}

#[cfg(feature = "ots")]
#[test]
fn decode_rejects_missing_entry_ots_when_required() {
    let src = tempdir("ots_req_src");
    fs::write(src.join("one.txt"), b"x").expect("write");
    let enc_dir = tempdir("ots_req_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );
    let (_, body) = decode(&ZERO_KEY, &fs::read(&catalog_path).expect("read")).expect("decode");
    let (adam_payload, _) = decode_adamantine(&body).expect("adam");
    let (rkyv, bundle) = split_adamantine_payload(&adam_payload).expect("split");
    let mut index =
        FilepackManifest::from_bytes_with_root(&rkyv, archive.catalog_bao_root).expect("index");
    index.entries[0].ots_proof = None;
    let payload = build_adamantine_payload(&index.to_bytes().expect("bytes"), &bundle).expect("p");
    let adam = encode_adamantine(
        &payload,
        ADAMANTINE_CARBONADO_FMT_PUBLIC,
        ADAMANTINE_FLAG_REQUIRE_OTS,
    );
    let (encoded, _) =
        carbonado::file::encode(&ZERO_KEY, &adam, DIRECTORY_ARCHIVE_FORMAT, None).expect("enc");
    let header =
        carbonado::file::Header::try_from(&encoded[..carbonado::file::Header::LEN]).expect("hdr");
    let root = *header.hash.as_bytes();
    let bad_catalog = adam_catalog_path(&enc_dir, &root, DIRECTORY_ARCHIVE_FORMAT);
    fs::write(&bad_catalog, &encoded).expect("write");
    let err = decode_directory(&ZERO_KEY, &bad_catalog, &tempdir("ots_req_dec")).unwrap_err();
    assert!(matches!(
        err,
        CarbonadoError::OtsProofRequired(ref rel) if rel == "one.txt"
    ));
}

#[test]
fn decode_rejects_headered_segment_main_layout() {
    let src = tempdir("seg_layout_src");
    fs::write(src.join("one.txt"), b"hello").expect("write");
    let enc_dir = tempdir("seg_layout_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );
    let (_, body) = decode(&ZERO_KEY, &fs::read(&catalog_path).expect("read")).expect("decode");
    let (adam_payload, _) = decode_adamantine(&body).expect("adam");
    let (rkyv, _) = split_adamantine_payload(&adam_payload).expect("split");
    let index =
        FilepackManifest::from_bytes_with_root(&rkyv, archive.catalog_bao_root).expect("index");
    let entry = &index.entries[0];
    let seg = &entry.segments[0];
    let seg_path = enc_dir.join(format!(
        "{}.c{}",
        hex32(&seg.segment_bao_root),
        entry.segment_format
    ));
    let (inboard, _) =
        carbonado::file::encode(&ZERO_KEY, b"not valid segment", entry.segment_format, None)
            .expect("inboard");
    fs::write(&seg_path, &inboard).expect("overwrite segment with headered blob");
    let err = decode_directory(&ZERO_KEY, &catalog_path, &tempdir("seg_layout_dec")).unwrap_err();
    assert!(
        matches!(
            err,
            CarbonadoError::DirectoryLayoutMismatch(ref msg) if msg.contains("bare main")
        ),
        "unexpected error: {err:?}"
    );
}

/// Directory segments (c12–c15): verification + FEC parity live in the centralized bundle.
/// `scrub_outboard` recovers corrupt bare mains (≤4 shard taints) using bundle parity slices.
#[test]
fn directory_segment_corruption_bao_bundle_extract_scrub_roundtrip() {
    use common::corruption::{scattered_outboard_main_knockout, OutboardShardLayout};
    use rand::thread_rng;

    let src = tempdir("fec_scrub_src");
    fs::copy(samples_dir().join("content.png"), src.join("content.png")).expect("copy png");

    let enc_dir = tempdir("fec_scrub_enc");
    let dec_dir = tempdir("fec_scrub_dec");

    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode_directory");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );

    let catalog_bytes = fs::read(&catalog_path).expect("read catalog");
    let (_, carbonado_body) = decode(&ZERO_KEY, &catalog_bytes).expect("decode catalog");
    let (adam_payload, _) = decode_adamantine(&carbonado_body).expect("adamantine");
    let (rkyv_payload, bao_bundle) = split_adamantine_payload(&adam_payload).expect("split");
    let manifest = FilepackManifest::from_bytes_with_root(&rkyv_payload, archive.catalog_bao_root)
        .expect("manifest");
    manifest
        .validate_bao_bundle_refs(bao_bundle.len())
        .expect("bundle refs");

    let entry = manifest
        .entries
        .iter()
        .find(|e| e.rel_path == "content.png")
        .expect("content.png entry");
    assert_eq!(
        entry.segment_format, SEGMENT_FORMAT_PUBLIC_RAW,
        "content.png should be c12"
    );
    let seg_ref = &entry.segments[0];
    let segment_root = seg_ref.segment_bao_root;
    let seg_path = enc_dir.join(format!(
        "{}.c{}",
        hex32(&segment_root),
        entry.segment_format
    ));

    let bao_ob = verification_slice_from_bundle(
        &bao_bundle,
        seg_ref.verification_outboard_offset,
        seg_ref.verification_outboard_len,
    )
    .expect("verification_slice_from_bundle");
    let fec_par = fec_slice_from_bundle(
        &bao_bundle,
        seg_ref.fec_parity_offset,
        seg_ref.fec_parity_len,
    )
    .expect("fec_slice_from_bundle");
    assert!(
        seg_ref.fec_parity_len > 0 && !fec_par.is_empty(),
        "c12 segment must have non-empty FEC parity in bundle"
    );

    let plaintext = fs::read(src.join("content.png")).expect("read source");
    let oenc =
        encode_outboard(&ZERO_KEY, &plaintext, entry.segment_format).expect("encode_outboard");
    assert_eq!(
        oenc.verification_outboard.as_deref(),
        Some(bao_ob),
        "bundle verification slice must match encode-time outboard"
    );
    assert_eq!(
        oenc.fec_parity.as_deref(),
        Some(fec_par),
        "bundle FEC slice must match encode-time parity"
    );

    let pristine = oenc.main.clone();
    let mut seg_main = pristine.clone();
    let hash_bytes = segment_root;

    assert!(
        matches!(
            scrub_outboard(
                &seg_main,
                Some(bao_ob),
                Some(fec_par),
                &oenc.info,
                entry.segment_format,
                &hash_bytes
            ),
            Err(CarbonadoError::UnnecessaryScrub)
        ),
        "pristine segment main must not require scrub"
    );

    let layout = OutboardShardLayout::from_outboard_encode(
        seg_main.len(),
        fec_par.len(),
        oenc.info.chunk_len,
    );
    let mut rng = thread_rng();
    let report = scattered_outboard_main_knockout(&mut seg_main, &layout, 12, 4, &mut rng);
    assert!(
        report.shards_touched.len() <= 4,
        "knockout must stay within RS recovery budget, touched {:?}",
        report.shards_touched
    );
    assert!(
        !report.positions.is_empty(),
        "knockout must corrupt at least one byte before scrub"
    );
    fs::write(&seg_path, &seg_main).expect("write corrupted segment");

    let recovered = scrub_outboard(
        &seg_main,
        Some(bao_ob),
        Some(fec_par),
        &oenc.info,
        entry.segment_format,
        &hash_bytes,
    )
    .expect("scrub_outboard recovers within 4-shard budget");
    assert_eq!(recovered, pristine);
    fs::write(&seg_path, &recovered).expect("write scrubbed segment");

    let scrub_wrong_root = scrub_outboard(
        &seg_main,
        Some(bao_ob),
        Some(fec_par),
        &oenc.info,
        entry.segment_format,
        &[0xBBu8; 32],
    )
    .unwrap_err();
    assert!(
        matches!(scrub_wrong_root, CarbonadoError::InvalidScrubbedHash),
        "wrong Bao root must fail scrub with InvalidScrubbedHash, got {scrub_wrong_root:?}"
    );

    let mut over_budget = pristine.clone();
    over_budget.fill(0xFF);
    let mut bad_par = fec_par.to_vec();
    bad_par.fill(0xFF);
    let scrub_exhausted = scrub_outboard(
        &over_budget,
        Some(bao_ob),
        Some(&bad_par),
        &oenc.info,
        entry.segment_format,
        &hash_bytes,
    )
    .unwrap_err();
    assert!(
        matches!(scrub_exhausted, CarbonadoError::InvalidScrubbedHash),
        "exhausted FEC budget must return InvalidScrubbedHash, got {scrub_exhausted:?}"
    );

    decode_directory(&ZERO_KEY, &catalog_path, &dec_dir).expect("decode_directory after scrub");
    assert_trees_equal(&src, &dec_dir);
}

#[test]
fn directory_fec_scrub_matrix_c12_c13_c14_c15() {
    use common::corruption::{scattered_outboard_main_knockout, OutboardShardLayout};
    use rand::thread_rng;

    for (label, policy, key, encrypted) in [
        ("c12", SegmentFormatPolicy::ForceC12, ZERO_KEY, false),
        ("c13", SegmentFormatPolicy::ForceC13, TEST_MASTER, true),
        ("c14", SegmentFormatPolicy::ForceC14, ZERO_KEY, false),
        ("c15", SegmentFormatPolicy::ForceC15, TEST_MASTER, true),
    ] {
        let src = tempdir(&format!("matrix_{label}_src"));
        let payload = if label == "c12" {
            fs::copy(samples_dir().join("content.png"), src.join("file.bin")).expect("copy");
            fs::read(src.join("file.bin")).expect("read")
        } else {
            let data = vec![0xABu8; 24_576];
            fs::write(src.join("file.bin"), &data).expect("write");
            data
        };

        let enc_dir = tempdir(&format!("matrix_{label}_enc"));
        let dec_dir = tempdir(&format!("matrix_{label}_dec"));
        let options = DirectoryEncodeOptions {
            segment_format_policy: policy,
            encrypted,
            ..DirectoryEncodeOptions::default()
        };
        let archive = encode_directory_with_options(&key, &src, &enc_dir, options).expect("encode");
        let catalog_format = if encrypted {
            DIRECTORY_ARCHIVE_FORMAT_ENCRYPTED
        } else {
            DIRECTORY_ARCHIVE_FORMAT
        };
        let catalog_path = adam_catalog_path(&enc_dir, &archive.catalog_bao_root, catalog_format);

        let catalog_bytes = fs::read(&catalog_path).expect("read catalog");
        let (_, body) = decode(&key, &catalog_bytes).expect("decode catalog");
        let (adam_payload, _) = decode_adamantine(&body).expect("adamantine");
        let (rkyv, bundle) = split_adamantine_payload(&adam_payload).expect("split");
        let manifest = FilepackManifest::from_bytes_with_root(&rkyv, archive.catalog_bao_root)
            .expect("manifest");
        manifest
            .validate_bao_bundle_refs(bundle.len())
            .unwrap_or_else(|e| panic!("{label} bundle refs: {e:?}"));
        let entry = &manifest.entries[0];
        let seg = &entry.segments[0];
        let bao_ob = verification_slice_from_bundle(
            &bundle,
            seg.verification_outboard_offset,
            seg.verification_outboard_len,
        )
        .expect("ver slice");
        let fec_par =
            fec_slice_from_bundle(&bundle, seg.fec_parity_offset, seg.fec_parity_len).expect("fec");
        assert!(
            seg.fec_parity_len > 0,
            "{label} must index FEC parity in bundle"
        );

        let seg_path = enc_dir.join(format!(
            "{}.c{}",
            hex32(&seg.segment_bao_root),
            entry.segment_format
        ));
        let oenc = encode_outboard(&key, &payload, entry.segment_format).expect("encode_outboard");
        let pristine = fs::read(&seg_path).expect("read segment main");
        let mut seg_main = pristine.clone();

        if label == "c13" {
            decode_directory(&key, &catalog_path, &dec_dir)
                .unwrap_or_else(|e| panic!("{label} decode: {e:?}"));
            assert_eq!(fs::read(dec_dir.join("file.bin")).expect("read"), payload);
            let layout = OutboardShardLayout::from_outboard_encode(
                seg_main.len(),
                fec_par.len(),
                oenc.info.chunk_len,
            );
            let report =
                scattered_outboard_main_knockout(&mut seg_main, &layout, 8, 4, &mut thread_rng());
            assert!(
                report.shards_touched.len() <= 4,
                "{label} knockout must stay within budget"
            );
            assert!(
                !report.positions.is_empty(),
                "{label} knockout must corrupt at least one byte before scrub"
            );
            let recovered = scrub_outboard(
                &seg_main,
                Some(bao_ob),
                Some(fec_par),
                &oenc.info,
                entry.segment_format,
                &seg.segment_bao_root,
            )
            .unwrap_or_else(|e| panic!("{label} scrub within 4 shards: {e:?}"));
            assert_eq!(
                recovered, pristine,
                "{label} scrub must restore directory main"
            );
            fs::write(&seg_path, &recovered).expect("write scrubbed c13 main");
            decode_directory(&key, &catalog_path, &dec_dir)
                .unwrap_or_else(|e| panic!("{label} decode after scrub: {e:?}"));
            assert_eq!(fs::read(dec_dir.join("file.bin")).expect("read"), payload);
            continue;
        }

        if label == "c15" {
            decode_directory(&key, &catalog_path, &dec_dir)
                .unwrap_or_else(|e| panic!("{label} decode: {e:?}"));
            assert_eq!(fs::read(dec_dir.join("file.bin")).expect("read"), payload);
            let mut corrupt = seg_main.clone();
            corrupt.fill(0xFF);
            let mut bad_par = fec_par.to_vec();
            bad_par.fill(0xFF);
            let scrub_err = scrub_outboard(
                &corrupt,
                Some(bao_ob),
                Some(&bad_par),
                &oenc.info,
                entry.segment_format,
                &seg.segment_bao_root,
            )
            .unwrap_err();
            assert!(
                matches!(scrub_err, CarbonadoError::InvalidScrubbedHash),
                "{label} five-shard knockout must be irrecoverable, got {scrub_err:?}"
            );
            continue;
        }

        let layout = OutboardShardLayout::from_outboard_encode(
            seg_main.len(),
            fec_par.len(),
            oenc.info.chunk_len,
        );
        let report =
            scattered_outboard_main_knockout(&mut seg_main, &layout, 8, 4, &mut thread_rng());
        assert!(
            report.shards_touched.len() <= 4,
            "{label} knockout must stay within budget"
        );
        assert!(
            !report.positions.is_empty(),
            "{label} knockout must corrupt at least one byte before scrub"
        );
        fs::write(&seg_path, &seg_main).expect("corrupt");

        let recovered = scrub_outboard(
            &seg_main,
            Some(bao_ob),
            Some(fec_par),
            &oenc.info,
            entry.segment_format,
            &seg.segment_bao_root,
        )
        .unwrap_or_else(|e| panic!("{label} scrub within 4 shards: {e:?}"));
        assert_eq!(
            recovered, pristine,
            "{label} scrub must restore directory main"
        );
        fs::write(&seg_path, &recovered).expect("write scrubbed");
        decode_directory(&key, &catalog_path, &dec_dir)
            .unwrap_or_else(|e| panic!("{label} decode after scrub: {e:?}"));
        assert_eq!(fs::read(dec_dir.join("file.bin")).expect("read"), payload);
    }
}

#[test]
fn directory_multi_segment_fec_bundle_indices() {
    let src = tempdir("multi_seg_src");
    let big = vec![0xEFu8; (DIRECTORY_TEST_SEGMENT_BUDGET * 2 + 1) as usize];
    fs::write(src.join("big.bin"), &big).expect("write");

    let enc_dir = tempdir("multi_seg_enc");
    let options = DirectoryEncodeOptions {
        segment_plaintext_budget: DIRECTORY_TEST_SEGMENT_BUDGET,
        ..DirectoryEncodeOptions::default()
    };
    let archive =
        encode_directory_with_options(&ZERO_KEY, &src, &enc_dir, options).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );

    let catalog_bytes = fs::read(&catalog_path).expect("read catalog");
    let (_, body) = decode(&ZERO_KEY, &catalog_bytes).expect("decode catalog");
    let (adam_payload, _) = decode_adamantine(&body).expect("adamantine");
    let (rkyv, bundle) = split_adamantine_payload(&adam_payload).expect("split");
    let manifest =
        FilepackManifest::from_bytes_with_root(&rkyv, archive.catalog_bao_root).expect("manifest");
    let entry = manifest
        .entries
        .iter()
        .find(|e| e.rel_path == "big.bin")
        .expect("big.bin");
    assert!(entry.segments.len() >= 2, "expected multi-segment file");

    let chunks: Vec<&[u8]> = big.chunks(DIRECTORY_TEST_SEGMENT_BUDGET as usize).collect();
    let mut bundle_cursor = 0u32;
    for (seg, chunk) in entry.segments.iter().zip(chunks.iter()) {
        if seg.main_len > 0 {
            assert!(
                seg.fec_parity_len > 0,
                "chunk {} with main_len {} must index FEC parity",
                seg.chunk_index,
                seg.main_len
            );
        }
        assert_eq!(
            seg.verification_outboard_offset, bundle_cursor,
            "chunk {} verification offset must be monotonic",
            seg.chunk_index
        );
        bundle_cursor = bundle_cursor
            .checked_add(seg.verification_outboard_len)
            .expect("ver len overflow");
        assert_eq!(
            seg.fec_parity_offset, bundle_cursor,
            "chunk {} fec offset must follow verification contiguously",
            seg.chunk_index
        );
        bundle_cursor = bundle_cursor
            .checked_add(seg.fec_parity_len)
            .expect("fec len overflow");

        let ver_slice = verification_slice_from_bundle(
            &bundle,
            seg.verification_outboard_offset,
            seg.verification_outboard_len,
        )
        .expect("ver");
        let fec_slice =
            fec_slice_from_bundle(&bundle, seg.fec_parity_offset, seg.fec_parity_len).expect("fec");
        let oenc =
            encode_outboard(&ZERO_KEY, chunk, entry.segment_format).expect("encode_outboard");
        assert_eq!(oenc.verification_outboard.as_deref(), Some(ver_slice));
        if seg.main_len > 0 {
            assert_eq!(oenc.fec_parity.as_deref(), Some(fec_slice));
        }
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
