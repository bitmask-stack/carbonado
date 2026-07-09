//! CBOR filepack ↔ rkyv FilepackManifest interop (Phase 4).
//!
//! Cross-tool contract: rkyv `FilepackManifest` v2 wire inside Adamantine 1.0 plus
//! Adamantine decimal on-disk segment naming (`{root}.c12` / `.c14` / `.adam.c14` / `.adam.c15`).

use carbonado::{
    adamantine::decode_adamantine,
    adamantine_payload::split_adamantine_payload,
    error::CarbonadoError,
    file::{decode, encode_directory, DirectoryArchive, DIRECTORY_ARCHIVE_FORMAT},
    filepack::{self, parse_filepack_cbor},
    filepack_manifest::{
        FilepackEntry, FilepackManifest, FilepackSegmentMap, SegmentRef,
        FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC, FILEPACK_MANIFEST_VERSION, MAX_REL_PATH_LEN,
    },
};
use ciborium::value::Value as CborValue;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const ZERO_KEY: [u8; 32] = [0u8; 32];

fn samples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples")
}

fn tempdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "carbonado_filepack_interop_{name}_{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create tempdir");
    dir
}

fn hex32(root: &[u8; 32]) -> String {
    root.iter().map(|b| format!("{b:02x}")).collect()
}

fn adam_catalog_path(enc_dir: &Path, root: &[u8; 32], format: u8) -> PathBuf {
    enc_dir.join(format!("{}.adam.c{format}", hex32(root)))
}

fn encode_samples_directory(enc_dir: &Path) -> DirectoryArchive {
    encode_directory(&ZERO_KEY, &samples_dir(), enc_dir).expect("encode_directory")
}

fn load_manifest_from_catalog(enc_dir: &Path, catalog_root: &[u8; 32]) -> FilepackManifest {
    let catalog_path = adam_catalog_path(enc_dir, catalog_root, DIRECTORY_ARCHIVE_FORMAT);
    let main = fs::read(&catalog_path).expect("read catalog");
    let (_, carbonado_body) = decode(&ZERO_KEY, &main).expect("decode catalog");
    let (adam_payload, _) = decode_adamantine(&carbonado_body).expect("adamantine");
    let (rkyv_payload, _) = split_adamantine_payload(&adam_payload).expect("split payload");
    FilepackManifest::from_bytes_with_root(&rkyv_payload, *catalog_root).expect("manifest")
}

fn encode_samples_manifest(enc_dir: &Path) -> (DirectoryArchive, FilepackManifest) {
    let archive = encode_samples_directory(enc_dir);
    let manifest = load_manifest_from_catalog(enc_dir, &archive.catalog_bao_root);
    (archive, manifest)
}

fn entry_fingerprint(entries: &[FilepackEntry]) -> BTreeMap<String, [u8; 32]> {
    entries
        .iter()
        .map(|e| (e.rel_path.clone(), e.content_blake3))
        .collect()
}

fn zero_hash_hex() -> String {
    "0".repeat(64)
}

fn cbor_manifest_with_package_path(component: &str) -> Vec<u8> {
    let file_map = vec![
        (
            CborValue::Text("hash".into()),
            CborValue::Text(zero_hash_hex()),
        ),
        (CborValue::Text("size".into()), CborValue::Integer(1.into())),
    ];
    let package = vec![(CborValue::Text(component.into()), CborValue::Map(file_map))];
    let manifest = vec![
        (CborValue::Text("embedded".into()), CborValue::Map(vec![])),
        (CborValue::Text("package".into()), CborValue::Map(package)),
        (
            CborValue::Text("signatures".into()),
            CborValue::Array(vec![]),
        ),
    ];
    let mut out = vec![];
    ciborium::ser::into_writer(&CborValue::Map(manifest), &mut out).expect("serialize");
    out
}

fn mock_segment_ref(main_len: u64, chunk_index: u32, root_byte: u8) -> SegmentRef {
    let ver_len = if main_len > 0 { 64 } else { 0 };
    let fec_len = carbonado::filepack_manifest::expected_fec_parity_len(main_len);
    SegmentRef {
        segment_bao_root: [root_byte; 32],
        chunk_index,
        main_len,
        verification_outboard_offset: 0,
        verification_outboard_len: ver_len,
        fec_parity_offset: ver_len,
        fec_parity_len: fec_len,
    }
}

fn mock_segment_map(paths: &[&str]) -> FilepackSegmentMap {
    let mut map = FilepackSegmentMap::new();
    for (i, path) in paths.iter().enumerate() {
        map.insert(
            (*path).to_string(),
            vec![mock_segment_ref(100 + i as u64, 0, i as u8 + 1)],
        );
    }
    map
}

#[test]
fn cbor_roundtrip_paths_and_hashes() {
    let samples = samples_dir();
    let packed = filepack::pack_directory(&samples).expect("pack_directory");
    let parsed = parse_filepack_cbor(&packed.manifest).expect("parse_filepack_cbor");
    assert!(parsed.len() >= 3);

    let segment_map = mock_segment_map(
        &parsed
            .iter()
            .map(|e| e.rel_path.as_str())
            .collect::<Vec<_>>(),
    );
    let imported = FilepackManifest::from_filepack_cbor(
        &packed.manifest,
        &segment_map,
        FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
        [9u8; 32],
    )
    .expect("from_filepack_cbor");

    let exported = imported.to_filepack_cbor().expect("to_filepack_cbor");
    let reparsed = parse_filepack_cbor(&exported).expect("reparse");

    let orig_paths: BTreeMap<_, _> = parsed
        .iter()
        .map(|e| (e.rel_path.clone(), e.content_blake3))
        .collect();
    let round_paths: BTreeMap<_, _> = reparsed
        .iter()
        .map(|e| (e.rel_path.clone(), e.content_blake3))
        .collect();
    assert_eq!(orig_paths, round_paths);

    for row in &reparsed {
        assert_eq!(row.size, 0, "export omits plaintext size");
    }
}

#[test]
fn from_packed_with_mock_segment_refs() {
    let packed = filepack::pack_directory(&samples_dir()).expect("pack");
    let paths: Vec<String> = packed.files.iter().map(|(p, _)| p.clone()).collect();
    let segment_map = mock_segment_map(&paths.iter().map(String::as_str).collect::<Vec<_>>());

    let manifest = FilepackManifest::from_packed(
        &packed,
        &segment_map,
        FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
        [7u8; 32],
    )
    .expect("from_packed");

    assert_eq!(manifest.version, FILEPACK_MANIFEST_VERSION);
    assert_eq!(manifest.format_level, FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC);
    assert_eq!(manifest.catalog_bao_root, [7u8; 32]);
    assert_eq!(manifest.entries.len(), packed.files.len());

    for (rel, data) in &packed.files {
        let entry = manifest
            .entries
            .iter()
            .find(|e| &e.rel_path == rel)
            .expect("entry");
        assert_eq!(entry.content_blake3, filepack::hash_file_content(data));
        assert_eq!(entry.segments.len(), 1);
        assert!(entry.ots_proof.is_none());
    }
}

#[test]
fn equivalence_pack_directory_vs_encode_directory() {
    let enc_dir = tempdir("equiv");
    let (_archive, encoded) = encode_samples_manifest(&enc_dir);
    let packed = filepack::pack_directory(&samples_dir()).expect("pack");

    let segment_map = FilepackSegmentMap::from_manifest_entries(&encoded.entries);
    let imported = FilepackManifest::from_filepack_cbor(
        &packed.manifest,
        &segment_map,
        encoded.format_level,
        encoded.catalog_bao_root,
    )
    .expect("import");

    assert_eq!(
        imported.entries.len(),
        encoded.entries.len(),
        "entry count mismatch"
    );
    assert_eq!(
        entry_fingerprint(&imported.entries),
        entry_fingerprint(&encoded.entries)
    );

    for (imported_entry, encoded_entry) in imported.entries.iter().zip(encoded.entries.iter()) {
        assert_eq!(imported_entry.rel_path, encoded_entry.rel_path);
        assert_eq!(imported_entry.content_blake3, encoded_entry.content_blake3);
        assert_eq!(imported_entry.segments, encoded_entry.segments);
    }
}

#[test]
fn parse_errors_use_invalid_filepack_cbor() {
    let err = parse_filepack_cbor(b"not-valid-cbor").unwrap_err();
    assert!(
        matches!(err, CarbonadoError::InvalidFilepackCbor(_)),
        "got {err:?}"
    );

    let packed = filepack::pack_directory(&samples_dir()).expect("pack");
    let err = FilepackManifest::from_filepack_cbor(
        &packed.manifest,
        &FilepackSegmentMap::new(),
        FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
        [0u8; 32],
    )
    .unwrap_err();
    assert!(
        matches!(err, CarbonadoError::InvalidFilepackCbor(ref msg) if msg.contains("missing segment refs")),
        "got {err:?}"
    );

    let mut corrupt = packed.manifest.clone();
    corrupt.truncate(corrupt.len().saturating_sub(4));
    let err = parse_filepack_cbor(&corrupt).unwrap_err();
    assert!(
        matches!(err, CarbonadoError::InvalidFilepackCbor(_)),
        "got {err:?}"
    );
}

#[test]
fn export_then_import_with_segment_map_preserves_hashes() {
    let enc_dir = tempdir("export_import");
    let (_archive, encoded) = encode_samples_manifest(&enc_dir);
    let cbor = encoded.to_filepack_cbor().expect("to_filepack_cbor");
    let segment_map = FilepackSegmentMap::from_manifest_entries(&encoded.entries);

    let reimported = FilepackManifest::from_filepack_cbor(
        &cbor,
        &segment_map,
        encoded.format_level,
        encoded.catalog_bao_root,
    )
    .expect("reimport");

    assert_eq!(
        entry_fingerprint(&reimported.entries),
        entry_fingerprint(&encoded.entries)
    );
}

#[test]
fn cbor_import_validate_errors_use_invalid_filepack_manifest() {
    let cbor = cbor_manifest_with_package_path("..");
    let mut segment_map = FilepackSegmentMap::new();
    segment_map.insert("..", vec![mock_segment_ref(1, 0, 1)]);
    let err = FilepackManifest::from_filepack_cbor(
        &cbor,
        &segment_map,
        FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
        [0u8; 32],
    )
    .unwrap_err();
    assert!(
        matches!(err, CarbonadoError::InvalidFilepackManifest(ref m) if m.contains("..")),
        "got {err:?}"
    );
}

#[test]
fn export_validate_errors_use_invalid_filepack_manifest() {
    let manifest = FilepackManifest {
        version: FILEPACK_MANIFEST_VERSION,
        format_level: FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
        catalog_bao_root: [0u8; 32],
        catalog_ots_proof: None,
        entries: vec![FilepackEntry {
            rel_path: "../escape.txt".into(),
            content_blake3: [0u8; 32],
            segment_format: carbonado::directory::format_policy::SEGMENT_FORMAT_PUBLIC_COMPRESSED,
            segments: vec![mock_segment_ref(1, 0, 1)],
            ots_proof: None,
        }],
    };
    let err = manifest.to_filepack_cbor().unwrap_err();
    assert!(
        matches!(err, CarbonadoError::InvalidFilepackManifest(ref m) if m.contains("..")),
        "got {err:?}"
    );
}

#[test]
fn parse_rejects_oversized_rel_path_at_flatten() {
    let long = "a".repeat(MAX_REL_PATH_LEN + 1);
    let cbor = cbor_manifest_with_package_path(&long);
    let err = parse_filepack_cbor(&cbor).unwrap_err();
    assert!(
        matches!(err, CarbonadoError::InvalidFilepackCbor(ref m) if m.contains("rel_path exceeds")),
        "got {err:?}"
    );
}

fn golden_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/directory_interop_golden.json")
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn adamantine_decimal_segment_naming_contract() {
    let enc_dir = tempdir("naming_contract");
    let (archive, manifest) = encode_samples_manifest(&enc_dir);

    let catalog_name = format!(
        "{}.adam.c{}",
        hex32(&archive.catalog_bao_root),
        DIRECTORY_ARCHIVE_FORMAT
    );
    assert!(
        catalog_name.ends_with(".adam.c14"),
        "catalog must use decimal c14 suffix, got {catalog_name}"
    );
    assert!(
        !catalog_name.contains(".c0e") && !catalog_name.contains(".c0E"),
        "catalog must not use hex format suffix: {catalog_name}"
    );
    assert!(enc_dir.join(&catalog_name).is_file());

    assert_eq!(manifest.version, FILEPACK_MANIFEST_VERSION);
    assert_eq!(manifest.format_level, FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC);

    let mut segment_suffixes = BTreeSet::new();
    for entry in &manifest.entries {
        for seg in &entry.segments {
            let name = format!("{}.c{}", hex32(&seg.segment_bao_root), entry.segment_format);
            segment_suffixes.insert(entry.segment_format);
            assert!(
                name.ends_with(".c12") || name.ends_with(".c14"),
                "public samples segments must be c12 or c14, got {name}"
            );
            assert!(
                !name.contains(".c0c") && !name.contains(".c0e"),
                "segment must use decimal suffix, not hex: {name}"
            );
            assert!(
                enc_dir.join(&name).is_file(),
                "missing on-disk segment artifact {name}"
            );
        }
    }
    assert!(
        segment_suffixes.contains(&12) && segment_suffixes.contains(&14),
        "tests/samples must include both c12 and c14 segment formats, got {segment_suffixes:?}"
    );

    for entry in fs::read_dir(&enc_dir).expect("read_dir") {
        let path = entry.expect("entry").path();
        if !path.is_file() {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy();
        assert!(
            !name.ends_with(".out") && !name.ends_with(".par"),
            "Adamantine 1.0 directory archives must not emit per-segment sidecars: {name}"
        );
    }
}

#[test]
fn golden_directory_interop_checksums_and_manifest_wire() {
    let fixture_text = fs::read_to_string(golden_fixture_path()).expect("read golden fixture");
    let fixture: JsonValue = serde_json::from_str(&fixture_text).expect("parse golden fixture");

    let enc_dir = tempdir("golden_checksums");
    let (archive, manifest) = encode_samples_manifest(&enc_dir);

    let expected_root = fixture["catalog_bao_root"]
        .as_str()
        .expect("catalog_bao_root");
    assert_eq!(hex32(&archive.catalog_bao_root), expected_root);
    assert_eq!(
        archive.entry_count,
        fixture["entry_count"].as_u64().expect("entry_count") as usize
    );

    assert_eq!(
        manifest.version,
        fixture["manifest_version"]
            .as_u64()
            .expect("manifest_version") as u32
    );
    assert_eq!(
        manifest.format_level,
        fixture["format_level"].as_u64().expect("format_level") as u8
    );

    let expected_entries = fixture["entries"].as_array().expect("entries");
    for spec in expected_entries {
        let rel = spec["rel_path"].as_str().expect("rel_path");
        let fmt = spec["segment_format"].as_u64().expect("segment_format") as u8;
        let entry = manifest
            .entries
            .iter()
            .find(|e| e.rel_path == rel)
            .unwrap_or_else(|| panic!("missing manifest entry {rel}"));
        assert_eq!(
            entry.segment_format, fmt,
            "{rel} segment_format drift (infer/heuristic change?)"
        );
        if let Some(seg_specs) = spec["segments"].as_array() {
            assert_eq!(entry.segments.len(), seg_specs.len(), "{rel} segment count");
            for (seg, seg_spec) in entry.segments.iter().zip(seg_specs.iter()) {
                if let Some(off) = seg_spec.get("verification_outboard_offset") {
                    assert_eq!(
                        seg.verification_outboard_offset,
                        off.as_u64().expect("verification_outboard_offset") as u32,
                        "{rel} chunk {} verification_outboard_offset",
                        seg.chunk_index
                    );
                }
                if let Some(len) = seg_spec.get("verification_outboard_len") {
                    assert_eq!(
                        seg.verification_outboard_len,
                        len.as_u64().expect("verification_outboard_len") as u32,
                        "{rel} chunk {} verification_outboard_len",
                        seg.chunk_index
                    );
                }
                assert_eq!(
                    seg.fec_parity_offset,
                    seg_spec["fec_parity_offset"]
                        .as_u64()
                        .expect("fec_parity_offset") as u32,
                    "{rel} chunk {} fec_parity_offset",
                    seg.chunk_index
                );
                assert_eq!(
                    seg.fec_parity_len,
                    seg_spec["fec_parity_len"].as_u64().expect("fec_parity_len") as u32,
                    "{rel} chunk {} fec_parity_len",
                    seg.chunk_index
                );
            }
        }
    }

    if let Some(bundle_sha) = fixture["bundle_sha256"].as_str() {
        let catalog_path = enc_dir.join(fixture["catalog_filename"].as_str().expect("catalog"));
        let catalog_bytes = fs::read(&catalog_path).expect("read catalog");
        let (_, body) = decode(&[0u8; 32], &catalog_bytes).expect("decode catalog");
        let (adam_payload, _) = decode_adamantine(&body).expect("adamantine");
        let (_, bundle) = split_adamantine_payload(&adam_payload).expect("split");
        assert_eq!(sha256_hex(&bundle), bundle_sha, "bundle sha256 drift");
    }

    let rkyv_bytes = manifest.into_bytes().expect("manifest into_bytes");
    assert_eq!(
        rkyv_bytes.len(),
        fixture["manifest_rkyv_len"]
            .as_u64()
            .expect("manifest_rkyv_len") as usize,
        "rkyv wire length drift — regenerate fixture on Linux CI"
    );
    assert_eq!(
        sha256_hex(&rkyv_bytes),
        fixture["manifest_rkyv_sha256"]
            .as_str()
            .expect("manifest_rkyv_sha256"),
        "rkyv FilepackManifest v2 wire bytes drift — regenerate fixture on Linux CI"
    );

    let artifacts = fixture["artifacts"].as_object().expect("artifacts");
    for (filename, spec) in artifacts {
        let path = enc_dir.join(filename);
        assert!(path.is_file(), "missing artifact {filename}");
        let bytes = fs::read(&path).expect("read artifact");
        assert_eq!(
            bytes.len(),
            spec["len"].as_u64().expect("artifact len") as usize,
            "{filename} length"
        );
        assert_eq!(
            sha256_hex(&bytes),
            spec["sha256"].as_str().expect("artifact sha256"),
            "{filename} sha256"
        );
        let decimal_suffix = spec["decimal_format_suffix"]
            .as_str()
            .expect("decimal_format_suffix");
        assert!(
            filename.ends_with(&format!(".c{decimal_suffix}"))
                || filename.ends_with(&format!(".adam.c{decimal_suffix}")),
            "{filename} must end with decimal .c{decimal_suffix}"
        );
    }
}

#[test]
#[ignore = "maintainer: regenerate tests/fixtures/directory_interop_golden.json on Linux CI"]
fn dump_interop_golden_fixture_values() {
    let enc_dir = tempdir("dump_golden");
    let (_archive, manifest) = encode_samples_manifest(&enc_dir);
    let rkyv_bytes = manifest.to_bytes().expect("to_bytes");
    eprintln!("manifest_rkyv_len={}", rkyv_bytes.len());
    eprintln!("manifest_rkyv_sha256={}", sha256_hex(&rkyv_bytes));
    let catalog_path = enc_dir.join(format!("{}.adam.c14", hex32(&_archive.catalog_bao_root)));
    let catalog_bytes = fs::read(&catalog_path).expect("read catalog");
    let (_, body) = decode(&[0u8; 32], &catalog_bytes).expect("decode");
    let (adam_payload, _) = decode_adamantine(&body).expect("adam");
    let (_, bundle) = split_adamantine_payload(&adam_payload).expect("split");
    eprintln!("bundle_sha256={}", sha256_hex(&bundle));
    for entry in &manifest.entries {
        eprintln!(
            "entry rel_path={} segment_format={}",
            entry.rel_path, entry.segment_format
        );
        for seg in &entry.segments {
            eprintln!(
                "  chunk {} ver_off={} ver_len={} fec_off={} fec_len={}",
                seg.chunk_index,
                seg.verification_outboard_offset,
                seg.verification_outboard_len,
                seg.fec_parity_offset,
                seg.fec_parity_len
            );
        }
    }
    for name in fs::read_dir(&enc_dir).expect("read_dir").flatten() {
        let path = name.path();
        if path.is_file() {
            let bytes = fs::read(&path).expect("read");
            eprintln!(
                "artifact {} len={} sha256={}",
                path.file_name().unwrap().to_string_lossy(),
                bytes.len(),
                sha256_hex(&bytes)
            );
        }
    }
}

#[test]
fn rejects_invalid_hash_hex_in_cbor() {
    let samples = samples_dir();
    let mut packed = filepack::pack_directory(&samples).expect("pack");
    packed.manifest = packed
        .manifest
        .iter()
        .map(|b| if *b == b'0' { b'z' } else { *b })
        .collect();
    let err = parse_filepack_cbor(&packed.manifest).unwrap_err();
    assert!(
        matches!(err, CarbonadoError::InvalidFilepackCbor(_)),
        "got {err:?}"
    );
}
