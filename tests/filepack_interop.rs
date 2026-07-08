//! CBOR filepack ↔ rkyv FilepackManifest interop (Phase 4).

use carbonado::{
    adamantine::decode_adamantine,
    adamantine_payload::split_adamantine_payload,
    error::CarbonadoError,
    file::{decode, encode_directory, DIRECTORY_ARCHIVE_FORMAT},
    filepack::{self, parse_filepack_cbor},
    filepack_manifest::{
        FilepackEntry, FilepackManifest, FilepackSegmentMap, SegmentRef,
        FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC, FILEPACK_MANIFEST_VERSION, MAX_REL_PATH_LEN,
    },
};
use ciborium::value::Value as CborValue;
use std::collections::BTreeMap;
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

fn load_encoded_manifest(enc_dir: &Path) -> FilepackManifest {
    let archive = encode_directory(&ZERO_KEY, &samples_dir(), enc_dir).expect("encode_directory");
    let catalog_path =
        adam_catalog_path(enc_dir, &archive.catalog_bao_root, DIRECTORY_ARCHIVE_FORMAT);
    let main = fs::read(&catalog_path).expect("read catalog");
    let (_, carbonado_body) = decode(&ZERO_KEY, &main).expect("decode catalog");
    let (adam_payload, _) = decode_adamantine(&carbonado_body).expect("adamantine");
    let (rkyv_payload, _) = split_adamantine_payload(&adam_payload).expect("split payload");
    FilepackManifest::from_bytes_with_root(&rkyv_payload, archive.catalog_bao_root)
        .expect("manifest")
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

fn mock_segment_map(paths: &[&str]) -> FilepackSegmentMap {
    let mut map = FilepackSegmentMap::new();
    for (i, path) in paths.iter().enumerate() {
        map.insert(
            (*path).to_string(),
            vec![SegmentRef {
                segment_bao_root: [i as u8 + 1; 32],
                chunk_index: 0,
                main_len: 100 + i as u64,
                bao_outboard_offset: 0,
                bao_outboard_len: 0,
            }],
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
    let encoded = load_encoded_manifest(&enc_dir);
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
    let encoded = load_encoded_manifest(&enc_dir);
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
    segment_map.insert(
        "..",
        vec![SegmentRef {
            segment_bao_root: [1u8; 32],
            chunk_index: 0,
            main_len: 1,
            bao_outboard_offset: 0,
            bao_outboard_len: 0,
        }],
    );
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
            segments: vec![SegmentRef {
                segment_bao_root: [1u8; 32],
                chunk_index: 0,
                main_len: 1,
                bao_outboard_offset: 0,
                bao_outboard_len: 0,
            }],
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
