//! Phase 3 allowlist for `backend-lean` (docs/TEST_CONTRACT.md).
//!
//! Directory dual-backend via **composition**:
//! - Rust: FS + **rkyv** FilepackManifest v2 + Adamantine framing + path policy
//! - Lean C ABI: segment outboard encode/decode + catalog headered encode/decode
//!
//! OTS entry/catalog proof cases remain Phase 4. Full rust-root checksum goldens
//! (`filepack_interop::golden_directory_interop_*`) stay `backend-rust`-only.
//!
//! ```bash
//! nix build .#libcarbonado -o result-libcarbonado
//! export CARBONADO_LEAN_LIB=$PWD/result-libcarbonado/lib
//! export CARBONADO_LEAN_INCLUDE=$PWD/result-libcarbonado/include
//! export LD_LIBRARY_PATH=$CARBONADO_LEAN_LIB
//! cargo test --no-default-features --features "backend-lean,pqc,ots" --test lean_backend_phase3
//! # or: just test-lean-phase3
//! ```
//! Only compiled under `backend-lean` (avoids breaking default/`backend-rust` clippy of all targets).

#![cfg(feature = "backend-lean")]

use std::fs;
use std::path::{Path, PathBuf};

use carbonado::directory::format_policy::{
    is_likely_incompressible, SegmentFormatPolicy, SEGMENT_FORMAT_ENCRYPTED_COMPRESSED,
    SEGMENT_FORMAT_PUBLIC_COMPRESSED, SEGMENT_FORMAT_PUBLIC_RAW,
};
use carbonado::error::CarbonadoError;
use carbonado::file::{
    decode_directory, encode_directory, encode_directory_with_options, DirectoryEncodeOptions,
    DIRECTORY_ARCHIVE_FORMAT,
};
use carbonado::filepack_manifest::{
    FilepackEntry, FilepackManifest, FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
    FILEPACK_MANIFEST_VERSION, MAX_REL_PATH_LEN,
};
use carbonado::{
    build_adamantine_payload, decode_adamantine, encode_adamantine, split_adamantine_payload,
    ADAMANTINE_CARBONADO_FMT_PUBLIC,
};

const ZERO_KEY: [u8; 32] = [0u8; 32];

const TEST_MASTER: [u8; 32] = [
    0x0c, 0xa1, 0xb0, 0xda, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
];

fn require_lean_lib() {
    if std::env::var_os("CARBONADO_LEAN_LIB").is_none() {
        panic!(
            "CARBONADO_LEAN_LIB unset. Build and export first:\n  \
             nix build .#libcarbonado -o result-libcarbonado\n  \
             export CARBONADO_LEAN_LIB=$PWD/result-libcarbonado/lib\n  \
             export CARBONADO_LEAN_INCLUDE=$PWD/result-libcarbonado/include\n  \
             export LD_LIBRARY_PATH=$CARBONADO_LEAN_LIB\n  \
             # or: just test-lean-phase3"
        );
    }
}

fn tempdir(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "carbonado-lean-p3-{}-{}-{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).expect("tempdir");
    p
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn adam_catalog_path(enc_dir: &Path, root: &[u8; 32], format: u8) -> PathBuf {
    enc_dir.join(format!("{}.adam.c{format}", hex32(root)))
}

fn write_tree(src: &Path, files: &[(&str, &[u8])]) {
    for (rel, data) in files {
        let path = src.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("mkdir");
        }
        fs::write(&path, data).expect("write");
    }
}

fn read_tree_file(dec: &Path, rel: &str) -> Vec<u8> {
    fs::read(dec.join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

#[test]
fn abi_version_is_one() {
    require_lean_lib();
    assert_eq!(carbonado::backend::lean::abi_version(), 1);
}

#[test]
fn directory_public_roundtrip_under_lean() {
    require_lean_lib();
    let src = tempdir("pub_src");
    write_tree(
        &src,
        &[
            ("hello.txt", b"phase3 public lean directory"),
            ("nested/x.bin", b"\x00\x01\x02nested"),
        ],
    );
    let enc = tempdir("pub_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc).expect("encode_directory public");
    assert_eq!(archive.entry_count, 2);

    let catalog = adam_catalog_path(&enc, &archive.catalog_bao_root, DIRECTORY_ARCHIVE_FORMAT);
    assert!(catalog.is_file(), "missing catalog {}", catalog.display());
    // Catalog filename uses decimal c14 (not hex .c0e).
    let name = catalog.file_name().unwrap().to_string_lossy();
    assert!(
        name.ends_with(".adam.c14"),
        "expected decimal .adam.c14, got {name}"
    );

    let dec = tempdir("pub_dec");
    decode_directory(&ZERO_KEY, &catalog, &dec).expect("decode_directory public");
    assert_eq!(
        read_tree_file(&dec, "hello.txt"),
        b"phase3 public lean directory"
    );
    assert_eq!(read_tree_file(&dec, "nested/x.bin"), b"\x00\x01\x02nested");
}

#[test]
fn directory_encrypted_roundtrip_under_lean() {
    require_lean_lib();
    let src = tempdir("enc_src");
    write_tree(&src, &[("secret.txt", b"encrypted catalog+segments")]);
    let enc = tempdir("enc_enc");
    let options = DirectoryEncodeOptions {
        encrypted: true,
        ..Default::default()
    };
    let archive = encode_directory_with_options(&TEST_MASTER, &src, &enc, options)
        .expect("encode_directory encrypted");
    assert_eq!(archive.entry_count, 1);

    let catalog = adam_catalog_path(&enc, &archive.catalog_bao_root, 0x0F);
    let name = catalog.file_name().unwrap().to_string_lossy();
    assert!(
        name.ends_with(".adam.c15"),
        "expected .adam.c15, got {name}"
    );

    let dec = tempdir("enc_dec");
    decode_directory(&TEST_MASTER, &catalog, &dec).expect("decode encrypted");
    assert_eq!(
        read_tree_file(&dec, "secret.txt"),
        b"encrypted catalog+segments"
    );
}

#[test]
fn empty_directory_roundtrip_under_lean() {
    require_lean_lib();
    let src = tempdir("empty_src");
    let enc = tempdir("empty_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc).expect("encode empty");
    assert_eq!(archive.entry_count, 0);
    let catalog = adam_catalog_path(&enc, &archive.catalog_bao_root, DIRECTORY_ARCHIVE_FORMAT);
    let dec = tempdir("empty_dec");
    decode_directory(&ZERO_KEY, &catalog, &dec).expect("decode empty");
}

#[test]
fn encode_rejects_zero_master_on_encrypted_strict() {
    require_lean_lib();
    let src = tempdir("zmk_src");
    write_tree(&src, &[("a.txt", b"x")]);
    let enc = tempdir("zmk_enc");
    let options = DirectoryEncodeOptions {
        encrypted: true,
        ..Default::default()
    };
    let err = encode_directory_with_options(&ZERO_KEY, &src, &enc, options).unwrap_err();
    assert!(
        matches!(err, CarbonadoError::ZeroMasterKeyNotAllowed),
        "expected ZeroMasterKeyNotAllowed, got {err:?}"
    );
}

#[test]
fn decode_rejects_nonzero_master_on_public_strict() {
    require_lean_lib();
    let src = tempdir("nz_src");
    write_tree(&src, &[("a.txt", b"public")]);
    let enc = tempdir("nz_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc).expect("encode");
    let catalog = adam_catalog_path(&enc, &archive.catalog_bao_root, DIRECTORY_ARCHIVE_FORMAT);
    let err = decode_directory(&TEST_MASTER, &catalog, &tempdir("nz_dec")).unwrap_err();
    assert!(
        matches!(err, CarbonadoError::EncryptedDirectoryNotRequested),
        "expected EncryptedDirectoryNotRequested, got {err:?}"
    );
}

#[test]
fn decode_rejects_path_traversal_writes_no_files() {
    require_lean_lib();
    // Unit SSOT: validate_rel_path / FilepackManifest::validate reject `..`.
    let pe = FilepackManifest::validate_rel_path("../escape.txt").unwrap_err();
    assert!(
        matches!(pe, CarbonadoError::InvalidFilepackManifest(_)),
        "expected InvalidFilepackManifest from validate_rel_path, got {pe:?}"
    );
    let _ = MAX_REL_PATH_LEN;

    // Full fail-closed: encode good tree → rewrite manifest rel_path → re-encode catalog →
    // decode_directory must fail before any extract write.
    let src = tempdir("mal_src");
    write_tree(&src, &[("one.txt", b"hello")]);
    let enc = tempdir("mal_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc).expect("encode");
    let good_catalog = adam_catalog_path(&enc, &archive.catalog_bao_root, DIRECTORY_ARCHIVE_FORMAT);

    let main_raw = fs::read(&good_catalog).expect("read catalog");
    let (_, body) = carbonado::file::decode(&ZERO_KEY, &main_raw).expect("headered decode");
    let (adam_payload, hdr) = decode_adamantine(&body).expect("adamantine");
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
    // Structural validate also fails on the hand-built index (secondary assert).
    let unit_err = malicious.validate().unwrap_err();
    assert!(
        matches!(unit_err, CarbonadoError::InvalidFilepackManifest(_)),
        "expected InvalidFilepackManifest from validate, got {unit_err:?}"
    );

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
    let mal_catalog = adam_catalog_path(&enc, &mal_root, DIRECTORY_ARCHIVE_FORMAT);
    fs::write(&mal_catalog, &mal_encoded).expect("write malicious catalog");

    let dec = tempdir("mal_dec");
    let err = decode_directory(&ZERO_KEY, &mal_catalog, &dec).unwrap_err();
    assert!(
        matches!(
            err,
            CarbonadoError::InvalidFilepackManifest(ref msg) if msg.contains("..")
        ),
        "expected InvalidFilepackManifest containing '..', got {err:?}"
    );
    assert!(
        fs::read_dir(&dec)
            .map(|mut d| d.next())
            .expect("read_dir")
            .is_none(),
        "decode_directory must not write files on path traversal"
    );
}

#[test]
fn format_policy_pure_logic_under_lean() {
    require_lean_lib();
    // Pure Rust policy (no crypto) — must stay available under backend-lean builds.
    assert!(!is_likely_incompressible(
        b"hello world text that compresses well"
    ));
    assert!(is_likely_incompressible(&[
        0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10
    ]));

    let text = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let fmt = SegmentFormatPolicy::Auto
        .resolve_segment_format(false, text)
        .expect("auto public text");
    assert_eq!(
        fmt, SEGMENT_FORMAT_PUBLIC_COMPRESSED,
        "compressible public → c14"
    );

    let jpeg = [0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10];
    let fmt = SegmentFormatPolicy::Auto
        .resolve_segment_format(false, &jpeg)
        .expect("auto public jpeg");
    assert_eq!(
        fmt, SEGMENT_FORMAT_PUBLIC_RAW,
        "incompressible public → c12"
    );

    let fmt = SegmentFormatPolicy::Auto
        .resolve_segment_format(true, text)
        .expect("auto encrypted text");
    assert_eq!(
        fmt, SEGMENT_FORMAT_ENCRYPTED_COMPRESSED,
        "compressible encrypted → c15"
    );

    let err = SegmentFormatPolicy::ForceC12
        .resolve_segment_format(true, text)
        .unwrap_err();
    assert!(
        matches!(err, CarbonadoError::SegmentFormatMismatch(_)),
        "ForceC12 on encrypted catalog must fail, got {err:?}"
    );
}

#[test]
fn catalog_rkyv_wire_roundtrip_under_lean_encode() {
    require_lean_lib();
    // Dual-suite claim: under backend-lean, directory catalogs still carry **rkyv**
    // FilepackManifest v2 (not CFP2) inside Adamantine payload.
    let src = tempdir("rkyv_src");
    write_tree(&src, &[("only.txt", b"rkyv normative wire")]);
    let enc = tempdir("rkyv_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc).expect("encode");
    let catalog = adam_catalog_path(&enc, &archive.catalog_bao_root, DIRECTORY_ARCHIVE_FORMAT);

    // Peel catalog: headered decode → adamantine → rkyv body.
    let main_raw = fs::read(&catalog).expect("read catalog");
    let (header, body) = carbonado::file::decode(&ZERO_KEY, &main_raw).expect("headered decode");
    assert_eq!(header.format.bits(), DIRECTORY_ARCHIVE_FORMAT);
    assert_eq!(header.hash.as_bytes(), &archive.catalog_bao_root);

    let (adam_payload, adam_hdr) = carbonado::decode_adamantine(&body).expect("adamantine");
    assert_eq!(adam_hdr.carbonado_fmt, 0x0E);
    let (rkyv_payload, _bundle) =
        carbonado::split_adamantine_payload(&adam_payload).expect("split");
    // CFP2 magic would be b"CFP2"; rkyv has no that prefix at byte 0 typically, but
    // definitive check is successful FilepackManifest deserialize + version 2.
    assert!(
        !rkyv_payload.starts_with(b"CFP2"),
        "dual-suite catalog must not be Lean-only CFP2 wire"
    );
    let manifest = FilepackManifest::from_bytes_with_root(&rkyv_payload, archive.catalog_bao_root)
        .expect("rkyv FilepackManifest v2");
    assert_eq!(manifest.version, FILEPACK_MANIFEST_VERSION);
    assert_eq!(manifest.format_level, FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC);
    assert_eq!(manifest.entries.len(), 1);
    assert_eq!(manifest.entries[0].rel_path, "only.txt");
}

/// G9 directory seed: rust-encoded fixture (tests/fixtures/phase3_g9_directory) → lean decode.
#[test]
fn g9_rust_encode_lean_decode_directory_fixture() {
    require_lean_lib();
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/phase3_g9_directory");
    assert!(
        fixture.is_dir(),
        "missing G9 fixture dir {}",
        fixture.display()
    );

    let catalog =
        fixture.join("16e2369f4f4465014e5e92740e3f76403f681cd60c01f7605ee11acd5423024f.adam.c14");
    assert!(
        catalog.is_file(),
        "missing G9 catalog {}",
        catalog.display()
    );

    // Fixture segments must sit next to the catalog (decode looks in parent dir).
    let dec = tempdir("g9_dec");
    // Copy entire fixture archive next to a writable extract root so decode can
    // resolve segment mains relative to the catalog path without mutating fixtures.
    let work = tempdir("g9_work");
    for entry in fs::read_dir(&fixture).expect("read fixture") {
        let entry = entry.expect("entry");
        let path = entry.path();
        if path.is_file()
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n != "README.txt")
        {
            fs::copy(&path, work.join(path.file_name().unwrap())).expect("copy artifact");
        }
    }
    let work_catalog = work.join(catalog.file_name().unwrap());
    decode_directory(&ZERO_KEY, &work_catalog, &dec).expect("lean decode of rust G9 fixture");
    assert_eq!(read_tree_file(&dec, "a.txt"), b"phase3 g9 hello");
    assert_eq!(read_tree_file(&dec, "sub/b.bin"), b"nested data");
}

#[test]
fn multi_segment_sharding_under_lean() {
    require_lean_lib();
    let src = tempdir("shard_src");
    // 5 bytes with budget 2 → 3 segments.
    write_tree(&src, &[("shard.bin", b"abcde")]);
    let enc = tempdir("shard_enc");
    let options = DirectoryEncodeOptions {
        segment_plaintext_budget: 2,
        ..Default::default()
    };
    let archive = encode_directory_with_options(&ZERO_KEY, &src, &enc, options).expect("encode");
    assert_eq!(archive.entry_count, 1);

    let catalog = adam_catalog_path(&enc, &archive.catalog_bao_root, DIRECTORY_ARCHIVE_FORMAT);
    let mains: Vec<_> = fs::read_dir(&enc)
        .expect("read_dir")
        .filter_map(|e| e.ok())
        .filter(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.contains(".c") && !n.contains(".adam.")
        })
        .collect();
    assert_eq!(
        mains.len(),
        3,
        "expected exactly 3 segment mains for budget=2 on 5-byte file, got {}",
        mains.len()
    );

    let dec = tempdir("shard_dec");
    decode_directory(&ZERO_KEY, &catalog, &dec).expect("decode sharded");
    assert_eq!(read_tree_file(&dec, "shard.bin"), b"abcde");
}
