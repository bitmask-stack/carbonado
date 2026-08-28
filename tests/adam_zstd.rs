//! Adamantine sidecar + required zstd level + dict-in-bundle contracts.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use carbonado::adamantine::ADAMANTINE_MAGIC;
use carbonado::constants::ZSTD_MAGIC;
use carbonado::error::CarbonadoError;
use carbonado::file::{
    self, DirectoryEncodeOptions, EncodeToDirOptions, decode_directory,
    encode_directory_with_options,
};
use carbonado::paths::{ArchiveLayout, detect_archive_layout};
use carbonado::stream::ZstdEncode;
use carbonado::stream::compress::{compress_buffer, compress_buffer_with_dict};
use carbonado::{decode, encode, encode_with_zstd};

use common::zstd_frame::parse_zstd_frame_header;

const MASTER: [u8; 32] = [0u8; 32];
/// Tests pass level 20 explicitly. It is not a library default.
const LEVEL: i32 = 20;
const PLAIN: &[u8] = b"the quick brown fox jumps over the lazy dog. carbonado dict test payload. ";

fn tempdir(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("carbonado_adam_zstd_{name}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("tempdir");
    dir
}

fn list_files(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("read_dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn train_dict(samples: &[&[u8]]) -> Vec<u8> {
    let mut unit = Vec::new();
    for s in samples {
        unit.extend_from_slice(s);
        unit.push(b'\n');
    }
    assert!(!unit.is_empty(), "dictionary samples must be nonempty");
    let mut corpus = Vec::new();
    let mut sizes = Vec::new();
    while corpus.len() < 128 * 1024 {
        corpus.extend_from_slice(&unit);
        sizes.push(unit.len());
    }
    zstd::dict::from_continuous(&corpus, &sizes, 256).expect("train zstd dictionary")
}

fn dict_id(dict: &[u8]) -> u32 {
    assert!(
        dict.len() >= 8 && dict[0..4] == [0x37, 0xa4, 0x30, 0xec],
        "RFC 8878 dictionary magic"
    );
    u32::from_le_bytes(dict[4..8].try_into().expect("dict id"))
}

#[test]
fn compression_encode_without_zstd_level_fails() {
    let Err(err) = encode(&MASTER, PLAIN, 2) else {
        panic!("expected MissingZstdLevel for c2");
    };
    assert!(
        matches!(err, CarbonadoError::MissingZstdLevel),
        "expected MissingZstdLevel, got {err:?}"
    );
    let Err(err) = encode(&MASTER, PLAIN, 14) else {
        panic!("expected MissingZstdLevel for c14");
    };
    assert!(
        matches!(err, CarbonadoError::MissingZstdLevel),
        "expected MissingZstdLevel for c14, got {err:?}"
    );
}

#[test]
fn compression_encode_without_zstd_level_fails_with_dict() {
    let dict = train_dict(&[PLAIN, b"hello hello hello"]);
    let zstd = ZstdEncode {
        level: None,
        dict: Some(dict),
    };
    let Err(err) = encode_with_zstd(&MASTER, PLAIN, 2, None, &zstd) else {
        panic!("expected MissingZstdLevel with dict and no level");
    };
    assert!(
        matches!(err, CarbonadoError::MissingZstdLevel),
        "dict without level must still fail, got {err:?}"
    );
}

#[test]
fn compress_buffer_requires_explicit_level() {
    let frame = compress_buffer(PLAIN, LEVEL).expect("compress with explicit level");
    assert_eq!(&frame[..4], &ZSTD_MAGIC);
}

#[test]
fn outboard_encode_writes_exactly_two_files_adam_sidecar() {
    let dir = tempdir("outboard");
    let written = file::encode_to_dir(
        &MASTER,
        PLAIN,
        14,
        &dir,
        EncodeToDirOptions {
            outboard: true,
            zstd: ZstdEncode::level(LEVEL),
        },
    )
    .expect("encode_to_dir outboard");
    let names = list_files(&dir);
    assert_eq!(
        names.len(),
        2,
        "outboard must write exactly two files, got {names:?}"
    );
    assert!(
        names
            .iter()
            .any(|n| n.ends_with(".c0e") && !n.contains(".adam.")),
        "expected bare {{hash}}.c0e, got {names:?}"
    );
    let adam = names
        .iter()
        .find(|n| n.contains(".adam.c"))
        .expect("adam sidecar name");
    assert!(
        adam.ends_with(".adam.c0e"),
        "sidecar must be {{hash}}.adam.c0e, got {adam}"
    );
    let adam_path = dir.join(adam);
    let magic = fs::read(&adam_path).expect("read sidecar");
    assert!(
        magic.len() >= ADAMANTINE_MAGIC.len()
            && &magic[..ADAMANTINE_MAGIC.len()] == ADAMANTINE_MAGIC,
        "sidecar must start with ADAMANTINE10\\n"
    );
    assert!(!dir.join(format!("{}.out", written.main_name())).exists());
    assert!(!dir.join(format!("{}.par", written.main_name())).exists());
}

#[test]
fn inboard_encode_writes_exactly_one_adam_file() {
    let dir = tempdir("inboard");
    file::encode_to_dir(
        &MASTER,
        PLAIN,
        14,
        &dir,
        EncodeToDirOptions {
            outboard: false,
            zstd: ZstdEncode::level(LEVEL),
        },
    )
    .expect("encode_to_dir inboard");
    let names = list_files(&dir);
    assert_eq!(
        names.len(),
        1,
        "inboard must write exactly one file, got {names:?}"
    );
    assert!(
        names[0].ends_with(".adam.c0e"),
        "inboard artifact must be {{hash}}.adam.c0e, got {}",
        names[0]
    );
    let bytes = fs::read(dir.join(&names[0])).expect("read inboard");
    assert_eq!(&bytes[..12], carbonado::constants::MAGICNO);
    let layout = detect_archive_layout(&dir.join(&names[0])).expect("layout");
    assert!(
        matches!(layout, ArchiveLayout::InboardHeadered { .. }),
        "inboard {{hash}}.adam.c0e must be headered, not outboard/catalog, got {layout:?}"
    );
}

#[test]
fn dict_in_adamantine_bundle_matches_frame_dictionary_id() {
    let dict = train_dict(&[PLAIN, b"fox fox fox jumps jumps"]);
    let want_id = dict_id(&dict);
    let dir = tempdir("dict_id");
    let written = file::encode_to_dir(
        &MASTER,
        PLAIN,
        2,
        &dir,
        EncodeToDirOptions {
            outboard: true,
            zstd: ZstdEncode {
                level: Some(LEVEL),
                dict: Some(dict.clone()),
            },
        },
    )
    .expect("encode with dict");

    let main = fs::read(dir.join(written.main_name())).expect("read main");
    let h = parse_zstd_frame_header(&main).expect("parse zstd frame");
    assert_eq!(h.dictionary_id, Some(want_id), "frame Dictionary_ID");
    assert!(h.dictionary_id_flag > 0);

    let bundle_dict = written
        .dict_bytes()
        .expect("dict section present in Adamantine bundle");
    assert_eq!(bundle_dict, dict.as_slice());
    assert_eq!(dict_id(bundle_dict), want_id);
}

#[test]
fn decode_with_dictionary_id_and_empty_dict_section_fails() {
    let dict = train_dict(&[PLAIN, b"lazy lazy lazy dog dog"]);
    let encoded = encode_with_zstd(
        &MASTER,
        PLAIN,
        2,
        None,
        &ZstdEncode {
            level: Some(LEVEL),
            dict: Some(dict),
        },
    )
    .expect("encode c2 with dict");
    let err = decode(
        &MASTER,
        encoded.1.as_bytes(),
        &encoded.0,
        encoded.2.padding_len,
        2,
    )
    .unwrap_err();
    assert!(
        matches!(err, CarbonadoError::MissingZstdDictionary { .. }),
        "decode without dict bytes must fail, got {err:?}"
    );
}

#[test]
fn outboard_cxx_plus_adam_is_single_file_not_directory_catalog() {
    let dir = tempdir("layout");
    let written = file::encode_to_dir(
        &MASTER,
        PLAIN,
        14,
        &dir,
        EncodeToDirOptions {
            outboard: true,
            zstd: ZstdEncode::level(LEVEL),
        },
    )
    .expect("outboard pair");
    let main = dir.join(written.main_name());
    let adam = dir.join(written.adam_name());
    assert!(main.is_file());
    assert!(adam.is_file());

    let from_main = detect_archive_layout(&main).expect("detect main");
    assert_eq!(
        from_main,
        ArchiveLayout::OutboardBare { main: main.clone() }
    );
    let from_adam = detect_archive_layout(&adam).expect("detect adam sidecar");
    assert_eq!(
        from_adam,
        ArchiveLayout::OutboardBare { main: main.clone() }
    );
    let from_dir = detect_archive_layout(&dir).expect("detect dir of pair");
    assert_eq!(
        from_dir,
        ArchiveLayout::OutboardBare { main },
        "same-hash .cXX + .adam.cXX must not be a directory catalog"
    );
}

#[test]
fn compress_with_dict_frame_magic_and_id() {
    let dict = train_dict(&[PLAIN]);
    let id = dict_id(&dict);
    let frame = compress_buffer_with_dict(PLAIN, LEVEL, &dict).expect("compress with dict");
    assert_eq!(&frame[..4], &ZSTD_MAGIC);
    let h = parse_zstd_frame_header(&frame).expect("parse");
    assert_eq!(h.dictionary_id, Some(id));
}

#[test]
fn directory_decode_loads_dict_from_adamantine_bundle() {
    let dict = train_dict(&[PLAIN, b"the quick brown fox"]);
    let src = tempdir("dir_dict_src");
    let payload = PLAIN.repeat(32);
    fs::write(src.join("note.txt"), &payload).expect("write source");
    let enc = tempdir("dir_dict_enc");
    let archive = encode_directory_with_options(
        &MASTER,
        &src,
        &enc,
        DirectoryEncodeOptions {
            zstd: ZstdEncode {
                level: Some(LEVEL),
                dict: Some(dict),
            },
            ..DirectoryEncodeOptions::default()
        },
    )
    .expect("encode directory with dict");
    let catalog = enc.join(format!(
        "{}.adam.c14",
        archive
            .catalog_bao_root
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    assert!(catalog.is_file(), "catalog {}", catalog.display());
    let out = tempdir("dir_dict_out");
    decode_directory(&MASTER, &catalog, &out).expect("decode directory with bundle dict");
    let recovered = fs::read(out.join("note.txt")).expect("read recovered");
    assert_eq!(recovered, payload);
}

#[test]
fn uncompressed_encode_does_not_require_zstd_level() {
    let encoded = encode(&MASTER, PLAIN, 0).expect("c0 has no compression bit");
    assert!(!encoded.0.is_empty());
}
