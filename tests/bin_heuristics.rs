//! Phase 1D: CLI sidecar path derivation and filename heuristics.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use carbonado::ZstdEncode;
use carbonado::file::{DIRECTORY_ARCHIVE_FORMAT, EncodeToDirOptions, encode_to_dir};
use carbonado::paths::{
    guess_format_from_filename, parse_bao_root_from_filename, sidecar_sibling_path,
};

use common::cli::{self, run_carbonado};

fn heuristics_tempdir(name: &str) -> PathBuf {
    cli::tempdir(&format!("carbonado_bin_heuristics_{name}"))
}

fn hex64(byte: u8) -> String {
    std::iter::repeat_n(format!("{byte:02x}"), 32).collect::<String>()
}

#[test]
fn sidecar_paths_adam_catalog_and_decimal_c14() {
    let adam = Path::new("/var/archives/nested/root.adam.c14");
    assert_eq!(
        sidecar_sibling_path(adam, "out"),
        PathBuf::from("/var/archives/nested/root.adam.c14.out")
    );
    assert_eq!(
        sidecar_sibling_path(adam, "par"),
        PathBuf::from("/var/archives/nested/root.adam.c14.par")
    );

    let seg = Path::new("/var/archives/nested/seg.c14");
    assert_eq!(
        sidecar_sibling_path(seg, "out"),
        PathBuf::from("/var/archives/nested/seg.c14.out")
    );
}

#[test]
fn sidecar_paths_hex_suffix_and_bare_main() {
    let hex_main = Path::new("/tmp/out/hash.c0e");
    assert_eq!(
        sidecar_sibling_path(hex_main, "par"),
        PathBuf::from("/tmp/out/hash.c0e.par")
    );

    let bare = Path::new("/tmp/out/recovered_payload");
    assert_eq!(
        sidecar_sibling_path(bare, "out"),
        PathBuf::from("/tmp/out/recovered_payload.out")
    );
}

#[test]
fn guess_format_decimal_c14_not_hex_twenty() {
    assert_eq!(
        guess_format_from_filename(Path::new("deadbeef.c14")),
        Some(14)
    );
    assert_eq!(
        guess_format_from_filename(Path::new("deadbeef.adam.c14")),
        Some(14)
    );
    assert_eq!(
        guess_format_from_filename(Path::new("deadbeef.c0e")),
        Some(0x0e)
    );
}

#[test]
fn parse_bao_root_from_suffixes() {
    let root_hex = hex64(0xab);
    let mut expected = [0u8; 32];
    expected.fill(0xab);

    for name in [
        format!("{root_hex}.c14"),
        format!("{root_hex}.adam.c14"),
        format!("{root_hex}.c0e"),
    ] {
        let parsed = parse_bao_root_from_filename(Path::new(&name)).expect("parse root");
        assert_eq!(parsed, expected, "failed for {name}");
    }
}

#[test]
fn cli_decode_discovers_decimal_c14_sidecars() {
    let work = heuristics_tempdir("decode_c14_sidecars");
    let master = [0u8; 32];
    let payload = b"bin heuristics decimal c14 sidecar discovery";
    let written = encode_to_dir(
        &master,
        payload,
        DIRECTORY_ARCHIVE_FORMAT,
        &work,
        EncodeToDirOptions {
            outboard: true,
            zstd: ZstdEncode::level(20),
        },
    )
    .expect("encode_to_dir outboard");
    let recovered = work.join("recovered.bin");

    let dec = run_carbonado(&[
        "decode",
        written.main_path.to_str().unwrap(),
        "--output",
        recovered.to_str().unwrap(),
    ]);

    assert!(
        dec.status.success(),
        "decode failed: status={:?} stderr={}",
        dec.status,
        String::from_utf8_lossy(&dec.stderr)
    );
    assert_eq!(fs::read(&recovered).expect("read recovered"), payload);
}

#[test]
fn cli_decode_uses_adamantine_sidecar_next_to_main() {
    let work = heuristics_tempdir("adam_sidecar");
    let master = [0u8; 32];
    let payload = b"decode uses {hash}.adam.c0e next to {hash}.c0e";
    let written = encode_to_dir(
        &master,
        payload,
        14,
        &work,
        EncodeToDirOptions {
            outboard: true,
            zstd: ZstdEncode::level(20),
        },
    )
    .expect("encode_to_dir outboard");
    let recovered = work.join("recovered.bin");

    let dec = run_carbonado(&[
        "decode",
        written.adam_path.to_str().unwrap(),
        "--output",
        recovered.to_str().unwrap(),
    ]);

    assert!(
        dec.status.success(),
        "decode adamantine sidecar failed: status={:?} stderr={}",
        dec.status,
        String::from_utf8_lossy(&dec.stderr)
    );
    assert_eq!(fs::read(&recovered).expect("read recovered"), payload);
}

#[test]
fn cli_decode_bare_outboard_requires_format_when_unguessable() {
    let work = heuristics_tempdir("format_error");
    let master = [0u8; 32];
    let payload = b"bare main without guessable format suffix";
    let written = encode_to_dir(
        &master,
        payload,
        14,
        &work,
        EncodeToDirOptions {
            outboard: true,
            zstd: ZstdEncode::level(20),
        },
    )
    .expect("encode_to_dir outboard");
    let main_path = work.join("barepayload");
    fs::copy(&written.main_path, &main_path).expect("copy main");

    let dec = run_carbonado(&["decode", main_path.to_str().unwrap()]);

    assert!(!dec.status.success(), "decode should fail without --format");
    let stderr = String::from_utf8_lossy(&dec.stderr);
    assert!(
        stderr.contains("provide --format")
            || stderr.contains("Magic number found")
            || stderr.contains("could not guess Carbonado format"),
        "expected format or magic hint in stderr, got: {stderr}"
    );
}
