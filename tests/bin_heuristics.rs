//! Phase 1D: CLI sidecar path derivation and filename heuristics.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use carbonado::encode_outboard;
use carbonado::file::DIRECTORY_ARCHIVE_FORMAT;
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

fn hex_encode32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
    let enc = encode_outboard(&master, payload, DIRECTORY_ARCHIVE_FORMAT).expect("encode");
    let root_hex = hex_encode32(enc.hash.as_bytes());

    let main_path = work.join(format!("{root_hex}.c14"));
    let out_path = work.join(format!("{root_hex}.c14.out"));
    let par_path = work.join(format!("{root_hex}.c14.par"));
    let recovered = work.join("recovered.bin");

    fs::write(&main_path, &enc.main).expect("write main");
    fs::write(
        &out_path,
        enc.verification_outboard.as_ref().expect("bao sidecar"),
    )
    .expect("write out");
    fs::write(&par_path, enc.fec_parity.as_ref().expect("fec sidecar")).expect("write par");

    let dec = run_carbonado(&[
        "decode",
        main_path.to_str().unwrap(),
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
fn cli_decode_honors_explicit_sidecar_overrides() {
    let work = heuristics_tempdir("explicit_sidecars");
    let master = [0u8; 32];
    let payload = b"explicit --bao-outboard / --fec-parity override path";
    let enc = encode_outboard(&master, payload, 14).expect("encode");
    let root_hex = hex_encode32(enc.hash.as_bytes());

    let main_path = work.join(format!("{root_hex}.c0e"));
    let custom_out = work.join("custom.out");
    let custom_par = work.join("custom.par");
    let recovered = work.join("recovered.bin");

    fs::write(&main_path, &enc.main).expect("write main");
    fs::write(
        &custom_out,
        enc.verification_outboard.as_ref().expect("bao sidecar"),
    )
    .expect("write custom out");
    fs::write(&custom_par, enc.fec_parity.as_ref().expect("fec sidecar"))
        .expect("write custom par");

    let dec = run_carbonado(&[
        "decode",
        main_path.to_str().unwrap(),
        "--output",
        recovered.to_str().unwrap(),
        "--bao-outboard",
        custom_out.to_str().unwrap(),
        "--fec-parity",
        custom_par.to_str().unwrap(),
    ]);

    assert!(
        dec.status.success(),
        "decode with overrides failed: status={:?} stderr={}",
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
    let enc = encode_outboard(&master, payload, 14).expect("encode");

    let main_path = work.join("barepayload");
    let out_path = work.join("barepayload.out");
    fs::write(&main_path, &enc.main).expect("write main");
    fs::write(
        &out_path,
        enc.verification_outboard.as_ref().expect("bao sidecar"),
    )
    .expect("write out");

    let dec = run_carbonado(&["decode", main_path.to_str().unwrap()]);

    assert!(!dec.status.success(), "decode should fail without --format");
    let stderr = String::from_utf8_lossy(&dec.stderr);
    assert!(
        stderr.contains("provide --format"),
        "expected format hint in stderr, got: {stderr}"
    );
}
