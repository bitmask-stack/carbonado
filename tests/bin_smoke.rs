//! Phase 1B: CLI smoke tests invoking the prebuilt `carbonado` binary.

mod common;

use std::fs;

use common::assert_trees_equal;
use common::cli::{self, find_single_archive, manifest_dir, run_carbonado};

fn smoke_tempdir(name: &str) -> std::path::PathBuf {
    cli::tempdir(&format!("carbonado_bin_smoke_{name}"))
}

#[test]
fn bin_smoke_single_file_encode_decode_roundtrip() {
    let work = smoke_tempdir("single");
    let input = work.join("input.txt");
    let outdir = work.join("enc");
    let recovered = work.join("recovered.bin");
    fs::create_dir_all(&outdir).expect("outdir");
    fs::write(&input, b"bin smoke single-file roundtrip payload").expect("write input");

    // Public single-file outboard roundtrip (bare main + sidecars). Default inboard
    // encode uses file::encode and writes headered `.c{fmt:02x}` artifacts.
    let enc = run_carbonado(&[
        "encode",
        input.to_str().unwrap(),
        "--format",
        "14",
        "--outboard",
        "--output",
        outdir.to_str().unwrap(),
    ]);
    assert!(
        enc.status.success(),
        "encode failed: status={:?} stderr={}",
        enc.status,
        String::from_utf8_lossy(&enc.stderr)
    );

    let archive = find_single_archive(&outdir);
    let dec = run_carbonado(&[
        "decode",
        archive.to_str().unwrap(),
        "--output",
        recovered.to_str().unwrap(),
    ]);
    assert!(
        dec.status.success(),
        "decode failed: status={:?} stderr={}",
        dec.status,
        String::from_utf8_lossy(&dec.stderr)
    );

    let got = fs::read(&recovered).expect("read recovered");
    assert_eq!(got, b"bin smoke single-file roundtrip payload");
}

#[test]
fn bin_smoke_directory_encode_decode_roundtrip() {
    let samples = manifest_dir().join("tests/samples");
    assert!(
        samples.is_dir(),
        "tests/samples required for directory smoke (content.png, contract.rgbc, code.tar)"
    );

    let work = smoke_tempdir("dir");
    let outdir = work.join("enc");
    let recovered = work.join("recovered");
    fs::create_dir_all(&outdir).expect("outdir");

    let enc = run_carbonado(&[
        "encode",
        samples.to_str().unwrap(),
        "--output",
        outdir.to_str().unwrap(),
    ]);
    assert!(
        enc.status.success(),
        "directory encode failed: status={:?} stderr={}",
        enc.status,
        String::from_utf8_lossy(&enc.stderr)
    );

    let catalog = fs::read_dir(&outdir)
        .expect("read enc dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.is_file()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with(".adam.c14"))
        })
        .expect("catalog .adam.c14 missing");

    let dec = run_carbonado(&[
        "decode",
        catalog.to_str().unwrap(),
        "--output",
        recovered.to_str().unwrap(),
    ]);
    assert!(
        dec.status.success(),
        "directory decode failed: status={:?} stderr={}",
        dec.status,
        String::from_utf8_lossy(&dec.stderr)
    );

    assert_trees_equal(&samples, &recovered);
}
