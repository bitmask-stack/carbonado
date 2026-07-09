//! CLI integration tests for the `carbonado` binary.

mod common;

use std::fs;

use common::assert_trees_equal;
use common::cli::{self, find_single_archive, manifest_dir, run_carbonado, run_carbonado_env};

fn cli_tempdir(name: &str) -> std::path::PathBuf {
    cli::tempdir(&format!("carbonado_bin_cli_{name}"))
}

/// Known 64-hex master for encrypted roundtrips (32 bytes of 0xab).
fn test_master_hex() -> String {
    std::iter::repeat_n("ab", 32).collect()
}

const INBOARD_PAYLOAD: &[u8] = b"bin cli inboard headered roundtrip payload";
const ENCRYPTED_PAYLOAD: &[u8] = b"bin cli encrypted format-15 roundtrip payload";

fn assert_starts_with_carbonado_header(path: &std::path::Path) {
    use carbonado::constants::MAGICNO;
    let bytes = fs::read(path).expect("read artifact");
    assert!(
        bytes.len() > carbonado::file::Header::LEN && &bytes[0..12] == MAGICNO,
        "expected CARBONADO20 header prefix: {}",
        path.display()
    );
}

fn assert_no_sidecars(main_path: &std::path::Path) {
    let stem = main_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let parent = main_path.parent().expect("parent");
    assert!(!parent.join(format!("{stem}.out")).exists());
    assert!(!parent.join(format!("{stem}.par")).exists());
}

#[test]
fn bin_inboard_encode_decode() {
    let work = cli_tempdir("inboard");
    let input = work.join("input.bin");
    let outdir = work.join("enc");
    let recovered = work.join("recovered.bin");
    fs::create_dir_all(&outdir).expect("outdir");
    fs::write(&input, INBOARD_PAYLOAD).expect("write input");

    let enc = run_carbonado(&[
        "encode",
        input.to_str().unwrap(),
        "--format",
        "14",
        "--output",
        outdir.to_str().unwrap(),
    ]);
    assert!(
        enc.status.success(),
        "inboard encode failed: status={:?} stderr={}",
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
        "inboard decode failed: status={:?} stderr={}",
        dec.status,
        String::from_utf8_lossy(&dec.stderr)
    );

    let got = fs::read(&recovered).expect("read recovered");
    assert_eq!(got, INBOARD_PAYLOAD);
}

#[test]
fn bin_encrypted_encode_decode() {
    let work = cli_tempdir("encrypted");
    let input = work.join("secret.bin");
    let outdir = work.join("enc");
    let recovered = work.join("recovered.bin");
    let master = test_master_hex();
    fs::create_dir_all(&outdir).expect("outdir");
    fs::write(&input, ENCRYPTED_PAYLOAD).expect("write input");

    let enc = run_carbonado(&[
        "encode",
        input.to_str().unwrap(),
        "--format",
        "15",
        "--master",
        &master,
        "--output",
        outdir.to_str().unwrap(),
    ]);
    assert!(
        enc.status.success(),
        "encrypted encode failed: status={:?} stderr={}",
        enc.status,
        String::from_utf8_lossy(&enc.stderr)
    );

    let archive = find_single_archive(&outdir);
    let dec = run_carbonado(&[
        "decode",
        archive.to_str().unwrap(),
        "--master",
        &master,
        "--output",
        recovered.to_str().unwrap(),
    ]);
    assert!(
        dec.status.success(),
        "encrypted decode failed: status={:?} stderr={}",
        dec.status,
        String::from_utf8_lossy(&dec.stderr)
    );

    let got = fs::read(&recovered).expect("read recovered");
    assert_eq!(got, ENCRYPTED_PAYLOAD);
}

#[test]
fn bin_encode_rejects_missing_input() {
    let work = cli_tempdir("missing_input");
    let missing = work.join("does-not-exist.bin");

    let out = run_carbonado(&["encode", missing.to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "encode should fail for missing input"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("input not found") || stderr.contains("not a file or directory"),
        "stderr should mention missing input, got: {stderr}"
    );
}

#[test]
fn bin_encode_dir_default_output_not_dot() {
    let samples = manifest_dir().join("tests/samples");
    assert!(samples.is_dir(), "tests/samples required");

    let _work = cli_tempdir("dir_default_out");
    let expected_out = samples.with_file_name("samples-archive");
    let _ = fs::remove_dir_all(&expected_out);

    let out = run_carbonado(&["encode", samples.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "directory encode with default -o failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        expected_out.is_dir(),
        "default output should be {{input}}-archive/, expected {}",
        expected_out.display()
    );
    assert!(
        !samples.join(".adam.c14").exists(),
        "directory encode must not default output to input directory (.)"
    );

    let catalog = fs::read_dir(&expected_out)
        .expect("read archive dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".adam.c14"))
        })
        .expect("catalog .adam.c14 missing");
    assert_starts_with_carbonado_header(&catalog);
    let _ = fs::remove_dir_all(&expected_out);
}

#[test]
fn bin_encode_dir_rejects_outboard_flag() {
    let samples = manifest_dir().join("tests/samples");
    let work = cli_tempdir("dir_outboard_reject");
    let outdir = work.join("enc");
    fs::create_dir_all(&outdir).expect("outdir");

    let out = run_carbonado(&[
        "encode",
        samples.to_str().unwrap(),
        "--outboard",
        "--output",
        outdir.to_str().unwrap(),
    ]);
    assert!(
        !out.status.success(),
        "directory encode with --outboard should fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--outboard is for single-file encode only"),
        "stderr should reject --outboard on directory, got: {stderr}"
    );
}

#[test]
fn bin_encode_dir_ignores_format_flag_uses_c14() {
    let samples = manifest_dir().join("tests/samples");
    assert!(samples.is_dir(), "tests/samples required");

    let work = cli_tempdir("dir_format_ignored");
    let outdir = work.join("enc");
    let decdir = work.join("dec");
    fs::create_dir_all(&outdir).expect("outdir");

    let out = run_carbonado(&[
        "encode",
        samples.to_str().unwrap(),
        "--format",
        "6",
        "--output",
        outdir.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "encode failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let catalog = fs::read_dir(&outdir)
        .expect("read enc dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".adam.c14"))
        })
        .expect("catalog .adam.c14 missing");

    let out = run_carbonado(&[
        "decode",
        catalog.to_str().unwrap(),
        "--output",
        decdir.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "decode failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_trees_equal(&samples, &decdir);
}

#[test]
fn bin_encode_dir_emits_bare_segment_mains() {
    let samples = manifest_dir().join("tests/samples");
    assert!(samples.is_dir(), "tests/samples required");

    let work = cli_tempdir("dir_segments_heterogeneous");
    let outdir = work.join("enc");
    fs::create_dir_all(&outdir).expect("outdir");

    let out = run_carbonado(&[
        "encode",
        samples.to_str().unwrap(),
        "--output",
        outdir.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "encode failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let catalog = fs::read_dir(&outdir)
        .expect("read enc dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".adam.c14"))
        })
        .expect("catalog .adam.c14 missing");
    assert_starts_with_carbonado_header(&catalog);

    let has_segment_main = fs::read_dir(&outdir)
        .expect("read enc dir")
        .filter_map(Result::ok)
        .any(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            (name.ends_with(".c12") || name.ends_with(".c14")) && !name.contains(".adam.")
        });
    assert!(has_segment_main, "expected bare .c12 or .c14 segment mains");
    assert_no_sidecars(&catalog);
}

#[test]
fn bin_encode_dir_format_c15_encrypted_roundtrip() {
    let samples = manifest_dir().join("tests/samples");
    assert!(samples.is_dir(), "tests/samples required");

    let work = cli_tempdir("dir_format_c5_enc");
    let outdir = work.join("enc");
    let decdir = work.join("dec");
    let mnemonic_path = work.join("mnemonic");
    fs::create_dir_all(&outdir).expect("outdir");
    let env = [("CARBONADO_MNEMONIC_PATH", mnemonic_path.to_str().unwrap())];

    let out = run_carbonado_env(
        &[
            "encode",
            samples.to_str().unwrap(),
            "--encrypted",
            "--output",
            outdir.to_str().unwrap(),
        ],
        &env,
    );
    assert!(
        out.status.success(),
        "encode failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let catalog = fs::read_dir(&outdir)
        .expect("read enc dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".adam.c15"))
        })
        .expect("catalog .adam.c15 missing");

    let out = run_carbonado_env(
        &[
            "decode",
            catalog.to_str().unwrap(),
            "--output",
            decdir.to_str().unwrap(),
        ],
        &env,
    );
    assert!(
        out.status.success(),
        "decode failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn bin_encode_dir_encrypted_auto_generates_mnemonic() {
    let samples = manifest_dir().join("tests/samples");
    assert!(samples.is_dir(), "tests/samples required");

    let work = cli_tempdir("dir_enc_auto_mnemonic");
    let outdir = work.join("enc");
    let mnemonic_path = work.join("mnemonic");
    fs::create_dir_all(&outdir).expect("outdir");
    let env = [("CARBONADO_MNEMONIC_PATH", mnemonic_path.to_str().unwrap())];

    let out = run_carbonado_env(
        &[
            "encode",
            samples.to_str().unwrap(),
            "--encrypted",
            "--output",
            outdir.to_str().unwrap(),
        ],
        &env,
    );
    assert!(
        out.status.success(),
        "encrypted directory encode should auto-generate mnemonic: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(mnemonic_path.is_file(), "mnemonic should be created");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("generated a new BIP39 mnemonic") && stderr.contains("plaintext"),
        "stderr should explain auto-generation, got: {stderr}"
    );
}

#[test]
fn bin_encode_dir_encrypted_roundtrip() {
    let samples = manifest_dir().join("tests/samples");
    assert!(samples.is_dir(), "tests/samples required");

    let work = cli_tempdir("dir_enc_rt");
    let outdir = work.join("enc");
    let recovered = work.join("recovered");
    let master = test_master_hex();
    fs::create_dir_all(&outdir).expect("outdir");

    let enc = run_carbonado(&[
        "encode",
        samples.to_str().unwrap(),
        "--encrypted",
        "--master",
        &master,
        "--output",
        outdir.to_str().unwrap(),
    ]);
    assert!(
        enc.status.success(),
        "encrypted directory encode failed: {:?}",
        String::from_utf8_lossy(&enc.stderr)
    );

    let catalog = fs::read_dir(&outdir)
        .expect("read enc dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".adam.c15"))
        })
        .expect("catalog .adam.c15 missing");

    let dec = run_carbonado(&[
        "decode",
        catalog.to_str().unwrap(),
        "--master",
        &master,
        "--output",
        recovered.to_str().unwrap(),
    ]);
    assert!(
        dec.status.success(),
        "encrypted directory decode failed: {:?}",
        String::from_utf8_lossy(&dec.stderr)
    );
    assert_trees_equal(&samples, &recovered);
}

#[test]
fn bin_encode_dir_smoke() {
    let samples = manifest_dir().join("tests/samples");
    assert!(
        samples.is_dir(),
        "tests/samples required (content.png, contract.rgbc, code.tar)"
    );

    let work = cli_tempdir("dir_smoke");
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
        "directory encode failed: {:?}",
        enc.status
    );
    let stdout = String::from_utf8_lossy(&enc.stdout);
    assert!(
        stdout.contains("directory archived"),
        "encode summary should mention directory archived, got: {stdout}"
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
    assert_starts_with_carbonado_header(&catalog);
    assert_no_sidecars(&catalog);

    let dec = run_carbonado(&[
        "decode",
        catalog.to_str().unwrap(),
        "--output",
        recovered.to_str().unwrap(),
    ]);
    assert!(
        dec.status.success(),
        "directory decode failed: {:?}",
        String::from_utf8_lossy(&dec.stderr)
    );
    assert_trees_equal(&samples, &recovered);
}

#[test]
fn bin_encode_dir_encrypted_roundtrip_cli() {
    let src = cli_tempdir("dir_enc_src");
    fs::write(src.join("secret.txt"), b"cli encrypted directory").expect("write");
    let outdir = cli_tempdir("dir_enc_out").join("enc");
    let recovered = cli_tempdir("dir_enc_out").join("recovered");
    fs::create_dir_all(&outdir).expect("outdir");

    let enc = run_carbonado(&[
        "encode",
        src.to_str().unwrap(),
        "--encrypted",
        "--master",
        &test_master_hex(),
        "--output",
        outdir.to_str().unwrap(),
    ]);
    assert!(
        enc.status.success(),
        "encrypted directory encode failed: {:?}",
        String::from_utf8_lossy(&enc.stderr)
    );

    let catalog = fs::read_dir(&outdir)
        .expect("read enc")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.is_file()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with(".adam.c15"))
        })
        .expect("catalog .adam.c15 missing");

    let dec = run_carbonado(&[
        "decode",
        catalog.to_str().unwrap(),
        "--master",
        &test_master_hex(),
        "--output",
        recovered.to_str().unwrap(),
    ]);
    assert!(
        dec.status.success(),
        "encrypted directory decode failed: {:?}",
        String::from_utf8_lossy(&dec.stderr)
    );
    assert_eq!(
        fs::read(recovered.join("secret.txt")).expect("read recovered"),
        b"cli encrypted directory"
    );
}

#[test]
fn bin_decode_directory_path() {
    let src = cli_tempdir("dir_path_src");
    fs::write(src.join("one.txt"), b"decode via dir path").expect("write");
    let outdir = cli_tempdir("dir_path_out").join("enc");
    let recovered = cli_tempdir("dir_path_out").join("recovered");
    fs::create_dir_all(&outdir).expect("outdir");

    let enc = run_carbonado(&[
        "encode",
        src.to_str().unwrap(),
        "--output",
        outdir.to_str().unwrap(),
    ]);
    assert!(enc.status.success(), "encode failed: {:?}", enc.status);

    let dec = run_carbonado(&[
        "decode",
        outdir.to_str().unwrap(),
        "--output",
        recovered.to_str().unwrap(),
    ]);
    assert!(
        dec.status.success(),
        "decode via directory path failed: {:?}",
        String::from_utf8_lossy(&dec.stderr)
    );
    assert_eq!(
        fs::read(recovered.join("one.txt")).expect("read recovered"),
        b"decode via dir path"
    );
}

#[test]
fn bin_decode_rejects_bad_master() {
    let work = cli_tempdir("bad_master");
    let input = work.join("input.bin");
    let outdir = work.join("enc");
    let recovered = work.join("recovered.bin");
    fs::create_dir_all(&outdir).expect("outdir");
    fs::write(&input, b"payload for bad master test").expect("write input");

    let enc = run_carbonado(&[
        "encode",
        input.to_str().unwrap(),
        "--format",
        "14",
        "--outboard",
        "--output",
        outdir.to_str().unwrap(),
    ]);
    assert!(enc.status.success(), "setup encode failed");

    let archive = find_single_archive(&outdir);
    let short_master = "ab".repeat(16);
    let out = run_carbonado(&[
        "decode",
        archive.to_str().unwrap(),
        "--master",
        &short_master,
        "--output",
        recovered.to_str().unwrap(),
    ]);
    assert!(
        !out.status.success(),
        "decode with 32 hex master should fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("64"),
        "stderr should mention 64 hex chars, got: {stderr}"
    );
}

#[test]
fn bin_help_and_version() {
    let help = run_carbonado(&["--help"]);
    assert!(
        help.status.success(),
        "--help failed: {:?}",
        help.status.code()
    );
    let help_stdout = String::from_utf8_lossy(&help.stdout);
    assert!(
        help_stdout.contains("encode"),
        "help should document encode"
    );
    assert!(
        help_stdout.contains("decode"),
        "help should document decode"
    );
    assert!(
        help_stdout.contains("BIP39"),
        "help should document BIP39 key material"
    );
    assert!(
        help_stdout.contains("key"),
        "help should document key subcommand"
    );

    let encode_help = run_carbonado(&["encode", "--help"]);
    assert!(encode_help.status.success(), "encode --help failed");
    let encode_stdout = String::from_utf8_lossy(&encode_help.stdout);
    assert!(
        encode_stdout.contains("--format") && encode_stdout.contains("--master"),
        "encode --help should document core flags"
    );

    let version = run_carbonado(&["--version"]);
    assert!(
        version.status.success(),
        "--version failed: {:?}",
        version.status.code()
    );
    let version_stdout = String::from_utf8_lossy(&version.stdout);
    assert!(
        version_stdout.contains("carbonado"),
        "version output should mention carbonado"
    );
}

#[test]
fn bin_decode_inboard_headered() {
    let work = cli_tempdir("decode_inboard");
    let input = work.join("input.bin");
    let outdir = work.join("enc");
    let recovered = work.join("recovered.bin");
    const PAYLOAD: &[u8] = b"format-0 public inboard header decode payload";
    fs::create_dir_all(&outdir).expect("outdir");
    fs::write(&input, PAYLOAD).expect("write input");

    // Format 0 (public, no compression/bao/fec) — distinct from c14 inboard roundtrip test.
    let enc = run_carbonado(&[
        "encode",
        input.to_str().unwrap(),
        "--format",
        "0",
        "--output",
        outdir.to_str().unwrap(),
    ]);
    assert!(enc.status.success(), "encode failed");

    let archive = find_single_archive(&outdir);
    let dec = run_carbonado(&[
        "decode",
        archive.to_str().unwrap(),
        "--output",
        recovered.to_str().unwrap(),
    ]);
    assert!(
        dec.status.success(),
        "headered inboard decode failed: {:?}",
        String::from_utf8_lossy(&dec.stderr)
    );

    let got = fs::read(&recovered).expect("read recovered");
    assert_eq!(got, PAYLOAD);
}

#[test]
fn bin_encode_encrypted_auto_generates_mnemonic() {
    let work = cli_tempdir("enc_auto_mnemonic");
    let input = work.join("secret.bin");
    let outdir = work.join("enc");
    let recovered = work.join("recovered.bin");
    let mnemonic_path = work.join("mnemonic");
    fs::create_dir_all(&outdir).expect("outdir");
    fs::write(&input, b"needs master").expect("write input");
    let env = [("CARBONADO_MNEMONIC_PATH", mnemonic_path.to_str().unwrap())];

    let enc = run_carbonado_env(
        &[
            "encode",
            input.to_str().unwrap(),
            "--format",
            "15",
            "--output",
            outdir.to_str().unwrap(),
        ],
        &env,
    );
    assert!(
        enc.status.success(),
        "encrypted encode should auto-generate mnemonic: {:?}",
        String::from_utf8_lossy(&enc.stderr)
    );
    assert!(mnemonic_path.is_file(), "mnemonic file should exist");
    let enc_stderr = String::from_utf8_lossy(&enc.stderr);
    assert!(
        enc_stderr.contains("generated a new BIP39 mnemonic") && enc_stderr.contains("plaintext"),
        "stderr should explain auto-generation, got: {enc_stderr}"
    );

    let archive = find_single_archive(&outdir);
    let dec = run_carbonado_env(
        &[
            "decode",
            archive.to_str().unwrap(),
            "--output",
            recovered.to_str().unwrap(),
        ],
        &env,
    );
    assert!(
        dec.status.success(),
        "decode with auto-generated mnemonic should succeed: {:?}",
        String::from_utf8_lossy(&dec.stderr)
    );
    assert_eq!(
        fs::read(&recovered).expect("read recovered"),
        b"needs master"
    );
}

#[test]
fn bin_encode_rejects_format_out_of_range() {
    let work = cli_tempdir("format_range_encode");
    let input = work.join("input.bin");
    fs::write(&input, b"format range test").expect("write input");

    let out = run_carbonado(&["encode", input.to_str().unwrap(), "--format", "16"]);
    assert!(!out.status.success(), "encode with format 16 should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("format must be 0-15"),
        "stderr should mention format range, got: {stderr}"
    );
}

#[test]
fn bin_decode_rejects_format_out_of_range() {
    let work = cli_tempdir("format_range_decode");
    let input = work.join("input.bin");
    let outdir = work.join("enc");
    let recovered = work.join("recovered.bin");
    fs::create_dir_all(&outdir).expect("outdir");
    fs::write(&input, b"format range decode test").expect("write input");

    let enc = run_carbonado(&[
        "encode",
        input.to_str().unwrap(),
        "--format",
        "14",
        "--outboard",
        "--output",
        outdir.to_str().unwrap(),
    ]);
    assert!(enc.status.success(), "setup encode failed");

    let archive = find_single_archive(&outdir);
    let out = run_carbonado(&[
        "decode",
        archive.to_str().unwrap(),
        "--format",
        "16",
        "--output",
        recovered.to_str().unwrap(),
    ]);
    assert!(!out.status.success(), "decode with format 16 should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("format must be 0-15"),
        "stderr should mention format range, got: {stderr}"
    );
}

#[test]
fn bin_encode_rejects_zero_master_on_encrypted() {
    let work = cli_tempdir("zero_master_encode");
    let input = work.join("secret.bin");
    fs::write(&input, b"zero master test").expect("write input");

    let zero_master = "00".repeat(32);
    let out = run_carbonado(&[
        "encode",
        input.to_str().unwrap(),
        "--format",
        "15",
        "--master",
        &zero_master,
    ]);
    assert!(
        !out.status.success(),
        "encrypted encode with all-zero master should fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("non-zero master key"),
        "stderr should reject zero master, got: {stderr}"
    );
}

#[test]
fn bin_decode_rejects_encrypted_without_master() {
    let work = cli_tempdir("enc_decode_no_master");
    let input = work.join("secret.bin");
    let outdir = work.join("enc");
    let recovered = work.join("recovered.bin");
    let master = test_master_hex();
    fs::create_dir_all(&outdir).expect("outdir");
    fs::write(&input, ENCRYPTED_PAYLOAD).expect("write input");

    let enc = run_carbonado(&[
        "encode",
        input.to_str().unwrap(),
        "--format",
        "15",
        "--master",
        &master,
        "--output",
        outdir.to_str().unwrap(),
    ]);
    assert!(enc.status.success(), "setup encode failed");

    let archive = find_single_archive(&outdir);
    let out = run_carbonado(&[
        "decode",
        archive.to_str().unwrap(),
        "--output",
        recovered.to_str().unwrap(),
    ]);
    assert!(
        !out.status.success(),
        "encrypted decode without --master should fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("encrypted archive requires --master")
            || stderr.contains("stored BIP39 seed")
            || stderr.contains("key import"),
        "stderr should require master key for decrypt, got: {stderr}"
    );
}

#[test]
fn bin_decode_rejects_format_on_headered_inboard() {
    let work = cli_tempdir("format_on_headered");
    let input = work.join("input.bin");
    let outdir = work.join("enc");
    let recovered = work.join("recovered.bin");
    fs::create_dir_all(&outdir).expect("outdir");
    fs::write(&input, INBOARD_PAYLOAD).expect("write input");

    let enc = run_carbonado(&[
        "encode",
        input.to_str().unwrap(),
        "--format",
        "14",
        "--output",
        outdir.to_str().unwrap(),
    ]);
    assert!(enc.status.success(), "setup encode failed");

    let archive = find_single_archive(&outdir);
    let out = run_carbonado(&[
        "decode",
        archive.to_str().unwrap(),
        "--format",
        "14",
        "--output",
        recovered.to_str().unwrap(),
    ]);
    assert!(
        !out.status.success(),
        "decode with --format on headered inboard should fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("bare outboard decode only"),
        "stderr should reject --format on headered file, got: {stderr}"
    );
}

#[test]
fn bin_outboard_encode_decode() {
    let work = cli_tempdir("outboard");
    let input = work.join("input.bin");
    let outdir = work.join("enc");
    let recovered = work.join("recovered.bin");
    const PAYLOAD: &[u8] = b"bin cli outboard roundtrip payload";
    fs::create_dir_all(&outdir).expect("outdir");
    fs::write(&input, PAYLOAD).expect("write input");

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
        "outboard encode failed: {:?}",
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
        "outboard decode failed: {:?}",
        String::from_utf8_lossy(&dec.stderr)
    );
    assert_eq!(fs::read(&recovered).expect("read recovered"), PAYLOAD);
}

#[test]
fn bin_orphaned_segments_missing_catalog() {
    let work = cli_tempdir("orphan");
    let input = work.join("input.bin");
    let outdir = work.join("enc");
    fs::create_dir_all(&outdir).expect("outdir");
    fs::write(&input, b"segment payload").expect("write input");

    let enc = run_carbonado(&[
        "encode",
        input.to_str().unwrap(),
        "--format",
        "14",
        "--outboard",
        "--output",
        outdir.to_str().unwrap(),
    ]);
    assert!(enc.status.success(), "setup encode failed");

    let archive = find_single_archive(&outdir);
    let orphan_dir = work.join("orphan_only");
    fs::create_dir_all(&orphan_dir).expect("orphan dir");
    fs::copy(&archive, orphan_dir.join(archive.file_name().unwrap())).expect("copy main");
    let stem = archive.file_stem().unwrap().to_string_lossy();
    let out_side = outdir.join(format!("{stem}.c0e.out"));
    if out_side.exists() {
        fs::copy(&out_side, orphan_dir.join(format!("{stem}.c0e.out"))).expect("copy out");
    }

    let dec = run_carbonado(&["decode", orphan_dir.to_str().unwrap()]);
    assert!(
        !dec.status.success(),
        "decode of orphaned segments without catalog should fail"
    );
    let stderr = String::from_utf8_lossy(&dec.stderr);
    assert!(
        stderr.contains("Missing directory catalog:"),
        "stderr should report MissingCatalog, got: {stderr}"
    );
}

#[test]
fn bin_encrypted_outboard_embedded_nonce_roundtrip() {
    let work = cli_tempdir("enc_outboard");
    let input = work.join("secret.bin");
    let outdir = work.join("enc");
    fs::create_dir_all(&outdir).expect("outdir");
    fs::write(&input, b"encrypted outboard CLI contract test payload").expect("write input");

    let master_hex = test_master_hex();
    let enc = run_carbonado(&[
        "encode",
        input.to_str().unwrap(),
        "--format",
        "5",
        "--outboard",
        "--master",
        &master_hex,
        "--output",
        outdir.to_str().unwrap(),
    ]);
    assert!(
        enc.status.success(),
        "encrypted outboard encode failed: {:?}",
        String::from_utf8_lossy(&enc.stderr)
    );

    let archive = find_single_archive(&outdir);
    let recovered = work.join("recovered.bin");
    let dec = run_carbonado(&[
        "decode",
        archive.to_str().unwrap(),
        "--master",
        &master_hex,
        "--output",
        recovered.to_str().unwrap(),
    ]);
    assert!(
        dec.status.success(),
        "encrypted outboard decode failed: {:?}",
        String::from_utf8_lossy(&dec.stderr)
    );
    assert_eq!(
        fs::read(&recovered).expect("read recovered"),
        b"encrypted outboard CLI contract test payload"
    );
}

/// BIP39 test vector (12 words); used for deterministic CLI seed tests.
const TEST_MNEMONIC_WORDS: &[&str] = &[
    "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
    "abandon", "abandon", "abandon", "about",
];

fn mnemonic_env(work: &std::path::Path) -> (String, String) {
    (
        "CARBONADO_MNEMONIC_PATH".to_string(),
        work.join("mnemonic").to_string_lossy().into_owned(),
    )
}

fn import_test_mnemonic(work: &std::path::Path) {
    let mut args = vec!["key", "import"];
    args.extend(TEST_MNEMONIC_WORDS.iter().copied());
    let (key, path) = mnemonic_env(work);
    let env = [(key.as_str(), path.as_str())];
    let out = run_carbonado_env(&args, &env);
    assert!(
        out.status.success(),
        "key import failed: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn bin_key_import_and_encrypted_roundtrip_without_master_flag() {
    let work = cli_tempdir("bip39_roundtrip");
    import_test_mnemonic(&work);

    let input = work.join("secret.bin");
    let outdir = work.join("enc");
    let recovered = work.join("recovered.bin");
    fs::create_dir_all(&outdir).expect("outdir");
    fs::write(&input, ENCRYPTED_PAYLOAD).expect("write input");

    let (key, path) = mnemonic_env(&work);
    let env = [(key.as_str(), path.as_str())];

    let enc = run_carbonado_env(
        &[
            "encode",
            input.to_str().unwrap(),
            "--format",
            "15",
            "--output",
            outdir.to_str().unwrap(),
        ],
        &env,
    );
    assert!(
        enc.status.success(),
        "encode with stored BIP39 failed: {:?}",
        String::from_utf8_lossy(&enc.stderr)
    );

    let archive = find_single_archive(&outdir);
    let dec = run_carbonado_env(
        &[
            "decode",
            archive.to_str().unwrap(),
            "--output",
            recovered.to_str().unwrap(),
        ],
        &env,
    );
    assert!(
        dec.status.success(),
        "decode with stored BIP39 failed: {:?}",
        String::from_utf8_lossy(&dec.stderr)
    );
    assert_eq!(
        fs::read(&recovered).expect("read recovered"),
        ENCRYPTED_PAYLOAD
    );
}

#[test]
fn bin_key_init_writes_mnemonic_file() {
    let work = cli_tempdir("key_init");
    let mnemonic_path = work.join("mnemonic");
    let env = [("CARBONADO_MNEMONIC_PATH", mnemonic_path.to_str().unwrap())];

    let out = run_carbonado_env(&["key", "init", "--words", "12"], &env);
    assert!(
        out.status.success(),
        "key init failed: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(mnemonic_path.is_file(), "mnemonic file should exist");

    let show = run_carbonado_env(&["key", "show"], &env);
    assert!(show.status.success(), "key show failed");
    let phrase = String::from_utf8_lossy(&show.stdout).trim().to_string();
    let word_count = phrase.split_whitespace().count();
    assert_eq!(word_count, 12, "expected 12-word mnemonic, got: {phrase}");
}

#[test]
fn bin_key_path_respects_env_override() {
    let work = cli_tempdir("key_path");
    let mnemonic_path = work.join("custom_seed.txt");
    let env = [("CARBONADO_MNEMONIC_PATH", mnemonic_path.to_str().unwrap())];
    let out = run_carbonado_env(&["key", "path"], &env);
    assert!(out.status.success(), "key path failed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let printed = stdout.trim();
    assert_eq!(printed, mnemonic_path.to_string_lossy());
}

#[test]
fn bin_master_hex_overrides_stored_bip39_seed() {
    let work = cli_tempdir("master_override");
    import_test_mnemonic(&work);

    let input = work.join("secret.bin");
    let outdir = work.join("enc");
    fs::create_dir_all(&outdir).expect("outdir");
    fs::write(&input, ENCRYPTED_PAYLOAD).expect("write input");

    let (key, path) = mnemonic_env(&work);
    let env = [(key.as_str(), path.as_str())];
    let other_master = "cd".repeat(32);

    let enc = run_carbonado_env(
        &[
            "encode",
            input.to_str().unwrap(),
            "--format",
            "15",
            "--master",
            &other_master,
            "--output",
            outdir.to_str().unwrap(),
        ],
        &env,
    );
    assert!(enc.status.success(), "encode with --master override failed");

    let archive = find_single_archive(&outdir);
    let recovered = work.join("recovered.bin");
    let dec_with_seed = run_carbonado_env(
        &[
            "decode",
            archive.to_str().unwrap(),
            "--output",
            recovered.to_str().unwrap(),
        ],
        &env,
    );
    assert!(
        !dec_with_seed.status.success(),
        "decode with BIP39 seed should fail when archive used different --master"
    );

    let dec_with_hex = run_carbonado_env(
        &[
            "decode",
            archive.to_str().unwrap(),
            "--master",
            &other_master,
            "--output",
            recovered.to_str().unwrap(),
        ],
        &env,
    );
    assert!(
        dec_with_hex.status.success(),
        "decode with matching --master should succeed: {:?}",
        String::from_utf8_lossy(&dec_with_hex.stderr)
    );
}

// Symlink input test skipped — accepted per spec; not required on all CI filesystems.
