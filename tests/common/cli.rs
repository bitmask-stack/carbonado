//! Shared helpers for `carbonado` binary integration tests.
//!
//! Not every integration test crate uses every helper; allow dead_code so
//! clippy `-D warnings` passes when `cli` is pulled in via `mod common`.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use carbonado::paths::{guess_format_from_filename, is_adam_catalog};

pub fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn carbonado_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_carbonado"))
}

/// Create a unique temp directory: `{prefix}_{pid}` under the system temp dir.
pub fn tempdir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("{prefix}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create tempdir");
    dir
}

pub fn run_carbonado(args: &[&str]) -> std::process::Output {
    run_carbonado_env(args, &[])
}

pub fn run_carbonado_env(args: &[&str], env: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new(carbonado_bin());
    cmd.args(args).current_dir(manifest_dir());
    for (key, value) in env {
        cmd.env(key, value);
    }
    cmd.output().expect("spawn carbonado binary")
}

pub fn find_single_archive(outdir: &Path) -> PathBuf {
    // Single-file CLI uses hex format suffix (e.g. format 14 -> `.c0e`), not decimal `.c14`.
    let mut matches: Vec<PathBuf> = fs::read_dir(outdir)
        .expect("read outdir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && guess_format_from_filename(p).is_some()
                && !is_adam_catalog(p)
                && !p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with(".out") || n.ends_with(".par"))
        })
        .collect();
    matches.sort();
    assert_eq!(
        matches.len(),
        1,
        "expected one archive artifact in {outdir:?}, found {:?}",
        matches
    );
    matches.remove(0)
}
