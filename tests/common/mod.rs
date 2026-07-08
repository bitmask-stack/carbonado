//! Shared helpers for integration tests.
//!
//! Each integration test crate includes only the helpers it needs; allow dead_code
//! so clippy `-D warnings` passes when not every consumer uses every export.
#![allow(dead_code)]

pub mod cli;
pub mod corruption;
pub mod format_matrix;
pub mod header_layout;

use std::fs;
use std::path::Path;

/// Recursively compare two directory trees for byte-identical file contents.
pub fn assert_trees_equal(a: &Path, b: &Path) {
    fn collect_files(base: &Path, prefix: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        for entry in fs::read_dir(base).expect("read_dir") {
            let entry = entry.expect("entry");
            let path = entry.path();
            let rel = prefix.join(entry.file_name());
            if path.is_dir() {
                collect_files(&path, &rel, out);
            } else if path.is_file() {
                let data = fs::read(&path).expect("read file");
                out.push((rel.to_string_lossy().replace('\\', "/"), data));
            }
        }
    }
    let mut left = Vec::new();
    let mut right = Vec::new();
    collect_files(a, Path::new(""), &mut left);
    collect_files(b, Path::new(""), &mut right);
    left.sort_by(|a, b| a.0.cmp(&b.0));
    right.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(left, right, "directory trees differ");
}
