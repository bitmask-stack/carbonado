//! Shared helpers for integration tests.
//!
//! Each integration test crate includes only the helpers it needs; allow dead_code
//! so clippy `-D warnings` passes when not every consumer uses every export.
#![allow(dead_code)]

pub mod cli;
pub mod corruption;
pub mod format_matrix;
pub mod header_layout;
pub mod inboard_parity;
pub mod zstd_frame;

/// Tests pass level 20 explicitly. Not a library default.
pub fn zstd20() -> carbonado::ZstdEncode {
    carbonado::ZstdEncode::level(20)
}

/// Low-level inboard encode with an explicit test zstd level (not a library default).
pub fn encode(
    master_key: &[u8],
    input: &[u8],
    format: u8,
) -> Result<carbonado::structs::Encoded, carbonado::error::CarbonadoError> {
    carbonado::encode_with_zstd(master_key, input, format, None, &zstd20())
}

/// Low-level outboard encode with an explicit test zstd level (not a library default).
pub fn encode_outboard(
    master_key: &[u8],
    input: &[u8],
    format: u8,
) -> Result<carbonado::structs::OutboardEncoded, carbonado::error::CarbonadoError> {
    carbonado::encode_outboard_with_zstd(master_key, input, format, None, &zstd20())
}

/// Streaming buffer encode with an explicit test zstd level (not a library default).
pub fn stream_encode_buffer(
    master_key: &[u8],
    input: &[u8],
    format: u8,
) -> Result<
    (
        Vec<u8>,
        carbonado::bao::Hash,
        carbonado::structs::EncodeInfo,
    ),
    carbonado::error::CarbonadoError,
> {
    carbonado::stream::encode::stream_encode_buffer_with_zstd(
        master_key,
        input,
        format,
        None,
        &zstd20(),
    )
}

/// Headered inboard encode with an explicit test zstd level (not a library default).
pub fn file_encode(
    master_key: &[u8],
    input: &[u8],
    level: u8,
    metadata: Option<[u8; 8]>,
) -> Result<(Vec<u8>, carbonado::structs::EncodeInfo), carbonado::error::CarbonadoError> {
    carbonado::file::encode_with_zstd(master_key, input, level, metadata, &zstd20())
}

/// Headered outboard encode with an explicit test zstd level (not a library default).
pub fn file_encode_outboard(
    master_key: &[u8],
    input: &[u8],
    level: u8,
    metadata: Option<[u8; 8]>,
) -> Result<
    (
        Option<carbonado::file::Header>,
        carbonado::structs::OutboardEncoded,
    ),
    carbonado::error::CarbonadoError,
> {
    carbonado::file::encode_outboard_with_zstd(master_key, input, level, metadata, &zstd20())
}

/// Headered stream encode with an explicit test zstd level (not a library default).
pub fn file_encode_stream<R: std::io::Read, W: std::io::Write>(
    master_key: &[u8],
    input: R,
    level: u8,
    metadata: Option<[u8; 8]>,
    output: &mut W,
) -> Result<
    (carbonado::file::Header, carbonado::structs::EncodeInfo),
    carbonado::error::CarbonadoError,
> {
    carbonado::file::encode_stream_with_zstd(master_key, input, level, metadata, output, &zstd20())
}

/// Inboard shard encode with an explicit test zstd level (not a library default).
pub fn encode_shard_stream<R: std::io::BufRead, W: std::io::Write>(
    master_key: &[u8],
    input: R,
    format: u8,
    chunk_index: u32,
    segment_plaintext_budget: u64,
    metadata: Option<[u8; 8]>,
    output: W,
) -> Result<carbonado::stream::ShardEncodeResult, carbonado::error::CarbonadoError> {
    carbonado::encode_shard_stream_with_zstd(
        master_key,
        input,
        format,
        chunk_index,
        segment_plaintext_budget,
        metadata,
        output,
        &zstd20(),
    )
}

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
