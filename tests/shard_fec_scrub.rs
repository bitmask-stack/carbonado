//! Sharding × FEC × scrub: per-segment corruption and multi-shard archives.

mod common;

use std::io::Cursor;

use anyhow::Result;
use carbonado::{
    error::CarbonadoError, scrub, stream::{
        decode_shards_stream, encode_shard_stream, ShardEncodeResult, ShardSource,
    },
};
use common::corruption::InboardShardLayout;

const MASTER: [u8; 32] = [0x42; 32];
const FORMAT: u8 = 14;
const SEGMENT_BUDGET: u64 = 4 * 1024 * 1024;

fn encode_all_shards(data: &[u8]) -> Vec<(ShardEncodeResult, Vec<u8>)> {
    let mut shards = Vec::new();
    let mut input = Cursor::new(data);
    let mut chunk_index = 0u32;
    loop {
        let mut body = Vec::new();
        let result = encode_shard_stream(
            &MASTER,
            &mut input,
            FORMAT,
            chunk_index,
            SEGMENT_BUDGET,
            None,
            &mut body,
        )
        .expect("encode shard");
        shards.push((result, body));
        if !shards.last().unwrap().0.has_more {
            break;
        }
        chunk_index += 1;
    }
    shards
}

fn headered_shard(result: &ShardEncodeResult, body: &[u8]) -> Vec<u8> {
    let mut out = result.header.try_to_vec().expect("header");
    out.extend_from_slice(body);
    out
}

#[test]
fn shard_fec_padding_boundary_sizes() -> Result<()> {
    // Stripe edges: one byte below/above 16 KiB FEC stripe (4 × 4 KiB slices).
    for size in [
        16 * 1024 - 1,
        16 * 1024,
        16 * 1024 + 1,
        SEGMENT_BUDGET as usize,
        SEGMENT_BUDGET as usize + 1,
    ] {
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let shards = encode_all_shards(&data);
        let sources: Vec<ShardSource> = shards
            .iter()
            .map(|(r, b)| ShardSource {
                chunk_index: r.header.chunk_index,
                encoded: headered_shard(r, b),
            })
            .collect();
        let mut out = Vec::new();
        decode_shards_stream(&MASTER, sources, &mut out)?;
        assert_eq!(out, data, "roundtrip size {size}");
    }
    Ok(())
}

#[test]
fn shard_body_corruption_scrub_one_segment() -> Result<()> {
    let size = 10 * 1024 * 1024;
    let original: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let shards = encode_all_shards(&original);
    assert_eq!(shards.len(), 3);

    let (result, body) = &shards[1];
    let hash_bytes = result.header.hash.as_bytes();
    let info = result.encode_info.clone();

    let mut corrupted_body = body.clone();
    let layout = InboardShardLayout::from_encode_info(corrupted_body.len(), info.chunk_len);
    // Erase four shard stripes (50% RS budget) — guarantees Bao failure + scrub path.
    common::corruption::erase_shards(&mut corrupted_body, &layout, &[0, 2, 4, 6]);

    let recovered_body = scrub(&corrupted_body, hash_bytes, &info, FORMAT)?;
    assert_eq!(recovered_body, *body);

    // Reassemble archive with healed middle shard.
    let sources: Vec<ShardSource> = shards
        .iter()
        .enumerate()
        .map(|(i, (r, b))| {
            let encoded = if i == 1 {
                headered_shard(r, &recovered_body)
            } else {
                headered_shard(r, b)
            };
            ShardSource {
                chunk_index: r.header.chunk_index,
                encoded,
            }
        })
        .collect();

    let mut out = Vec::new();
    decode_shards_stream(&MASTER, sources, &mut out)?;
    assert_eq!(out, original);
    Ok(())
}

#[test]
fn shard_gap_returns_missing_shard_index() {
    let size = 10 * 1024 * 1024;
    let original: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let encoded = encode_all_shards(&original);

    let shard0 = ShardSource {
        chunk_index: 0,
        encoded: headered_shard(&encoded[0].0, &encoded[0].1),
    };
    let shard2 = ShardSource {
        chunk_index: 2,
        encoded: headered_shard(&encoded[2].0, &encoded[2].1),
    };

    let err = decode_shards_stream(&MASTER, [shard0, shard2], Cursor::new(Vec::new())).unwrap_err();
    assert!(matches!(
        err,
        CarbonadoError::MissingShardIndex {
            expected: 1,
            found: 2
        }
    ));
}