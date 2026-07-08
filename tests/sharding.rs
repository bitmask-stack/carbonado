//! Multi-segment sharding via authenticated `Header.chunk_index`.

mod common;

use std::io::Cursor;

use carbonado::{
    constants::MAGICNO,
    error::CarbonadoError,
    stream::{
        decode_shards_stream, encode_shard_stream, ShardEncodeResult, ShardSource,
        DEFAULT_SEGMENT_PLAINTEXT_BUDGET,
    },
};
use rand::RngCore;

use common::header_layout::{self, offsets};

const MASTER: [u8; 32] = [0x42; 32];
const FORMAT: u8 = 14;
const SEGMENT_BUDGET: u64 = 4 * 1024 * 1024; // 4 MiB per shard for ~10 MiB → 3 shards

fn encode_all_shards(
    data: &[u8],
    master_key: &[u8],
    format: u8,
) -> Vec<(ShardEncodeResult, Vec<u8>)> {
    let mut shards = Vec::new();
    let mut input = Cursor::new(data);
    let mut chunk_index = 0u32;
    loop {
        let mut body = Vec::new();
        let result = encode_shard_stream(
            master_key,
            &mut input,
            format,
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
fn shard_roundtrip_three_segments() {
    let size = 10 * 1024 * 1024;
    let original: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();

    let encoded = encode_all_shards(&original, &MASTER, FORMAT);
    assert_eq!(
        encoded.len(),
        3,
        "10 MiB / 4 MiB budget should yield 3 shards"
    );
    assert!(encoded[0].0.has_more);
    assert!(encoded[1].0.has_more);
    assert!(!encoded[2].0.has_more);

    let expected_lens = [SEGMENT_BUDGET, SEGMENT_BUDGET, 2 * 1024 * 1024];
    for (i, (result, _)) in encoded.iter().enumerate() {
        assert_eq!(result.header.chunk_index, i as u32);
        assert_eq!(result.encode_info.input_len as u64, expected_lens[i]);
    }

    let sources: Vec<ShardSource> = encoded
        .iter()
        .map(|(result, body)| ShardSource {
            chunk_index: result.header.chunk_index,
            encoded: headered_shard(result, body),
        })
        .collect();

    let mut recovered = Vec::new();
    let total = decode_shards_stream(&MASTER, sources, &mut recovered).expect("decode shards");
    assert_eq!(total, original.len() as u64);
    assert_eq!(recovered, original);
}

#[test]
fn tampered_chunk_index_fails_authentication() {
    let original: Vec<u8> = (0..SEGMENT_BUDGET as usize)
        .map(|i| (i % 200) as u8)
        .collect();
    let (result, body) = encode_all_shards(&original, &MASTER, FORMAT)
        .into_iter()
        .next()
        .unwrap();

    let mut header_bytes = result.header.try_to_vec().expect("header");
    header_layout::flip_byte(&mut header_bytes, offsets::CHUNK_INDEX);

    let mut tampered = header_bytes;
    tampered.extend_from_slice(&body);

    let err = decode_shards_stream(
        &MASTER,
        [ShardSource {
            chunk_index: 0,
            encoded: tampered,
        }],
        Cursor::new(Vec::new()),
    )
    .unwrap_err();

    assert!(
        matches!(err, CarbonadoError::AuthenticationFailed),
        "tampered chunk_index must fail auth, got {err:?}"
    );
}

#[test]
fn gap_in_shard_sequence_returns_missing_shard_index() {
    let size = 10 * 1024 * 1024;
    let original: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let encoded = encode_all_shards(&original, &MASTER, FORMAT);

    let shard0 = ShardSource {
        chunk_index: 0,
        encoded: headered_shard(&encoded[0].0, &encoded[0].1),
    };
    let shard2 = ShardSource {
        chunk_index: 2,
        encoded: headered_shard(&encoded[2].0, &encoded[2].1),
    };

    let err = decode_shards_stream(&MASTER, [shard0, shard2], Cursor::new(Vec::new())).unwrap_err();

    assert!(
        matches!(
            err,
            CarbonadoError::MissingShardIndex {
                expected: 1,
                found: 2
            }
        ),
        "gap (0, 2) must yield MissingShardIndex {{ expected: 1, found: 2 }}, got {err:?}"
    );
}

#[test]
fn duplicate_shard_index_returns_duplicate_shard_index() {
    let original: Vec<u8> = (0..SEGMENT_BUDGET as usize)
        .map(|i| (i % 200) as u8)
        .collect();
    let (result, body) = encode_all_shards(&original, &MASTER, FORMAT)
        .into_iter()
        .next()
        .unwrap();
    let encoded = headered_shard(&result, &body);

    let shard = ShardSource {
        chunk_index: 0,
        encoded: encoded.clone(),
    };

    let err =
        decode_shards_stream(&MASTER, [shard.clone(), shard], Cursor::new(Vec::new())).unwrap_err();

    assert!(
        matches!(err, CarbonadoError::DuplicateShardIndex(0)),
        "duplicate chunk_index 0 must yield DuplicateShardIndex(0), got {err:?}"
    );
}

#[test]
fn sequence_not_starting_at_zero_returns_invalid_shard_sequence() {
    let original: Vec<u8> = (0..SEGMENT_BUDGET as usize)
        .map(|i| (i % 200) as u8)
        .collect();
    let (result, body) = encode_all_shards(&original, &MASTER, FORMAT)
        .into_iter()
        .next()
        .unwrap();

    let err = decode_shards_stream(
        &MASTER,
        [ShardSource {
            chunk_index: 1,
            encoded: headered_shard(&result, &body),
        }],
        Cursor::new(Vec::new()),
    )
    .unwrap_err();

    assert!(
        matches!(err, CarbonadoError::InvalidShardSequence(_)),
        "shard starting at chunk_index 1 must yield InvalidShardSequence, got {err:?}"
    );
}

#[test]
fn shard_source_chunk_index_mismatch_returns_shard_index_mismatch() {
    let size = 10 * 1024 * 1024;
    let original: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let encoded = encode_all_shards(&original, &MASTER, FORMAT);

    // Authenticated header is chunk_index 1; caller mislabels as 0.
    let mislabeled = ShardSource {
        chunk_index: 0,
        encoded: headered_shard(&encoded[1].0, &encoded[1].1),
    };

    let err = decode_shards_stream(&MASTER, [mislabeled], Cursor::new(Vec::new())).unwrap_err();

    assert!(
        matches!(
            err,
            CarbonadoError::ShardIndexMismatch {
                claimed: 0,
                authenticated: 1
            }
        ),
        "mislabeled ShardSource must yield ShardIndexMismatch {{ claimed: 0, authenticated: 1 }}, got {err:?}"
    );
}

#[test]
fn empty_shard_list_returns_ok_zero() {
    let total = decode_shards_stream(&MASTER, [], Cursor::new(Vec::new())).expect("empty decode");
    assert_eq!(total, 0);
}

#[test]
fn default_segment_budget_matches_u32_max() {
    assert_eq!(DEFAULT_SEGMENT_PLAINTEXT_BUDGET, u32::MAX as u64);
}

#[test]
fn small_payload_roundtrip() {
    let original: Vec<u8> = (0..8192).map(|i| (i % 127) as u8).collect();
    let encoded = encode_all_shards(&original, &MASTER, FORMAT);
    let sources: Vec<ShardSource> = encoded
        .iter()
        .map(|(result, body)| ShardSource {
            chunk_index: result.header.chunk_index,
            encoded: headered_shard(result, body),
        })
        .collect();

    let mut recovered = Vec::new();
    decode_shards_stream(&MASTER, sources, &mut recovered).expect("decode");
    assert_eq!(recovered, original);
}

#[test]
fn shard_roundtrip_encrypted_c15() {
    let size = 10 * 1024 * 1024;
    let original: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let mut master = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut master);

    let encoded = encode_all_shards(&original, &master, 15);
    assert_eq!(
        encoded.len(),
        3,
        "10 MiB / 4 MiB budget should yield 3 shards for c15"
    );
    assert!(encoded[0].0.has_more);
    assert!(encoded[1].0.has_more);
    assert!(!encoded[2].0.has_more);

    let expected_lens = [SEGMENT_BUDGET, SEGMENT_BUDGET, 2 * 1024 * 1024];
    for (i, (result, _)) in encoded.iter().enumerate() {
        assert_eq!(result.header.chunk_index, i as u32);
        assert_eq!(result.encode_info.input_len as u64, expected_lens[i]);
        assert_eq!(result.header.format.bits(), 15);
        assert_ne!(
            result.header.payload_nonce, [0u8; 16],
            "encrypted shard must carry nonce in header"
        );
    }

    let sources: Vec<ShardSource> = encoded
        .iter()
        .map(|(result, body)| ShardSource {
            chunk_index: result.header.chunk_index,
            encoded: headered_shard(result, body),
        })
        .collect();

    let mut recovered = Vec::new();
    let total =
        decode_shards_stream(&master, sources, &mut recovered).expect("decode encrypted c15");
    assert_eq!(total, original.len() as u64);
    assert_eq!(recovered, original);
}

/// Outboard sharding is not exposed: `encode_shard_stream` is inboard-only (header + body).
/// Directory archives use bare segment mains + centralized Bao bundle instead.
/// See doc/TEST_STRATEGY.md P1 item 4 — document limitation, do not add API here.
#[test]
fn shard_encoding_is_inboard_only_no_outboard_api() {
    let original: Vec<u8> = (0..4096).map(|i| (i % 127) as u8).collect();
    let (result, body) = encode_all_shards(&original, &MASTER, 14)
        .into_iter()
        .next()
        .unwrap();

    // Inboard shard: headered archive carries CARBONADO20 magic (not bare outboard main).
    let headered = headered_shard(&result, &body);
    assert!(
        headered.starts_with(MAGICNO),
        "encode_shard_stream produces inboard headered segments, not bare outboard mains"
    );
    assert!(
        !body.starts_with(MAGICNO),
        "shard body alone is verifiable payload without prepended header"
    );
}
