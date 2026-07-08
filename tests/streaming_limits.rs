//! Documents current streaming memory and parallelism bottlenecks.
//!
//! These tests encode **observed limits** of the implementation. They pass today
//! because they assert present behavior; when true streaming FEC/Bao lands, update
//! or remove the corresponding tests.

mod common;

use std::io::Cursor;

use carbonado::constants::FEC_M;
use carbonado::stream::fec::{encode_inboard_buffer, FecInboardEncoder};
use carbonado::stream::{stream_encode_buffer, stream_decode_buffer};

/// Inboard encode currently stages the full pre-FEC body before `encode_inboard_buffer`.
/// Peak memory is O(input) per segment, not O(stripe).
#[test]
fn inboard_fec_encoder_incremental_feed_matches_buffer_path() {
    let input: Vec<u8> = (0..65_536).map(|i| (i % 251) as u8).collect();

    let (buffer_encoded, pl, cl) = encode_inboard_buffer(&input).expect("buffer");

    let mut enc = FecInboardEncoder::new(input.len()).expect("new");
    let mut off = 0usize;
    while off < input.len() {
        let step = 256.min(input.len() - off);
        let _ = enc
            .feed(Cursor::new(&input[off..off + step]))
            .expect("feed");
        off += step;
    }
    let stripe = enc.finish().expect("finish").expect("stripe");
    let mut incremental = Vec::new();
    for shard in &stripe.shards {
        incremental.extend_from_slice(shard);
    }

    assert_eq!(pl, enc.padding_len());
    assert_eq!(cl, enc.chunk_len());
    assert_eq!(incremental.len(), buffer_encoded.len());
    assert_eq!(incremental, buffer_encoded);
}

/// Bao root over inboard body requires the full processed payload before tree build.
/// Parallelizing keyed root computation across stripes without buffering is not
/// supported — this test documents the serial dependency.
#[test]
fn bao_zfec_encode_root_depends_on_full_staged_body() {
    let input = b"parallelism bottleneck: bao root needs complete body";
    let (body, hash1, info1) = stream_encode_buffer(&[0u8; 32], input, 12).expect("encode");
    let (body2, hash2, _) = stream_encode_buffer(&[0u8; 32], input, 12).expect("re-encode");
    assert_eq!(body, body2);
    assert_eq!(hash1, hash2, "deterministic keyed root requires full body hash tree");
    let dec = stream_decode_buffer(
        &[0u8; 32],
        hash1.as_bytes(),
        &body,
        info1.padding_len,
        12,
    )
    .expect("decode");
    assert_eq!(dec, input);
}

/// RS stripe width is 8 shards; scrub combinatorial search is O(C(n,4)) over extracted
/// shards — inherently serial per archive. Document expected shard count.
#[test]
fn fec_stripe_shard_count_is_eight() {
    assert_eq!(FEC_M, 8, "RS 4/8 model: 8 shards per stripe (4 data + 4 parity)");
}

/// Aspirational: when streaming decode avoids full-body buffer, this bound should tighten.
/// Ignored until implemented — un-ignore and lower threshold when P2 streaming FEC ships.
#[test]
#[ignore = "aspirational: stream_decode_buffer currently materializes full body (see doc/STREAMING_PARALLELISM.md)"]
fn stream_decode_should_not_materialize_full_body() {
    let size = 8 * 1024 * 1024;
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let (encoded, hash, info) =
        stream_encode_buffer(&[0u8; 32], &data, 14).expect("encode");
    let _decoded =
        stream_decode_buffer(&[0u8; 32], hash.as_bytes(), &encoded, info.padding_len, 14)
            .expect("decode");
    // Future: track peak RSS < size + stripe overhead. Today: documents gap only.
    panic!("streaming decode still buffers full body — implement bounded-memory path");
}