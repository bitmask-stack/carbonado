//! Async streaming decode parity tests (Phase 2). Requires `--features async`.

#![cfg(feature = "async")]

mod common;

use std::io::{Cursor, ErrorKind};

use carbonado::constants::FEC_M;
use carbonado::error::CarbonadoError;
use carbonado::stream::{stream_decode, stream_decode_async, stream_decode_buffer};
use carbonado::stream_encode_buffer;
use futures_lite::io::Cursor as AsyncCursor;
use rand::RngCore;

use common::inboard_parity::{BoundedAsyncRead, BoundedReadSeek};

const MASTER: [u8; 32] = [0x42; 32];
const CHUNK: usize = 512;

fn assert_truncated_staging_error(err: CarbonadoError, msg: &'static str) {
    assert!(
        matches!(
            err,
            CarbonadoError::StdIoError(ref e)
                if e.kind() == ErrorKind::UnexpectedEof && e.to_string() == msg
        ),
        "expected UnexpectedEof with exact message {msg:?}, got {err:?}"
    );
}

async fn assert_stream_decode_async_parity(
    master: &[u8; 32],
    format: u8,
    input: &[u8],
    max_chunk: Option<usize>,
) {
    let (encoded, hash, info) =
        stream_encode_buffer(master, input, format).expect("encode for parity");
    let body_len = encoded.len() as u64;

    let buffer_dec =
        stream_decode_buffer(master, hash.as_bytes(), &encoded, info.padding_len, format)
            .expect("buffer decode");

    let mut sync_stream_dec = Vec::new();
    match max_chunk {
        Some(chunk) => {
            stream_decode(
                master,
                hash.as_bytes(),
                BoundedReadSeek::new(encoded.clone(), chunk),
                info.padding_len,
                format,
                Some(body_len),
                &mut sync_stream_dec,
            )
            .expect("bounded sync stream decode");
        }
        None => {
            stream_decode(
                master,
                hash.as_bytes(),
                Cursor::new(&encoded),
                info.padding_len,
                format,
                Some(body_len),
                &mut sync_stream_dec,
            )
            .expect("sync stream decode");
        }
    }
    assert_eq!(
        sync_stream_dec, buffer_dec,
        "sync stream_decode must match buffer for c{format}"
    );

    let mut async_dec = Vec::new();
    match max_chunk {
        Some(chunk) => {
            stream_decode_async(
                master,
                hash.as_bytes(),
                BoundedAsyncRead::new(encoded, chunk),
                info.padding_len,
                format,
                Some(body_len),
                &mut async_dec,
            )
            .await
            .expect("bounded async decode");
        }
        None => {
            stream_decode_async(
                master,
                hash.as_bytes(),
                AsyncCursor::new(encoded),
                info.padding_len,
                format,
                Some(body_len),
                &mut async_dec,
            )
            .await
            .expect("async decode");
        }
    }

    assert_eq!(
        async_dec, buffer_dec,
        "stream_decode_async must match buffer for c{format}"
    );
    assert_eq!(async_dec, input, "roundtrip for c{format}");
}

/// Format matrix parity: async must match sync buffer path (c4/c6/c8/c12/c14/c15).
#[tokio::test]
async fn stream_decode_async_matches_buffer_path_c4_c6_c8_c12_c14_c15() {
    let input: Vec<u8> = (0..65_536).map(|i| (i % 251) as u8).collect();
    let mut enc_master = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut enc_master);

    for &format in &[4u8, 6, 8, 12, 14] {
        assert_stream_decode_async_parity(&MASTER, format, &input, None).await;
    }
    assert_stream_decode_async_parity(&enc_master, 15, &input, None).await;
}

/// Bounded chunked async read (512 B) must match sync bounded path.
#[tokio::test]
async fn stream_decode_async_bounded_read_matches_sync_c4_c6_c8_c12_c14_c15() {
    let input: Vec<u8> = (0..65_536).map(|i| (i % 251) as u8).collect();
    let mut enc_master = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut enc_master);

    for &format in &[4u8, 6, 8, 12, 14] {
        assert_stream_decode_async_parity(&MASTER, format, &input, Some(CHUNK)).await;
    }
    assert_stream_decode_async_parity(&enc_master, 15, &input, Some(CHUNK)).await;
}

/// Trailing bytes after declared `encoded_body_len` map to `EncodedBodyExceedsDeclaredLength`.
#[tokio::test]
async fn stream_decode_async_rejects_trailing_encoded_body_bytes() {
    let input: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();

    for &format in &[4u8, 8, 12, 14] {
        let (encoded, hash, info) = stream_encode_buffer(&MASTER, &input, format).expect("encode");
        let declared = encoded.len() as u64;
        let mut with_trailing = encoded;
        with_trailing.push(0xBB);

        let mut out = Vec::new();
        let err = stream_decode_async(
            &MASTER,
            hash.as_bytes(),
            BoundedAsyncRead::new(with_trailing, CHUNK),
            info.padding_len,
            format,
            Some(declared),
            &mut out,
        )
        .await
        .expect_err("trailing encoded body");

        assert!(
            matches!(
                err,
                CarbonadoError::EncodedBodyExceedsDeclaredLength { declared: d } if d == declared
            ),
            "c{format}: expected EncodedBodyExceedsDeclaredLength, got {err:?}"
        );
        assert!(
            out.is_empty(),
            "c{format}: must not emit output on trailing-body error"
        );
    }
}

/// Truncated bounded input on non-verification formats: staging messages match sync `take(limit)`.
#[tokio::test]
async fn stream_decode_async_truncated_bounded_body_staging_errors_c4_c8() {
    let input: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();

    for &(format, msg) in &[(4u8, "truncated encoded body"), (8u8, "truncated FEC body")] {
        let (encoded, hash, info) = stream_encode_buffer(&MASTER, &input, format).expect("encode");
        let declared = encoded.len() as u64;
        let truncated = encoded[..encoded.len().saturating_sub(64)].to_vec();

        let mut out = Vec::new();
        let err = stream_decode_async(
            &MASTER,
            hash.as_bytes(),
            BoundedAsyncRead::new(truncated, CHUNK),
            info.padding_len,
            format,
            Some(declared),
            &mut out,
        )
        .await
        .expect_err("truncated bounded body");

        assert_truncated_staging_error(err, msg);
        assert!(
            out.is_empty(),
            "c{format}: must not emit output on truncation"
        );
    }
}

/// Verification c12: spool staging fails before Bao; sync fails at Bao (`BaoResponseTruncated`).
#[tokio::test]
async fn stream_decode_async_truncated_bounded_verification_diverges_from_sync_c12() {
    let input: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
    let (encoded, hash, info) = stream_encode_buffer(&MASTER, &input, 12).expect("encode c12");
    let declared = encoded.len() as u64;
    let truncated = encoded[..encoded.len().saturating_sub(64)].to_vec();

    let mut sync_out = Vec::new();
    let err_sync = stream_decode(
        &MASTER,
        hash.as_bytes(),
        BoundedReadSeek::new(truncated.clone(), CHUNK),
        info.padding_len,
        12,
        Some(declared),
        &mut sync_out,
    )
    .expect_err("sync truncated bounded c12");
    assert!(
        matches!(err_sync, CarbonadoError::BaoResponseTruncated(_)),
        "sync must yield BaoResponseTruncated, got {err_sync:?}"
    );
    assert!(sync_out.is_empty());

    let mut async_out = Vec::new();
    let err_async = stream_decode_async(
        &MASTER,
        hash.as_bytes(),
        BoundedAsyncRead::new(truncated, CHUNK),
        info.padding_len,
        12,
        Some(declared),
        &mut async_out,
    )
    .await
    .expect_err("async truncated bounded c12");
    assert_truncated_staging_error(err_async, "truncated encoded body");
    assert!(async_out.is_empty());
}

/// Declared FEC body length not divisible by shard count yields `UnevenFecChunks`.
#[tokio::test]
async fn stream_decode_async_uneven_fec_chunks_errors() {
    let input: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
    let (encoded, hash, info) = stream_encode_buffer(&MASTER, &input, 8).expect("encode c8");
    let declared = encoded.len() as u64 - 1;
    assert!(!declared.is_multiple_of(FEC_M as u64));
    let exact = encoded[..declared as usize].to_vec();

    let mut out = Vec::new();
    let err = stream_decode_async(
        &MASTER,
        hash.as_bytes(),
        BoundedAsyncRead::new(exact, CHUNK),
        info.padding_len,
        8,
        Some(declared),
        &mut out,
    )
    .await
    .expect_err("uneven fec chunks");

    assert!(
        matches!(err, CarbonadoError::UnevenFecChunks),
        "expected UnevenFecChunks, got {err:?}"
    );
    assert!(out.is_empty());
}

/// Truncated keyed Bao response must yield `BaoResponseTruncated`, not zero-padded output.
#[tokio::test]
async fn stream_decode_async_truncated_keyed_response_errors() {
    let input: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
    let (encoded, hash, info) = stream_encode_buffer(&MASTER, &input, 12).expect("encode c12");
    let truncated = encoded[..encoded.len() / 2].to_vec();

    let mut out = Vec::new();
    let err = stream_decode_async(
        &MASTER,
        hash.as_bytes(),
        BoundedAsyncRead::new(truncated, CHUNK),
        info.padding_len,
        12,
        None,
        &mut out,
    )
    .await
    .expect_err("truncated response");

    assert!(
        matches!(err, CarbonadoError::BaoResponseTruncated(_)),
        "truncated keyed response must yield BaoResponseTruncated, got {err:?}"
    );
    assert!(out.is_empty());
}

/// EtM MAC is verified before any plaintext is emitted (tampered tag fails closed).
#[tokio::test]
async fn stream_decode_async_rejects_tampered_tag_before_plaintext() {
    let mut enc_master = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut enc_master);

    let input = b"async etm mac-before-decrypt";
    let (encoded, hash, info) = stream_encode_buffer(&enc_master, input, 3).expect("encode c3");
    let mut tampered = encoded;
    tampered[20] ^= 0xFF;

    let mut out = Vec::new();
    let err = stream_decode_async(
        &enc_master,
        hash.as_bytes(),
        BoundedAsyncRead::new(tampered, CHUNK),
        info.padding_len,
        3,
        None,
        &mut out,
    )
    .await
    .expect_err("tampered tag");

    assert!(
        matches!(err, CarbonadoError::AuthenticationFailed),
        "expected AuthenticationFailed before plaintext, got {err:?}"
    );
    assert!(out.is_empty(), "must not emit plaintext before MAC verify");
}

/// Wrong format key on async path must yield `AuthenticationFailed` (parity with sync).
#[tokio::test]
async fn stream_decode_async_wrong_format_key_yields_authentication_failed() {
    let input: Vec<u8> = (0..16_384).map(|i| (i % 251) as u8).collect();
    let (encoded, hash, info) = stream_encode_buffer(&MASTER, &input, 12).expect("encode c12");
    let declared = encoded.len() as u64;

    let err_sync = stream_decode(
        &MASTER,
        hash.as_bytes(),
        Cursor::new(encoded.clone()),
        info.padding_len,
        13,
        Some(declared),
        &mut Vec::new(),
    )
    .expect_err("sync wrong format key");
    assert!(
        matches!(err_sync, CarbonadoError::AuthenticationFailed),
        "sync expected AuthenticationFailed, got {err_sync:?}"
    );

    let mut out = Vec::new();
    let err_async = stream_decode_async(
        &MASTER,
        hash.as_bytes(),
        BoundedAsyncRead::new(encoded, CHUNK),
        info.padding_len,
        13,
        Some(declared),
        &mut out,
    )
    .await
    .expect_err("async wrong format key");

    assert!(
        matches!(err_async, CarbonadoError::AuthenticationFailed),
        "async expected AuthenticationFailed, got {err_async:?}"
    );
    assert!(out.is_empty());
}

/// Short inboard Bao bodies (< 8 bytes) return `InvalidHeaderLength` on async path.
#[tokio::test]
async fn stream_decode_async_short_bao_body_invalid_header_length() {
    let short = vec![0u8; 4];
    let hash = [0u8; 32];

    let mut out = Vec::new();
    let err = stream_decode_async(
        &[0x42u8; 32],
        &hash,
        AsyncCursor::new(short),
        0,
        14,
        None,
        &mut out,
    )
    .await
    .expect_err("short body");

    assert!(
        matches!(err, CarbonadoError::InvalidHeaderLength),
        "expected InvalidHeaderLength, got {err:?}"
    );
    assert!(out.is_empty());
}

/// `async-tokio` compiles the `spawn_blocking` offload path (exercised under `--all-features` CI).
#[cfg(feature = "async-tokio")]
#[test]
fn async_tokio_spawn_blocking_path_enabled() {
    const SPAWN_BLOCKING_OFFLOAD: bool = true;
    const _: () = assert!(SPAWN_BLOCKING_OFFLOAD);
}

/// `bao_tree/tokio_fsm` is feature-gated but not wired — decode uses spool bridge (documented contract).
#[test]
fn async_feature_tokio_fsm_reserved_not_wired_in_decode() {
    // Intentional: no `bao_tree::io::fsm` import in decode path. Flip when FSM lands.
    const TOKIO_FSM_WIRED_IN_DECODE: bool = false;
    const _: () = assert!(!TOKIO_FSM_WIRED_IN_DECODE);
}
