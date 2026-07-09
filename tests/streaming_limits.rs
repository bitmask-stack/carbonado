//! Streaming memory contracts and parallelism bottlenecks.
//!
//! S2 (stripe-bounded inboard FEC encode), S3 (streaming keyed Bao inboard encode),
//! S4 (streaming inboard decode), and S5 (scrub verify oracle without full-body staging) are
//! **shipped** — see encode/decode/scrub contract tests below.

mod common;

use std::io::Cursor;

use carbonado::constants::FEC_M;
use carbonado::decode as low_level_decode;
use carbonado::error::CarbonadoError;
use carbonado::file::{decode, decode_stream, encode, encode_stream, Header};
use carbonado::stream::crypto_stream::{
    stream_decrypt, stream_decrypt_seek, stream_decrypt_with_nonce, stream_decrypt_with_nonce_seek,
};
use carbonado::stream::encode::stream_encode_outboard;
use carbonado::stream::encode::{stream_encode_inboard_body, PreprocessStats};
use carbonado::stream::fec::{encode_inboard_buffer, FecInboardEncoder};
use carbonado::stream::{
    stream_decode, stream_decode_buffer, stream_decode_outboard, stream_decode_outboard_buffer,
    stream_encode_buffer,
};
use carbonado::{encode_outboard, scrub, scrub_outboard, verify_inboard_keyed_oracle};
use rand::RngCore;

use common::inboard_parity::{
    assert_bounded_inboard_body_roundtrip, assert_inboard_body_roundtrip, BoundedReadSeek,
};

const MASTER: [u8; 32] = [0x42; 32];

/// `FecInboardEncoder::feed` matches the buffer-path `encode_inboard_buffer` output.
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

/// `stream_encode_inboard_body` FEC path feeds post-preprocess data incrementally (S2).
/// Output and full [`EncodeInfo`] must match the buffer path for c12/c14.
#[test]
fn stream_encode_inboard_body_fec_matches_buffer_path_c12_c14() {
    for &format in &[12u8, 14u8] {
        let input: Vec<u8> = (0..65_536).map(|i| (i % 251) as u8).collect();
        assert_inboard_body_roundtrip(&MASTER, format, &input);
    }
}

/// Empty inboard FEC body at pipeline level (c12/c14) with decode roundtrip.
#[test]
fn stream_encode_inboard_body_empty_fec_roundtrip() {
    for &format in &[12u8, 14u8] {
        assert_inboard_body_roundtrip(&MASTER, format, &[]);
    }
}

/// Encrypted c15: S2 parity + bounded-read with non-zero master key.
#[test]
fn stream_encode_inboard_body_fec_matches_buffer_path_c15() {
    let mut enc_master = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut enc_master);

    let input: Vec<u8> = (0..65_536).map(|i| (i % 251) as u8).collect();
    assert_inboard_body_roundtrip(&enc_master, 15, &input);
    assert_bounded_inboard_body_roundtrip(&enc_master, 15, &input, 512);
}

/// Non-FEC `stream_copy` path matches buffer encode (c4).
#[test]
fn stream_encode_inboard_body_non_fec_matches_buffer_path_c4() {
    let input: Vec<u8> = (0..16_384).map(|i| (i % 251) as u8).collect();
    assert_inboard_body_roundtrip(&MASTER, 4, &input);
}

/// Non-FEC verification path streams from seekable `Read` without body staging `Vec` (S3).
#[test]
fn stream_encode_inboard_body_verification_seek_read_at_c6() {
    let input: Vec<u8> = (0..16_384).map(|i| (i % 251) as u8).collect();
    assert_inboard_body_roundtrip(&MASTER, 6, &input);
    assert_bounded_inboard_body_roundtrip(&MASTER, 6, &input, 512);
}

/// FEC-only c8: direct `write_inboard_stripe` path without Bao staging.
#[test]
fn stream_encode_inboard_body_fec_matches_buffer_path_c8() {
    let input: Vec<u8> = (0..32_768).map(|i| (i % 251) as u8).collect();
    assert_inboard_body_roundtrip(&MASTER, 8, &input);
}

/// FEC padding geometry boundaries at pipeline level (c8: bare_len == logical_len).
#[test]
fn stream_encode_inboard_body_fec_padding_boundaries() {
    for logical_len in [1usize, 4095, 4096, 4097, 16 * 1024 - 1] {
        let input: Vec<u8> = (0..logical_len).map(|i| (i % 251) as u8).collect();
        assert_inboard_body_roundtrip(&MASTER, 8, &input);
    }
}

/// Contract: FEC inboard encode must not require a pre-FEC allocation sized to `bare_len`.
/// A seekable reader that returns at most 512 bytes per `read` still produces wire-identical output.
#[test]
fn stream_encode_inboard_body_fec_bounded_read_contract() {
    for &format in &[8u8, 12u8, 14u8] {
        let input: Vec<u8> = (0..32_768).map(|i| (i % 251) as u8).collect();
        assert_bounded_inboard_body_roundtrip(&MASTER, format, &input, 512);
    }
}

/// Pipeline-level FEC short read must error (not zero-pad missing logical bytes).
#[test]
fn stream_encode_inboard_body_fec_errors_on_short_read() {
    let body: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
    let short = &body[..4096];
    let stats = PreprocessStats {
        bare_len: body.len() as u64,
        input_len: body.len() as u64,
        bytes_compressed: 0,
    };

    let err = stream_encode_inboard_body(Cursor::new(short), stats, 8, &mut Vec::new())
        .expect_err("short read at pipeline level");

    assert!(
        matches!(
            err,
            CarbonadoError::StdIoError(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof
        ),
        "expected UnexpectedEof for truncated FEC reader, got {err:?}"
    );
}

/// Keyed Bao root commits to the complete leaf set; re-encode is deterministic.
/// S3 streams leaves from the FEC stripe without a flat staging `Vec`, but the
/// Merkle root still depends on every leaf hash (parallel leaf hashing, serial root).
#[test]
fn verification_keyed_root_is_deterministic_over_complete_body() {
    let input = b"keyed root commits to all leaves in the processed body";
    let (body, hash1, info1) = stream_encode_buffer(&[0u8; 32], input, 12).expect("encode");
    let (body2, hash2, _) = stream_encode_buffer(&[0u8; 32], input, 12).expect("re-encode");
    assert_eq!(body, body2);
    assert_eq!(
        hash1, hash2,
        "deterministic keyed root over identical processed body"
    );
    let dec = stream_decode_buffer(&[0u8; 32], hash1.as_bytes(), &body, info1.padding_len, 12)
        .expect("decode");
    assert_eq!(dec, input);
}

/// S5: pristine inboard archive must return `UnnecessaryScrub` via keyed verify oracle
/// (no O(decoded) body staging on scrub entry).
#[test]
fn scrub_s5_pristine_returns_unnecessary_scrub() {
    let input: Vec<u8> = (0..65_536).map(|i| (i % 251) as u8).collect();
    let (encoded, hash, info) = stream_encode_buffer(&[0u8; 32], &input, 14).expect("encode c14");

    let err = scrub(&encoded, hash.as_bytes(), &info, 14).expect_err("pristine must not scrub");
    assert!(
        matches!(err, CarbonadoError::UnnecessaryScrub),
        "expected UnnecessaryScrub, got {err:?}"
    );
}

/// S5: corrupt inboard archive still recovers via combinatorial FEC scrub after verify fails.
#[test]
fn scrub_s5_corrupt_still_recovers() {
    let input: Vec<u8> = (0..65_536).map(|i| (i % 251) as u8).collect();
    let (mut encoded, hash, info) = stream_encode_buffer(&[0u8; 32], &input, 14).expect("encode");

    let flip_at = 8 + (info.chunk_len as usize / 2);
    encoded[flip_at] ^= 0xFF;

    let oracle_err = verify_inboard_keyed_oracle(&encoded, hash.as_bytes(), 14).unwrap_err();
    assert!(
        matches!(oracle_err, CarbonadoError::AuthenticationFailed),
        "scrub-entry oracle must fail AuthenticationFailed on corrupt body, got {oracle_err:?}"
    );

    let recovered = scrub(&encoded, hash.as_bytes(), &info, 14).expect("scrub must recover");
    assert_eq!(
        recovered.len(),
        encoded.len(),
        "scrub recovery preserves encoded body length"
    );
    let decoded = stream_decode_buffer(
        &[0u8; 32],
        hash.as_bytes(),
        &recovered,
        info.padding_len,
        14,
    )
    .expect("decode recovered body");
    assert_eq!(decoded, input, "scrub recovery roundtrip content");
}

/// S5: pristine outboard archive must return `UnnecessaryScrub` via sink-based verify oracle.
#[test]
fn scrub_s5_outboard_pristine_returns_unnecessary_scrub() {
    let input: Vec<u8> = (0..65_536).map(|i| (i % 251) as u8).collect();
    let oenc = encode_outboard(&[0u8; 32], &input, 14).expect("encode outboard c14");
    let ob = oenc.verification_outboard.as_deref();
    let par = oenc.fec_parity.as_deref();

    let err = scrub_outboard(&oenc.main, ob, par, &oenc.info, 14, oenc.hash.as_bytes())
        .expect_err("pristine outboard must not scrub");
    assert!(
        matches!(err, CarbonadoError::UnnecessaryScrub),
        "expected UnnecessaryScrub, got {err:?}"
    );
}

/// Scrub entry routes structural verify failures into recovery (final outcome may be irrecoverable).
#[test]
fn scrub_entry_short_input_attempts_recovery_then_invalid_scrubbed_hash() {
    let short = [0u8; 4];
    let hash = [0u8; 32];
    let info = carbonado::structs::EncodeInfo {
        input_len: 0,
        output_len: 0,
        bytes_compressed: 0,
        compression_factor: 1.0,
        bytes_encrypted: 0,
        bytes_ecc: 0,
        bytes_verifiable: 0,
        amplification_factor: 1.0,
        padding_len: 0,
        chunk_len: 4096,
        verifiable_slice_count: 0,
        chunk_slice_count: 1,
    };

    let err = scrub(&short, &hash, &info, 12).expect_err("short input cannot scrub-recover");
    assert!(
        matches!(err, CarbonadoError::InvalidScrubbedHash),
        "short input must attempt recovery then fail InvalidScrubbedHash, got {err:?}"
    );
}

/// Scrub entry routes truncated Bao response into recovery (final outcome may be irrecoverable).
#[test]
fn scrub_entry_truncated_bao_response_attempts_recovery_then_invalid_scrubbed_hash() {
    let input: Vec<u8> = (0..16_384).map(|i| (i % 251) as u8).collect();
    let (encoded, hash, info) = stream_encode_buffer(&[0u8; 32], &input, 12).expect("encode");
    let truncated = &encoded[..encoded.len() / 2];

    let oracle_err = verify_inboard_keyed_oracle(truncated, hash.as_bytes(), 12).unwrap_err();
    assert!(
        matches!(oracle_err, CarbonadoError::BaoResponseTruncated(_)),
        "truncated response must fail BaoResponseTruncated at oracle, got {oracle_err:?}"
    );

    let err = scrub(truncated, hash.as_bytes(), &info, 12)
        .expect_err("truncated body cannot scrub-recover");
    assert!(
        matches!(err, CarbonadoError::InvalidScrubbedHash),
        "truncated body must attempt recovery then fail InvalidScrubbedHash, got {err:?}"
    );
}

/// RS stripe width is 8 shards; scrub combinatorial search is O(C(n,4)) over extracted
/// shards — inherently serial per archive. Document expected shard count.
#[test]
fn fec_stripe_shard_count_is_eight() {
    assert_eq!(
        FEC_M, 8,
        "RS 4/8 model: 8 shards per stripe (4 data + 4 parity)"
    );
}

/// S4 read-chunk contract: bounded `read` `stream_decode` matches the buffer path on a large c14
/// payload. Proves incremental-read wiring + output parity (not peak-RSS; fixture still holds
/// the encoded blob in `BoundedReadSeek.data`).
#[test]
fn stream_decode_bounded_read_matches_buffer_path() {
    let size = 8 * 1024 * 1024;
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let (encoded, hash, info) = stream_encode_buffer(&[0u8; 32], &data, 14).expect("encode");
    let body_len = encoded.len() as u64;

    let buffer_dec =
        stream_decode_buffer(&[0u8; 32], hash.as_bytes(), &encoded, info.padding_len, 14)
            .expect("buffer decode");

    let mut stream_dec = Vec::new();
    stream_decode(
        &[0u8; 32],
        hash.as_bytes(),
        BoundedReadSeek::new(encoded, 512),
        info.padding_len,
        14,
        Some(body_len),
        &mut stream_dec,
    )
    .expect("streaming decode");

    assert_eq!(
        stream_dec, buffer_dec,
        "stream_decode must match buffer path"
    );
    assert_eq!(stream_dec, data, "roundtrip content");
}

/// `stream_decode` output must match `stream_decode_buffer` for representative inboard formats.
#[test]
fn stream_decode_matches_buffer_path_c4_c6_c8_c12_c14_c15() {
    let mut enc_master = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut enc_master);

    for &format in &[4u8, 6, 8, 12, 14] {
        let input: Vec<u8> = (0..65_536).map(|i| (i % 251) as u8).collect();
        assert_stream_decode_parity(&[0u8; 32], format, &input, None);
    }

    let input: Vec<u8> = (0..65_536).map(|i| (i % 251) as u8).collect();
    assert_stream_decode_parity(&enc_master, 15, &input, None);
}

/// Bounded-read decode parity for Bao-only (c6), Bao+FEC (c12), and encrypted post-stage (c15).
#[test]
fn stream_decode_bounded_read_matches_buffer_path_c6_c12_c15() {
    let mut enc_master = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut enc_master);

    let input: Vec<u8> = (0..65_536).map(|i| (i % 251) as u8).collect();
    assert_stream_decode_parity(&[0u8; 32], 6, &input, Some(512));
    assert_stream_decode_parity(&[0u8; 32], 12, &input, Some(512));
    assert_stream_decode_parity(&enc_master, 15, &input, Some(512));
}

/// Wrong format key on the S4 pipeline must yield `AuthenticationFailed`.
#[test]
fn stream_decode_wrong_format_key_yields_authentication_failed() {
    let input: Vec<u8> = (0..16_384).map(|i| (i % 251) as u8).collect();
    let (encoded, hash, info) = stream_encode_buffer(&[0u8; 32], &input, 12).expect("encode c12");
    let body_len = encoded.len() as u64;

    let err = stream_decode_buffer(&[0u8; 32], hash.as_bytes(), &encoded, info.padding_len, 13)
        .expect_err("wrong format key");
    assert!(
        matches!(err, CarbonadoError::AuthenticationFailed),
        "expected AuthenticationFailed, got {err:?}"
    );

    let mut out = Vec::new();
    let err_stream = stream_decode(
        &[0u8; 32],
        hash.as_bytes(),
        BoundedReadSeek::new(encoded, 512),
        info.padding_len,
        13,
        Some(body_len),
        &mut out,
    )
    .expect_err("bounded stream wrong format key");
    assert!(
        matches!(err_stream, CarbonadoError::AuthenticationFailed),
        "expected AuthenticationFailed on stream_decode, got {err_stream:?}"
    );
}

/// Short inboard Bao bodies (< 8 bytes) return `InvalidHeaderLength` on all decode entry points.
#[test]
fn stream_decode_short_bao_body_invalid_header_length_all_entry_points() {
    let short = [0u8; 4];
    let master = [0x42u8; 32];
    let hash = [0u8; 32];

    let err_decode = low_level_decode(&master, hash.as_ref(), &short, 0, 12).expect_err("decode");
    assert!(
        matches!(err_decode, CarbonadoError::InvalidHeaderLength),
        "low_level_decode: {err_decode:?}"
    );

    let err_buffer =
        stream_decode_buffer(&master, hash.as_ref(), &short, 0, 12).expect_err("buffer");
    assert!(
        matches!(err_buffer, CarbonadoError::InvalidHeaderLength),
        "stream_decode_buffer: {err_buffer:?}"
    );

    let (archive, _) = encode(&master, b"hello", 12, None).expect("encode file");
    let truncated = &archive[..Header::LEN + 4];

    let err_file = decode(&master, truncated).expect_err("file::decode");
    assert!(
        matches!(err_file, CarbonadoError::InvalidHeaderLength),
        "file::decode: {err_file:?}"
    );

    let mut out = Vec::new();
    let err_stream = decode_stream(&master, Cursor::new(truncated), &mut out).expect_err("stream");
    assert!(
        matches!(err_stream, CarbonadoError::InvalidHeaderLength),
        "decode_stream: {err_stream:?}"
    );
}

/// Truncated keyed Bao response after a valid prefix must not zero-pad logical bytes.
#[test]
fn stream_decode_truncated_keyed_response_errors() {
    let input: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
    let (encoded, hash, info) = stream_encode_buffer(&[0u8; 32], &input, 12).expect("encode");
    let truncated = &encoded[..encoded.len() / 2];

    let err = stream_decode_buffer(&[0u8; 32], hash.as_bytes(), truncated, info.padding_len, 12)
        .expect_err("truncated response");
    assert!(
        matches!(err, CarbonadoError::BaoResponseTruncated(_)),
        "truncated keyed response must yield BaoResponseTruncated, got {err:?}"
    );
}

/// Encrypted c15: bounded-read `decode_stream` matches buffer path (streaming EtM decrypt).
#[test]
fn stream_decode_encrypted_bounded_read_matches_buffer_path_c15() {
    let mut enc_master = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut enc_master);

    let input: Vec<u8> = (0..65_536).map(|i| (i % 251) as u8).collect();
    assert_stream_decode_parity(&enc_master, 15, &input, Some(512));
}

/// Header-path encode_stream / decode_stream roundtrip without intermediate body staging.
#[test]
fn encode_stream_decode_stream_roundtrip_c14_c15() {
    let mut enc_master = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut enc_master);

    for &(master, format) in &[(&[0u8; 32], 14u8), (&enc_master, 15u8)] {
        let input: Vec<u8> = (0..65_536).map(|i| (i % 251) as u8).collect();
        let mut body = Vec::new();
        let (header, _) =
            encode_stream(master, Cursor::new(&input), format, None, &mut body).expect("encode");
        let mut archive = header.try_to_vec().expect("header");
        archive.extend_from_slice(&body);

        let mut recovered = Vec::new();
        decode_stream(master, Cursor::new(&archive), &mut recovered).expect("decode_stream");
        assert_eq!(recovered, input, "encode_stream roundtrip c{format}");
    }
}

/// Payload spanning RS stripe geometry (>16 KiB logical) via fused inboard encode.
#[test]
fn stream_encode_inboard_multi_stripe_geometry_roundtrip() {
    let input: Vec<u8> = (0..48_000).map(|i| (i % 251) as u8).collect();
    assert_inboard_body_roundtrip(&MASTER, 12, &input);
    assert_bounded_inboard_body_roundtrip(&MASTER, 12, &input, 512);
}

/// EtM MAC is verified before any plaintext is emitted (tampered tag fails closed).
#[test]
fn stream_decrypt_rejects_tampered_tag_before_plaintext() {
    let mut enc_master = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut enc_master);

    let (archive, _) =
        encode(&enc_master, b"streaming etm mac-before-decrypt", 3, None).expect("encode c3");
    let mut tampered = archive;
    tampered[Header::LEN] ^= 0xFF;

    let err = decode(&enc_master, &tampered).expect_err("tampered payload tag");
    assert!(
        matches!(err, CarbonadoError::AuthenticationFailed),
        "expected AuthenticationFailed before plaintext, got {err:?}"
    );

    let mut out = Vec::new();
    let err_stream = decode_stream(&enc_master, Cursor::new(&tampered), &mut out)
        .expect_err("decode_stream tampered tag");
    assert!(
        matches!(err_stream, CarbonadoError::AuthenticationFailed),
        "decode_stream must fail AuthenticationFailed, got {err_stream:?}"
    );
    assert!(out.is_empty(), "must not emit plaintext before MAC verify");
}

/// Trailing bytes after declared `encoded_body_len` map to `EncodedBodyExceedsDeclaredLength`.
#[test]
fn stream_decode_rejects_trailing_encoded_body_bytes() {
    let input: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();

    for &format in &[4u8, 8, 12] {
        let (encoded, hash, info) =
            stream_encode_buffer(&[0u8; 32], &input, format).expect("encode");
        let declared = encoded.len() as u64;
        let mut with_trailing = encoded.clone();
        with_trailing.push(0xBB);

        let mut out = Vec::new();
        let err = stream_decode(
            &[0u8; 32],
            hash.as_bytes(),
            BoundedReadSeek::new(with_trailing, 512),
            info.padding_len,
            format,
            Some(declared),
            &mut out,
        )
        .expect_err("trailing encoded body bytes");

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

/// Excess ciphertext beyond declared `ct_len` maps to `CiphertextExceedsDeclaredLength`.
#[test]
fn stream_decrypt_excess_ciphertext_errors() {
    let mut enc_master = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut enc_master);

    let pt = b"excess ct length guard";
    let blob = carbonado::crypto::symmetric_encrypt(&enc_master, pt).expect("encrypt");
    let nonce: [u8; 16] = blob[..16].try_into().expect("nonce");
    let body = &blob[16..]; // [tag | ct]

    let ct_len = (body.len() - 64) as u64;
    let mut padded = body.to_vec();
    padded.push(0xAA);

    let err = stream_decrypt_with_nonce_seek(
        &enc_master,
        nonce,
        Cursor::new(&padded),
        &mut Vec::new(),
        Some(ct_len),
    )
    .expect_err("excess ciphertext");
    assert!(
        matches!(
            err,
            CarbonadoError::CiphertextExceedsDeclaredLength { declared } if declared == ct_len
        ),
        "expected CiphertextExceedsDeclaredLength, got {err:?}"
    );
}

/// Truncated ciphertext maps to `InvalidCiphertextLength`.
#[test]
fn stream_decrypt_truncated_ciphertext_errors() {
    let mut enc_master = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut enc_master);

    let pt = b"truncated ct guard";
    let blob = carbonado::crypto::symmetric_encrypt(&enc_master, pt).expect("encrypt");
    let nonce: [u8; 16] = blob[..16].try_into().expect("nonce");
    let body = &blob[16..];
    let ct_len = (body.len() - 64) as u64;
    let truncated = &body[..body.len() - 1];

    let err = stream_decrypt_with_nonce_bounded_helper(&enc_master, nonce, truncated, ct_len);
    assert!(
        matches!(err, CarbonadoError::InvalidCiphertextLength),
        "expected InvalidCiphertextLength, got {err:?}"
    );
}

fn stream_decrypt_with_nonce_bounded_helper(
    master: &[u8; 32],
    nonce: [u8; 16],
    body: &[u8],
    ct_len: u64,
) -> CarbonadoError {
    let mut out = Vec::new();
    stream_decrypt_with_nonce_seek(master, nonce, Cursor::new(body), &mut out, Some(ct_len))
        .expect_err("must fail")
}

/// MAC-before-decrypt on raw streaming crypto helpers (no plaintext before verify).
#[test]
fn stream_crypto_helpers_reject_tampered_tag_before_plaintext() {
    let mut enc_master = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut enc_master);

    let pt = b"crypto helper mac guard";
    let blob = carbonado::crypto::symmetric_encrypt(&enc_master, pt).expect("encrypt");
    let mut tampered = blob.clone();
    tampered[20] ^= 0xFF; // tag region

    // Embedded-nonce non-seek path
    let mut out = Vec::new();
    let err = stream_decrypt(&enc_master, Cursor::new(&tampered), &mut out).expect_err("seek");
    assert!(
        matches!(err, CarbonadoError::AuthenticationFailed),
        "stream_decrypt: {err:?}"
    );
    assert!(out.is_empty(), "stream_decrypt must not emit plaintext");

    // Embedded-nonce seek path
    let mut out = Vec::new();
    let ct_len = (tampered.len() - 80) as u64;
    let err = stream_decrypt_seek(&enc_master, Cursor::new(&tampered), &mut out, Some(ct_len))
        .expect_err("seek");
    assert!(
        matches!(err, CarbonadoError::AuthenticationFailed),
        "stream_decrypt_seek: {err:?}"
    );
    assert!(
        out.is_empty(),
        "stream_decrypt_seek must not emit plaintext"
    );

    // Explicit-nonce [tag|ct] path
    let nonce: [u8; 16] = blob[..16].try_into().expect("nonce");
    let header_body = &blob[16..];
    let mut tampered_header = header_body.to_vec();
    tampered_header[0] ^= 0xFF;
    let mut out = Vec::new();
    let err =
        stream_decrypt_with_nonce(&enc_master, nonce, Cursor::new(&tampered_header), &mut out)
            .expect_err("header path");
    assert!(
        matches!(err, CarbonadoError::AuthenticationFailed),
        "stream_decrypt_with_nonce: {err:?}"
    );
    assert!(
        out.is_empty(),
        "stream_decrypt_with_nonce must not emit plaintext"
    );
}

/// Outboard streaming decode parity (c14 public + c15 embedded vs header-path nonce).
#[test]
fn stream_decode_outboard_bounded_read_matches_buffer_path() {
    let mut enc_master = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut enc_master);

    let input: Vec<u8> = (0..65_536).map(|i| (i % 251) as u8).collect();

    // c14 public (embedded-nonce N/A)
    let o14 = encode_outboard(&[0u8; 32], &input, 14).expect("encode c14");
    assert_stream_decode_outboard_parity(
        &[0u8; 32],
        14,
        &o14.main,
        o14.verification_outboard.as_deref(),
        o14.fec_parity.as_deref(),
        o14.hash.as_bytes(),
        o14.info.padding_len,
        None,
        &input,
        Some(512),
    );

    // c15 embedded nonce (low-level encode_outboard)
    let o15 = encode_outboard(&enc_master, &input, 15).expect("encode c15");
    assert_stream_decode_outboard_parity(
        &enc_master,
        15,
        &o15.main,
        o15.verification_outboard.as_deref(),
        o15.fec_parity.as_deref(),
        o15.hash.as_bytes(),
        o15.info.padding_len,
        None,
        &input,
        Some(512),
    );

    // c15 header-path explicit nonce (stream_encode_outboard)
    let mut main_buf = std::io::Cursor::new(Vec::new());
    let mut bao_buf = Vec::new();
    let mut par_buf = Vec::new();
    let mut nonce = [0u8; 16];
    let (hash, info) = stream_encode_outboard(
        &enc_master,
        std::io::Cursor::new(&input),
        15,
        &mut main_buf,
        Some(&mut bao_buf),
        Some(&mut par_buf),
        &mut nonce,
        true,
    )
    .expect("header-path encode");
    assert_stream_decode_outboard_parity(
        &enc_master,
        15,
        &main_buf.into_inner(),
        Some(&bao_buf),
        Some(&par_buf),
        hash.as_bytes(),
        info.padding_len,
        Some(nonce),
        &input,
        Some(512),
    );
}

#[allow(clippy::too_many_arguments)]
fn assert_stream_decode_outboard_parity(
    master: &[u8; 32],
    format: u8,
    main: &[u8],
    ob: Option<&[u8]>,
    par: Option<&[u8]>,
    hash: &[u8],
    padding: u32,
    explicit_nonce: Option<[u8; 16]>,
    expected: &[u8],
    max_chunk: Option<usize>,
) {
    let buffer_dec =
        stream_decode_outboard_buffer(master, hash, main, ob, par, padding, format, explicit_nonce)
            .expect("buffer decode");

    let chunk = max_chunk.unwrap_or(main.len().max(1));
    let mut stream_dec = Vec::new();
    stream_decode_outboard(
        master,
        hash,
        BoundedReadSeek::new(main.to_vec(), chunk),
        ob.map(|sidecar| BoundedReadSeek::new(sidecar.to_vec(), chunk)),
        par.map(|p| BoundedReadSeek::new(p.to_vec(), chunk)),
        padding,
        format,
        explicit_nonce,
        &mut stream_dec,
    )
    .expect("stream outboard decode");

    assert_eq!(
        stream_dec, buffer_dec,
        "outboard stream vs buffer c{format}"
    );
    assert_eq!(stream_dec, expected, "outboard roundtrip c{format}");
}

fn assert_stream_decode_parity(
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

    let mut stream_dec = Vec::new();
    match max_chunk {
        Some(chunk) => {
            stream_decode(
                master,
                hash.as_bytes(),
                BoundedReadSeek::new(encoded, chunk),
                info.padding_len,
                format,
                Some(body_len),
                &mut stream_dec,
            )
            .expect("bounded stream decode");
        }
        None => {
            stream_decode(
                master,
                hash.as_bytes(),
                Cursor::new(&encoded),
                info.padding_len,
                format,
                Some(body_len),
                &mut stream_dec,
            )
            .expect("stream decode");
        }
    }

    assert_eq!(
        stream_dec, buffer_dec,
        "stream_decode must match stream_decode_buffer for c{format}"
    );
    assert_eq!(stream_dec, input, "roundtrip for c{format}");
}
