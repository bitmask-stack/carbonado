//! Phase 3 determinism: parallel RS parity encode matches serial reference output.
//!
//! Run with: `cargo test --test parallel_determinism` (default features include `parallel`).
//!
//! Serial-path coverage without `parallel`: `cargo test --no-default-features --features "pqc,ots,cli" --test serial_fec_path`.

#![cfg(feature = "parallel")]

mod common;

use std::io::Cursor;

use carbonado::constants::{FEC_K, FEC_M};
use carbonado::error::CarbonadoError;
use carbonado::stream::encode::stream_encode_inboard_body;
use carbonado::stream::fec::{
    encode_inboard_buffer, encode_outboard_parity_buffer, write_outboard_parity, FecInboardEncoder,
    FecStripe,
};
use carbonado::stream::parallel::{
    encode_rs_parity_serial, encode_rs_parity_with_config, rs_parity_parallelism_active,
    ParallelConfig,
};
use carbonado::stream::{stream_decode_buffer, stream_encode_buffer};
use carbonado::{decode, encode, scrub, structs::Encoded};
use common::corruption::{flip_byte, InboardShardLayout};
use reed_solomon_erasure::galois_8::ReedSolomon;

use common::inboard_parity::{assert_inboard_body_roundtrip, preprocess_and_body};

const MASTER: [u8; 32] = [0x42; 32];

fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn rs_codec() -> ReedSolomon {
    ReedSolomon::new(FEC_K, FEC_M - FEC_K).expect("rs codec")
}

/// Re-encode parity serially from data shards (stand-in for default-build `rs.encode` path).
fn serial_parity_from_data_shards(
    rs: &ReedSolomon,
    data_shards: &[Vec<u8>],
    chunk_len: usize,
) -> Vec<Vec<u8>> {
    let mut shards = data_shards.to_vec();
    shards.extend((0..FEC_M - FEC_K).map(|_| vec![0u8; chunk_len]));
    encode_rs_parity_serial(rs, &mut shards).expect("serial parity");
    shards
}

/// RS parity fork-join matches serial `encode_sep` on representative stripe sizes.
#[test]
fn rs_parity_parallel_matches_serial_reference() {
    let rs = rs_codec();

    for logical_len in [4096usize, 16_384, 65_536, 262_144] {
        let input = patterned(logical_len);
        let mut enc = FecInboardEncoder::new(logical_len).expect("new");
        enc.feed(Cursor::new(&input)).expect("feed");
        let stripe = enc.finish().expect("finish").expect("stripe");
        let chunk_len = stripe.chunk_len as usize;

        let serial_shards = serial_parity_from_data_shards(&rs, &stripe.shards[..FEC_K], chunk_len);
        assert_eq!(
            stripe.shards, serial_shards,
            "parity shards must match serial reference for logical_len={logical_len}"
        );
    }
}

/// Stripe-boundary payloads (16 KiB ± 1, 32 KiB): parallel FEC bytes match serial reference.
#[test]
fn stripe_boundary_parallel_fec_matches_serial_reference() {
    let rs = rs_codec();

    for logical_len in [16_384 - 1, 16_384, 16_384 + 1, 32_768] {
        let input = patterned(logical_len);
        let (encoded_parallel, pl, cl) = encode_inboard_buffer(&input).expect("parallel encode");

        let mut enc = FecInboardEncoder::new(logical_len).expect("new");
        enc.feed(Cursor::new(&input)).expect("feed");
        let stripe = enc.finish().expect("finish").expect("stripe");
        let serial_shards =
            serial_parity_from_data_shards(&rs, &stripe.shards[..FEC_K], stripe.chunk_len as usize);
        let mut encoded_serial = Vec::new();
        carbonado::stream::fec::write_inboard_stripe(
            &FecStripe {
                shards: serial_shards,
                chunk_len: cl,
            },
            &mut encoded_serial,
        )
        .expect("flatten serial");

        assert_eq!(
            encoded_parallel, encoded_serial,
            "inboard body bytes at logical_len={logical_len}"
        );
        assert_eq!(pl, enc.padding_len());
        assert!(rs_parity_parallelism_active(
            cl as usize,
            ParallelConfig::default()
        ));
    }
}

/// Full c12/c14 inboard encode: parallel feature build matches buffer-path bytes + keyed Bao root.
#[test]
fn c12_c14_parallel_encode_matches_buffer_path() {
    for &format in &[12u8, 14u8] {
        let input = patterned(65_536);
        assert_inboard_body_roundtrip(&MASTER, format, &input);

        let (buf_body, buf_hash, buf_info) =
            stream_encode_buffer(&MASTER, &input, format).expect("buffer encode");
        let (stats, body, _nonce) = preprocess_and_body(&MASTER, format, &input);
        let mut stream_body = Vec::new();
        let (stream_hash, stream_info) =
            stream_encode_inboard_body(Cursor::new(&body), stats, format, &mut stream_body)
                .expect("stream inboard body");

        assert_eq!(stream_body, buf_body, "body bytes c{format}");
        assert_eq!(stream_hash, buf_hash, "keyed Bao root c{format}");
        assert_eq!(stream_info, buf_info, "EncodeInfo c{format}");

        let decoded = stream_decode_buffer(
            &MASTER,
            stream_hash.as_bytes(),
            &stream_body,
            stream_info.padding_len,
            format,
        )
        .expect("decode");
        assert_eq!(decoded, input, "roundtrip c{format}");
    }
}

/// Outboard parity sidecar is identical under parallel RS encode vs serial re-encode.
#[test]
fn outboard_parity_parallel_matches_serial_buffer_path() {
    let rs = rs_codec();
    let input = patterned(32_768);
    let (pl, cl, parity_parallel) = encode_outboard_parity_buffer(&input).expect("parallel path");

    let mut enc = FecInboardEncoder::new(input.len()).expect("new");
    enc.feed(Cursor::new(&input)).expect("feed");
    let stripe = enc.finish().expect("finish").expect("stripe");
    let serial_shards =
        serial_parity_from_data_shards(&rs, &stripe.shards[..FEC_K], stripe.chunk_len as usize);
    let mut parity_serial = Vec::new();
    write_outboard_parity(
        &FecStripe {
            shards: serial_shards,
            chunk_len: cl,
        },
        &mut parity_serial,
    )
    .expect("write parity");

    assert_eq!(parity_parallel, parity_serial, "outboard parity bytes");
    assert_eq!(pl, enc.padding_len());
}

/// Parallel encode + inboard scrub recovery (scrub depends on deterministic FEC re-encode).
#[test]
fn parallel_encode_inboard_scrub_roundtrip_c12_c14() {
    for &format in &[12u8, 14u8] {
        let payload = patterned(16_384);
        let Encoded(orig, hash, info) = encode(&MASTER, &payload, format).expect("encode");
        let hash_bytes = hash.as_bytes();

        assert!(
            matches!(
                scrub(&orig, hash_bytes, &info, format),
                Err(CarbonadoError::UnnecessaryScrub)
            ),
            "pristine c{format}"
        );

        let mut corrupted = orig.clone();
        if corrupted.len() > 64 {
            flip_byte(&mut corrupted, 48, 0x5A);
        }
        let recovered = scrub(&corrupted, hash_bytes, &info, format).expect("scrub c{format}");
        assert_eq!(recovered, orig, "light scrub c{format}");

        let layout = InboardShardLayout::from_encode_info(orig.len(), info.chunk_len);
        let mut chaos = orig.clone();
        let report = common::corruption::scattered_stream_knockout(
            &mut chaos,
            &layout,
            24,
            4,
            &mut rand::thread_rng(),
        );
        assert!(
            report.shards_touched.len() <= 4,
            "knockout must stay within RS budget, touched {:?}",
            report.shards_touched
        );
        let recovered_chaos = scrub(&chaos, hash_bytes, &info, format).expect("chaos scrub");
        assert_eq!(recovered_chaos, orig, "chaos scrub c{format}");

        let decoded = decode(
            &MASTER,
            hash_bytes,
            &recovered_chaos,
            info.padding_len,
            format,
        )
        .expect("decode after scrub");
        assert_eq!(decoded, payload);
    }
}

/// Per-wave worker cap preserves deterministic parity bytes across caps.
#[test]
fn parallel_config_max_threads_preserves_parity_bytes() {
    let rs = rs_codec();
    let input = patterned(16_384);

    let mut enc = FecInboardEncoder::new(input.len()).expect("new");
    enc.feed(Cursor::new(&input)).expect("feed");
    let stripe = enc.finish().expect("finish").expect("stripe");
    let chunk_len = stripe.chunk_len as usize;
    let data = stripe.shards[..FEC_K].to_vec();

    let mut shards_a = data.clone();
    shards_a.extend((0..FEC_M - FEC_K).map(|_| vec![0u8; chunk_len]));
    encode_rs_parity_with_config(
        &rs,
        &mut shards_a,
        chunk_len,
        ParallelConfig { max_threads: 2 },
    )
    .expect("2 workers");

    let mut shards_b = data;
    shards_b.extend((0..FEC_M - FEC_K).map(|_| vec![0u8; chunk_len]));
    encode_rs_parity_with_config(
        &rs,
        &mut shards_b,
        chunk_len,
        ParallelConfig { max_threads: 4 },
    )
    .expect("4 workers");

    assert_eq!(
        shards_a, shards_b,
        "max_threads must not change parity bytes"
    );

    let (encoded, _, _) = encode_inboard_buffer(&input).expect("encode");
    assert_eq!(encoded.len(), FEC_M * chunk_len, "encoded stripe geometry");
}
