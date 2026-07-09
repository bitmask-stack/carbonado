//! Serial FEC encode path (`fec.rs` `rs.encode` branch) when `parallel` is disabled.
//!
//! CI runs this via `cargo test --no-default-features --features "pqc,ots,cli" --test serial_fec_path`.

#![cfg(not(feature = "parallel"))]

use std::io::Cursor;

use carbonado::constants::FEC_M;
use carbonado::stream::fec::{encode_inboard_buffer, FecInboardEncoder};

fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// `FecInboardEncoder` serial `rs.encode` path roundtrips buffer encode at stripe boundaries.
#[test]
fn serial_fec_encoder_matches_buffer_path_at_stripe_boundaries() {
    for logical_len in [16_384 - 1, 16_384, 16_384 + 1, 32_768, 65_536] {
        let input = patterned(logical_len);
        let (buffer_encoded, pl, cl) = encode_inboard_buffer(&input).expect("buffer");

        let mut enc = FecInboardEncoder::new(logical_len).expect("new");
        enc.feed(Cursor::new(&input)).expect("feed");
        let stripe = enc.finish().expect("finish").expect("stripe");
        let mut incremental = Vec::new();
        for shard in &stripe.shards {
            incremental.extend_from_slice(shard);
        }

        assert_eq!(pl, enc.padding_len(), "padding len {logical_len}");
        assert_eq!(cl, enc.chunk_len(), "chunk len {logical_len}");
        assert_eq!(
            incremental, buffer_encoded,
            "serial rs.encode path at logical_len={logical_len}"
        );
        assert_eq!(incremental.len(), FEC_M * cl as usize);
    }
}
