//! FEC chaos: distributed random byte knockout up to 50% shard budget (RS 4/8).
//!
//! Validates scrub recovery when corruption is spread throughout the encoded stream
//! (multiple shards, random offsets) — not clustered in a single segment.

mod common;

use anyhow::Result;
use carbonado::{decode, encode, error::CarbonadoError, scrub, structs::Encoded};
use common::corruption::{scattered_stream_knockout, InboardShardLayout};
use common::format_matrix::{bao_zfec_levels, format_label};
use proptest::prelude::*;
use rand::Rng;

const CHAOS_PAYLOAD_SIZES: [usize; 5] = [4096, 16_384, 65_536, 131_072, 262_144];

fn varied_payload(size: usize, seed: u8) -> Vec<u8> {
    (0..size)
        .map(|i| (i.wrapping_mul(13).wrapping_add(seed as usize)) as u8)
        .collect()
}

#[test]
fn distributed_knockout_recovers_up_to_four_shards_public_bao_zfec() -> Result<()> {
    let mut rng = rand::thread_rng();
    let key = [0u8; 32];

    for level in bao_zfec_levels().filter(|l| l & 1 == 0) {
        for &size in &CHAOS_PAYLOAD_SIZES {
            let payload = varied_payload(size, level);
            let Encoded(orig, hash, info) = encode(&key, &payload, level)?;
            let hash_bytes = hash.as_bytes();

            // Good data must not scrub.
            assert!(
                matches!(
                    scrub(&orig, hash_bytes, &info, level),
                    Err(CarbonadoError::UnnecessaryScrub)
                ),
                "unnecessary scrub for {} size {}",
                format_label(level),
                size
            );

            let layout = InboardShardLayout::from_encode_info(orig.len(), info.chunk_len);

            // Distributed knockouts spread across ≤4 data shards (50% RS budget).
            let mut corrupted = orig.clone();
            let knockouts = (size / 512).clamp(8, 48);
            let report = scattered_stream_knockout(
                &mut corrupted,
                &layout,
                knockouts,
                layout.max_recoverable_bad_shards(),
                &mut rng,
            );
            assert!(
                report.shards_touched.len() <= 4,
                "must stay within RS recovery: {:?}",
                report.shards_touched
            );
            assert!(
                report.positions.len() >= 4,
                "knockouts spread across stream"
            );
            assert!(
                scrub(&orig, hash_bytes, &info, level).is_err(),
                "sanity: pristine must not scrub for {} size {}",
                format_label(level),
                size
            );

            let recovered = scrub(&corrupted, hash_bytes, &info, level).unwrap_or_else(|e| {
                panic!(
                    "scrub failed level {} size {} shards {:?}: {e}",
                    format_label(level),
                    size,
                    report.shards_touched
                )
            });
            assert_eq!(recovered, orig, "byte-identical recovery");

            let dec = decode(&key, hash_bytes, &recovered, info.padding_len, level)?;
            assert_eq!(dec, payload);
        }
    }
    Ok(())
}

#[test]
fn encrypted_distributed_knockout_roundtrip_content() -> Result<()> {
    let mut rng = rand::thread_rng();
    for level in [13u8, 15] {
        let payload = varied_payload(32_768, level);
        let mut key = [0u8; 32];
        rand::thread_rng().fill(&mut key);
        let Encoded(orig, hash, info) = encode(&key, &payload, level)?;
        let hash_bytes = hash.as_bytes();

        let layout = InboardShardLayout::from_encode_info(orig.len(), info.chunk_len);
        let mut corrupted = orig.clone();
        scattered_stream_knockout(&mut corrupted, &layout, 80, 4, &mut rng);

        let recovered = scrub(&corrupted, hash_bytes, &info, level)?;
        assert_eq!(recovered, orig);
        let dec = decode(&key, hash_bytes, &recovered, info.padding_len, level)?;
        assert_eq!(dec, payload);
    }
    Ok(())
}

#[test]
fn five_shard_touch_fails_scrub_proves_fifty_percent_limit() -> Result<()> {
    let payload = varied_payload(65_536, 12);
    let Encoded(orig, hash, info) = encode(&[0u8; 32], &payload, 12)?;
    let hash_bytes = hash.as_bytes();
    let layout = InboardShardLayout::from_encode_info(orig.len(), info.chunk_len);

    let mut corrupted = orig.clone();
    common::corruption::erase_shards(&mut corrupted, &layout, &[0, 1, 2, 3, 4]);

    let err = scrub(&corrupted, hash_bytes, &info, 12).unwrap_err();
    assert!(
        matches!(err, CarbonadoError::InvalidScrubbedHash),
        "5/8 shard loss must be irrecoverable, got {err:?}"
    );
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        .. ProptestConfig::default()
    })]

    #[test]
    fn proptest_distributed_knockout_c12(
        size in 4096usize..=65536,
        knockouts in 8usize..=64,
    ) {
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let Encoded(orig, hash, info) = encode(&[0u8; 32], &payload, 12)?;
        let hash_bytes = hash.as_bytes();
        let layout = InboardShardLayout::from_encode_info(orig.len(), info.chunk_len);

        let mut corrupted = orig.clone();
        let mut rng = rand::thread_rng();
        scattered_stream_knockout(&mut corrupted, &layout, knockouts, 4, &mut rng);

        let recovered = scrub(&corrupted, hash_bytes, &info, 12)?;
        prop_assert_eq!(&recovered, &orig);
        let dec = decode(&[0u8; 32], hash_bytes, &recovered, info.padding_len, 12)?;
        prop_assert_eq!(dec, payload);
    }
}
