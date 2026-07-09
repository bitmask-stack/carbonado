//! FEC chaos: distributed random byte knockout up to 50% shard budget (RS 4/8).
//!
//! Validates scrub recovery when corruption is spread throughout the encoded stream
//! (multiple shards, random offsets) — not clustered in a single segment.

mod common;

use anyhow::Result;
use carbonado::{
    decode, decode_outboard, encode, encode_outboard, error::CarbonadoError, scrub, scrub_outboard,
    structs::Encoded,
};
use common::corruption::{
    scattered_outboard_main_knockout, scattered_stream_knockout, InboardShardLayout,
    OutboardShardLayout,
};
use common::format_matrix::{format_label, verification_fec_levels};
use proptest::prelude::*;
use rand::Rng;

const CHAOS_PAYLOAD_SIZES: [usize; 5] = [4096, 16_384, 65_536, 131_072, 262_144];

/// Payload sizes spanning the 16 KiB RS stripe geometry edge (4 × 4 KiB data shards).
/// Carbonado buffer encode emits one RS stripe per blob, scaling `chunk_len` above 16 KiB
/// rather than multiple fixed 16 KiB stripes.
const STRIPE_BOUNDARY_SIZES: [usize; 5] = [16 * 1024 - 1, 16 * 1024, 16 * 1024 + 1, 32_768, 49_152];

fn varied_payload(size: usize, seed: u8) -> Vec<u8> {
    (0..size)
        .map(|i| (i.wrapping_mul(13).wrapping_add(seed as usize)) as u8)
        .collect()
}

#[test]
fn distributed_knockout_recovers_up_to_four_shards_public_bao_zfec() -> Result<()> {
    let mut rng = rand::thread_rng();
    let key = [0u8; 32];

    for level in verification_fec_levels().filter(|l| l & 1 == 0) {
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
                !report.positions.is_empty(),
                "knockouts require non-empty data shard ranges"
            );
            assert!(
                matches!(
                    scrub(&orig, hash_bytes, &info, level),
                    Err(CarbonadoError::UnnecessaryScrub)
                ),
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
fn outboard_distributed_knockout_scrub_recover_c12_c14_c15() -> Result<()> {
    let mut rng = rand::thread_rng();

    for level in [12u8, 14, 15] {
        let key = if level & 1 != 0 {
            let mut k = [0u8; 32];
            rng.fill(&mut k);
            k
        } else {
            [0u8; 32]
        };
        let payload = varied_payload(32_768, level);
        let oenc = encode_outboard(&key, &payload, level)?;
        let hash_bytes = oenc.hash.as_bytes();
        let ob = oenc.verification_outboard.as_deref().expect("bao outboard");
        let par = oenc.fec_parity.as_deref().expect("fec parity");

        assert!(matches!(
            scrub_outboard(
                &oenc.main,
                Some(ob),
                Some(par),
                &oenc.info,
                level,
                hash_bytes
            ),
            Err(CarbonadoError::UnnecessaryScrub)
        ));

        let layout = OutboardShardLayout::from_outboard_encode(
            oenc.main.len(),
            par.len(),
            oenc.info.chunk_len,
        );
        let mut corrupted = oenc.main.clone();
        let report = scattered_outboard_main_knockout(
            &mut corrupted,
            &layout,
            48,
            layout.max_recoverable_bad_shards(),
            &mut rng,
        );
        assert!(
            report.shards_touched.len() <= 4,
            "outboard chaos must stay within RS budget: {:?}",
            report.shards_touched
        );
        assert!(
            !report.positions.is_empty(),
            "knockouts spread across bare main"
        );

        let recovered = scrub_outboard(
            &corrupted,
            Some(ob),
            Some(par),
            &oenc.info,
            level,
            hash_bytes,
        )?;
        assert_eq!(
            recovered, oenc.main,
            "scrub_outboard byte-identical recovery"
        );

        let dec = decode_outboard(
            &key,
            hash_bytes,
            &recovered,
            Some(ob),
            Some(par),
            oenc.info.padding_len,
            level,
        )?;
        assert_eq!(dec, payload);
    }
    Ok(())
}

#[test]
fn fec_with_parity_outboard_decode_without_scrub() -> Result<()> {
    let key = [0u8; 32];

    // Zfec-only outboard (no Bao gate): decode_outboard calls fec_with_parity directly.
    // Truncating bare main erases trailing data shards; RS reconstructs from intact `.par`.
    // XOR bit-flip corruption on Bao+Zfec paths still requires scrub_outboard.
    // c8 only: bare main bytes map 1:1 to pre-FEC logical body (c10 Snappy shrinks main vs chunk).
    for level in [8u8] {
        for &size in &[16_384usize, 32_768] {
            let payload = varied_payload(size, level);
            let oenc = encode_outboard(&key, &payload, level)?;
            let par = oenc.fec_parity.as_deref().expect("parity sidecar");
            let chunk = oenc.info.chunk_len as usize;

            let erase_shards = if size > 16_384 { 2 } else { 1 };
            let keep = oenc.main.len().saturating_sub(erase_shards * chunk);
            assert!(
                keep >= chunk,
                "truncation must leave at least one data shard"
            );
            let truncated = &oenc.main[..keep];

            let dec = decode_outboard(
                &key,
                oenc.hash.as_bytes(),
                truncated,
                None,
                Some(par),
                oenc.info.padding_len,
                level,
            )?;
            assert_eq!(
                dec,
                payload,
                "fec_with_parity erasure recovery {} size {} keep {}",
                format_label(level),
                size,
                keep
            );
        }
    }
    Ok(())
}

#[test]
fn scrub_outboard_truncated_main_recovers_c14() -> Result<()> {
    let mut rng = rand::thread_rng();
    let key = [0u8; 32];
    // Random payload resists Snappy shrink so bare main spans multiple FEC data shards.
    let mut payload = vec![0u8; 131_072];
    rng.fill(&mut payload[..]);
    let oenc = encode_outboard(&key, &payload, 14)?;
    let hash_bytes = oenc.hash.as_bytes();
    let ob = oenc.verification_outboard.as_deref().expect("bao outboard");
    let par = oenc.fec_parity.as_deref().expect("fec parity");
    let chunk = oenc.info.chunk_len as usize;

    // Truncate bare main (JBOD tail loss); parity retains encode-time geometry.
    let erase_shards = if oenc.main.len() >= 3 * chunk { 2 } else { 1 };
    let keep = oenc.main.len().saturating_sub(erase_shards * chunk);
    assert!(
        keep >= chunk,
        "truncation must leave at least one data shard (main {} chunk {})",
        oenc.main.len(),
        chunk
    );
    let truncated = &oenc.main[..keep];

    let recovered = scrub_outboard(truncated, Some(ob), Some(par), &oenc.info, 14, hash_bytes)?;
    assert_eq!(recovered, oenc.main);

    let dec = decode_outboard(
        &key,
        hash_bytes,
        &recovered,
        Some(ob),
        Some(par),
        oenc.info.padding_len,
        14,
    )?;
    assert_eq!(dec, payload);
    Ok(())
}

#[test]
fn stripe_boundary_inboard_distributed_chaos() -> Result<()> {
    let mut rng = rand::thread_rng();
    let key = [0u8; 32];

    for &size in &STRIPE_BOUNDARY_SIZES {
        let payload = varied_payload(size, 12);
        let Encoded(orig, hash, info) = encode(&key, &payload, 12)?;
        let hash_bytes = hash.as_bytes();
        let layout = InboardShardLayout::from_encode_info(orig.len(), info.chunk_len);

        let mut corrupted = orig.clone();
        let knockouts = (size / 256).clamp(12, 64);
        let report = scattered_stream_knockout(&mut corrupted, &layout, knockouts, 4, &mut rng);
        assert!(
            report.shards_touched.len() <= 4,
            "stripe-boundary size {size} shards {:?}",
            report.shards_touched
        );

        let recovered = scrub(&corrupted, hash_bytes, &info, 12)?;
        assert_eq!(
            recovered, orig,
            "inboard stripe-boundary recovery size {size}"
        );

        let dec = decode(&key, hash_bytes, &recovered, info.padding_len, 12)?;
        assert_eq!(dec, payload);
    }
    Ok(())
}

#[test]
fn stripe_boundary_outboard_scrub_chaos() -> Result<()> {
    let mut rng = rand::thread_rng();
    let key = [0u8; 32];

    for &size in &STRIPE_BOUNDARY_SIZES {
        let payload = varied_payload(size, 14);
        let oenc = encode_outboard(&key, &payload, 14)?;
        let hash_bytes = oenc.hash.as_bytes();
        let ob = oenc.verification_outboard.as_deref().expect("bao outboard");
        let par = oenc.fec_parity.as_deref().expect("fec parity");

        let layout = OutboardShardLayout::from_outboard_encode(
            oenc.main.len(),
            par.len(),
            oenc.info.chunk_len,
        );
        let mut corrupted = oenc.main.clone();
        let knockouts = (size / 256).clamp(12, 64);
        let report =
            scattered_outboard_main_knockout(&mut corrupted, &layout, knockouts, 4, &mut rng);
        assert!(
            report.shards_touched.len() <= 4,
            "outboard stripe-boundary size {size} shards {:?}",
            report.shards_touched
        );
        assert!(
            !report.positions.is_empty(),
            "outboard stripe-boundary knockouts size {size}"
        );

        let recovered =
            scrub_outboard(&corrupted, Some(ob), Some(par), &oenc.info, 14, hash_bytes)?;
        assert_eq!(
            recovered, oenc.main,
            "outboard stripe-boundary scrub recovery size {size}"
        );

        let dec = decode_outboard(
            &key,
            hash_bytes,
            &recovered,
            Some(ob),
            Some(par),
            oenc.info.padding_len,
            14,
        )?;
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
        let report = scattered_stream_knockout(&mut corrupted, &layout, knockouts, 4, &mut rng);
        prop_assert!(report.shards_touched.len() <= 4);
        prop_assert!(!report.positions.is_empty());

        let recovered = scrub(&corrupted, hash_bytes, &info, 12)?;
        prop_assert_eq!(&recovered, &orig);
        let dec = decode(&[0u8; 32], hash_bytes, &recovered, info.padding_len, 12)?;
        prop_assert_eq!(dec, payload);
    }
}
