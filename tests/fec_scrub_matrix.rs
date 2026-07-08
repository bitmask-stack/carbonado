//! Scrub matrix: every Bao+Zfec format × inboard and outboard recovery paths.

mod common;

use anyhow::Result;
use carbonado::{
    decode, decode_outboard, encode, encode_outboard, error::CarbonadoError, scrub,
    scrub_outboard, structs::Encoded,
};
use common::corruption::{flip_byte, InboardShardLayout};
use common::format_matrix::{bao_zfec_levels, format_label, public_zfec_levels};
use rand::Rng;

fn master_for(level: u8) -> [u8; 32] {
    let mut key = [0u8; 32];
    if level & 1 != 0 {
        rand::thread_rng().fill(&mut key);
    }
    key
}

#[test]
fn inboard_scrub_matrix_light_and_distributed() -> Result<()> {
    let mut rng = rand::thread_rng();
    let payload: Vec<u8> = (0..16_384).map(|i| (i % 251) as u8).collect();

    for level in bao_zfec_levels() {
        let key = master_for(level);
        let Encoded(orig, hash, info) = encode(&key, &payload, level)?;
        let hash_bytes = hash.as_bytes();

        // Unnecessary scrub on pristine data.
        assert!(
            matches!(
                scrub(&orig, hash_bytes, &info, level),
                Err(CarbonadoError::UnnecessaryScrub)
            ),
            "{}",
            format_label(level)
        );

        // Single-byte flip (minimal corruption).
        let mut light = orig.clone();
        if light.len() > 64 {
            flip_byte(&mut light, 48, 0x5A);
        }
        let rec_light = scrub(&light, hash_bytes, &info, level)?;
        assert_eq!(rec_light, orig, "light scrub {}", format_label(level));

        // Distributed knockout within 4-shard budget.
        let layout = InboardShardLayout::from_encode_info(orig.len(), info.chunk_len);
        let mut chaos = orig.clone();
        common::corruption::scattered_stream_knockout(&mut chaos, &layout, 24, 4, &mut rng);
        let rec_chaos = scrub(&chaos, hash_bytes, &info, level)?;
        assert_eq!(rec_chaos, orig, "chaos scrub {}", format_label(level));

        let dec = decode(&key, hash_bytes, &rec_chaos, info.padding_len, level)?;
        assert_eq!(dec, payload);
    }
    Ok(())
}

#[test]
fn outboard_scrub_matrix_c12_c14_c15() -> Result<()> {
    let payload: Vec<u8> = (0..32_768).map(|i| (i % 251) as u8).collect();

    for level in [12u8, 14, 15] {
        let key = master_for(level);
        let oenc = encode_outboard(&key, &payload, level)?;
        let hash_bytes = oenc.hash.as_bytes();
        let ob = oenc.bao_outboard.as_deref();
        let par = oenc.fec_parity.as_deref();

        assert!(matches!(
            scrub_outboard(&oenc.main, ob, par, &oenc.info, level, hash_bytes),
            Err(CarbonadoError::UnnecessaryScrub)
        ));

        let mut bad = oenc.main.clone();
        if bad.len() > 32 {
            flip_byte(&mut bad, 24, 0xAB);
        }
        let recovered = scrub_outboard(&bad, ob, par, &oenc.info, level, hash_bytes)?;
        assert_eq!(recovered, oenc.main);

        let dec = decode_outboard(
            &key,
            hash_bytes,
            &recovered,
            ob,
            par,
            oenc.info.padding_len,
            level,
        )?;
        assert_eq!(dec, payload);
    }
    Ok(())
}

#[test]
fn zfec_without_bao_returns_scrub_requires_bao() -> Result<()> {
    let payload = b"zfec only";
    for level in public_zfec_levels().filter(|l| l & 4 == 0) {
        let Encoded(encoded, hash, info) = encode(&[0u8; 32], payload, level)?;
        let err = scrub(&encoded, hash.as_bytes(), &info, level).unwrap_err();
        assert!(
            matches!(err, CarbonadoError::ScrubRequiresBao),
            "level {} must require bao for scrub",
            format_label(level)
        );
    }
    Ok(())
}