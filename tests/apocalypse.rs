use std::fs::read;

use anyhow::Result;
use carbonado::{encode, scrub, structs::Encoded};
use log::{debug, info};
use rand::RngCore;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

#[test]
fn contract() -> Result<()> {
    let _ = pretty_env_logger::try_init();

    act_of_god("tests/samples/contract.rgbc")?;

    Ok(())
}

#[ignore]
#[test]
fn content() -> Result<()> {
    let _ = pretty_env_logger::try_init();

    act_of_god("tests/samples/content.png")?;

    Ok(())
}

#[ignore]
#[test]
fn code() -> Result<()> {
    let _ = pretty_env_logger::try_init();

    act_of_god("tests/samples/code.tar")?;

    Ok(())
}

#[wasm_bindgen_test]
fn wasm_contract() -> Result<()> {
    let _ = pretty_env_logger::try_init();

    act_of_god("tests/samples/contract.rgbc")?;

    Ok(())
}

#[wasm_bindgen_test]
fn wasm_content() -> Result<()> {
    let _ = pretty_env_logger::try_init();

    act_of_god("tests/samples/content.png")?;

    Ok(())
}

#[wasm_bindgen_test]
fn wasm_code() -> Result<()> {
    let _ = pretty_env_logger::try_init();

    act_of_god("tests/samples/code.tar")?;

    Ok(())
}

fn act_of_god(path: &str) -> Result<()> {
    let input = read(path)?;

    // Use a random 32-byte symmetric master key (new v2 crypto model)
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);

    info!("Encoding {path}...");
    let Encoded(orig_encoded, hash, encode_info) = encode(&key, &input, 12)?;
    debug!("Encoding Info: {encode_info:#?}");
    let _new_encoded = orig_encoded.clone();

    info!("Scrubbing stream against hash: {hash}...");
    // Pass the exact format used for this bao (level 12 = Bao+Zfec) so keyed paths in
    // scrub use correct derive_key (addresses multi-dim keyed roots).
    let orig_result = scrub(&orig_encoded, hash.as_bytes(), &encode_info, 12);
    assert!(
        orig_result.is_err(),
        "Return error when there's no need to scrub"
    );

    // Scrub recovery e2e exercise (now deterministic + robust RS search).
    // Verifies end-to-end: flip in response, scrub via verify_slice + RS subset,
    // re-bao with format, hash+len match.
    let mut flipped = orig_encoded.clone();
    if flipped.len() > 200 {
        flipped[200] ^= 0x55; // flip (often parent area, but search handles data taints too)
    }
    let recovered = scrub(&flipped, hash.as_bytes(), &encode_info, 12).expect("scrub must recover");
    assert_eq!(
        recovered, orig_encoded,
        "scrub recovered identical verifiable"
    );

    // Additional distributed taint for small/medium (contract)
    if flipped.len() > 500 {
        flipped[300] = 0;
        flipped[450] = 0;
    }
    let rec =
        scrub(&flipped, hash.as_bytes(), &encode_info, 12).expect("scrub must recover distributed");
    assert_eq!(rec, orig_encoded);

    let _ = orig_encoded; // baseline already asserted via encodes
    info!("All good!");

    Ok(())
}
