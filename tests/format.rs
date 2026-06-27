use std::{fs::OpenOptions, io::Write, path::PathBuf};

use anyhow::Result;
use carbonado::{constants::Format, decode, encode, file::Header, structs::Encoded};
use log::{debug, info, trace};
use rand::RngCore;
use wasm_bindgen_test::wasm_bindgen_test_configure;

wasm_bindgen_test_configure!(run_in_browser);

#[test]
fn format() -> Result<()> {
    let _ = pretty_env_logger::try_init();

    let input = "Hello world!".as_bytes();
    let carbonado_level = 15;
    let format = Format::from(carbonado_level);

    // Simple random 32-byte symmetric master key.
    // Key agreement (ECDH or otherwise) is an application-layer concern and is no
    // longer demonstrated here. Carbonado assumes you already have a master key.
    // There is no direct equivalent for SLH-DSA (which is a signature scheme only).
    let mut master = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut master);

    info!("Encoding input: {input:?}...");

    let Encoded(encoded, hash, encode_info) = encode(&master, input, carbonado_level)?;

    debug!("Encoding Info: {encode_info:#?}");

    // For v2 header we need a payload nonce (the one used for AES-CTR of this segment)
    let mut payload_nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut payload_nonce);

    let header = Header::new(
        &master,
        payload_nonce,
        hash.as_bytes(),
        [0u8; 32],
        format,
        0u32,
        encode_info.bytes_verifiable,
        encode_info.padding_len,
        None,
    )?;
    trace!("Header: {header:#?}");

    let header_bytes = header.try_to_vec()?;

    let file_path = PathBuf::from("/tmp").join(header.file_name());
    info!("Writing test file to: {file_path:?}");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&file_path)?;
    file.write_all(&header_bytes)?;
    file.write_all(&encoded)?;
    info!("Test file successfully written.");

    info!("Parsing file headers...");
    // Use the v2-aware slice parser (the file-based legacy TryFrom was removed in the clean break)
    let mut file_for_parse = std::fs::File::open(&file_path)?;
    let mut file_bytes = Vec::new();
    std::io::Read::read_to_end(&mut file_for_parse, &mut file_bytes)?;
    let header = Header::try_from(&file_bytes[..])?;

    // v2 Header no longer stores the signer pubkey (symmetric model)
    assert_eq!(header.hash, hash);
    assert_eq!(header.format, format);
    assert_eq!(header.chunk_index, 0);
    assert_eq!(header.padding_len, encode_info.padding_len);

    info!("Decoding Carbonado bytes");
    let decoded = decode(
        &master,
        hash.as_bytes(),
        &encoded,
        encode_info.padding_len,
        carbonado_level,
    )?;

    assert_eq!(decoded, input, "Decoded output is same as encoded input");

    info!("All good!");

    Ok(())
}
