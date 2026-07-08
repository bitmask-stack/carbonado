//! Streaming encode/decode roundtrip vs buffer path + multi-MiB smoke.

use std::fs::File;
use std::io::{Cursor, Write};

use carbonado::encode;
use carbonado::file::{decode_stream, encode_stream};
use carbonado::stream::{
    decode::stream_decode_outboard,
    encode::{stream_encode_buffer, stream_encode_outboard, stream_encode_outboard_buffer},
    stream_decode_buffer,
};
use proptest::prelude::*;

const MASTER: [u8; 32] = [0x42; 32];

proptest! {
    #[test]
    fn stream_buffer_roundtrip_matches(data in prop::collection::vec(any::<u8>(), 0..32_768), format in 0u8..=15u8) {
        let (b1, h1, i1) = stream_encode_buffer(&MASTER, &data, format)?;
        let dec = stream_decode_buffer(&MASTER, h1.as_bytes(), &b1, i1.padding_len, format)?;
        prop_assert_eq!(dec, data);
    }

    #[test]
    fn stream_outboard_buffer_matches_stream_encode(
        data in prop::collection::vec(any::<u8>(), 0..16_384),
    ) {
        for &format in &[4u8, 12u8, 14u8] {
            let buf = stream_encode_outboard_buffer(&MASTER, &data, format, None)?;
            let data = data.clone();

            let mut main_buf = Cursor::new(Vec::new());
            let mut bao_buf = Vec::new();
            let mut par_buf = Vec::new();
            let mut nonce = [0u8; 16];
            let (hash, info) = stream_encode_outboard(
                &MASTER,
                Cursor::new(&data),
                format,
                &mut main_buf,
                Some(&mut bao_buf),
                Some(&mut par_buf),
                &mut nonce,
                false,
            )
            .expect("stream encode");

            prop_assert_eq!(hash, buf.hash);
            prop_assert_eq!(info.padding_len, buf.info.padding_len);

            let mut out = Vec::new();
            stream_decode_outboard(
                &MASTER,
                hash.as_bytes(),
                Cursor::new(main_buf.into_inner()),
                Some(Cursor::new(bao_buf)),
                Some(Cursor::new(par_buf)),
                info.padding_len,
                format,
                None,
                &mut out,
            )
            .expect("stream decode");
            prop_assert_eq!(out, data);
        }
    }
}

#[test]
fn stream_outboard_empty_zfec_roundtrip() {
    let mut main_buf = Cursor::new(Vec::new());
    let mut bao_buf = Vec::new();
    let mut par_buf = Vec::new();
    let mut nonce = [0u8; 16];
    let (hash, info) = stream_encode_outboard(
        &MASTER,
        Cursor::new(&[] as &[u8]),
        12,
        &mut main_buf,
        Some(&mut bao_buf),
        Some(&mut par_buf),
        &mut nonce,
        false,
    )
    .expect("empty encode");

    assert!(main_buf.get_ref().is_empty());
    assert_eq!(info.padding_len, 0);

    let mut out = Vec::new();
    stream_decode_outboard(
        &MASTER,
        hash.as_bytes(),
        Cursor::new(main_buf.into_inner()),
        Some(Cursor::new(bao_buf)),
        Some(Cursor::new(par_buf)),
        0,
        12,
        None,
        &mut out,
    )
    .expect("empty decode");
    assert!(out.is_empty());
}

#[test]
fn stream_outboard_encrypted_header_nonce_roundtrip() {
    let data = b"encrypted stream outboard header-path nonce test";
    let mut main_buf = Cursor::new(Vec::new());
    let mut bao_buf = Vec::new();
    let mut nonce = [0u8; 16];
    let (hash, info) = stream_encode_outboard(
        &MASTER,
        Cursor::new(&data[..]),
        5,
        &mut main_buf,
        Some(&mut bao_buf),
        None::<&mut Vec<u8>>,
        &mut nonce,
        true,
    )
    .expect("enc encode");
    assert_ne!(nonce, [0u8; 16]);

    let mut out = Vec::new();
    stream_decode_outboard(
        &MASTER,
        hash.as_bytes(),
        Cursor::new(main_buf.into_inner()),
        Some(Cursor::new(bao_buf)),
        None::<Cursor<Vec<u8>>>,
        info.padding_len,
        5,
        Some(nonce),
        &mut out,
    )
    .expect("enc decode");
    assert_eq!(out, data);
}

#[test]
fn multi_mib_file_stream_smoke() {
    let work =
        std::env::temp_dir().join(format!("carbonado-streaming-smoke-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).expect("tmpdir");

    let input_path = work.join("big.bin");
    let mut input_f = File::create(&input_path).expect("create input");
    let chunk = vec![0xABu8; 64 * 1024];
    for _ in 0..64 {
        input_f.write_all(&chunk).expect("write chunk");
    }
    drop(input_f);

    let mut in_f = File::open(&input_path).expect("open input");
    let mut body_buf = Vec::new();
    let (header, _info) =
        encode_stream(&MASTER, &mut in_f, 14, None, &mut body_buf).expect("encode_stream");

    let mut archive = header.try_to_vec().expect("header");
    archive.extend_from_slice(&body_buf);

    let archive_path = work.join("archive.c0e");
    File::create(&archive_path)
        .expect("create archive")
        .write_all(&archive)
        .expect("write archive");

    let mut dec_in = File::open(&archive_path).expect("open archive");
    let out_path = work.join("out.bin");
    let mut dec_out = File::create(&out_path).expect("create out");
    let (_h, n) = decode_stream(&MASTER, &mut dec_in, &mut dec_out).expect("decode_stream");
    assert_eq!(n, 4 * 1024 * 1024);

    let (_hdr, recovered) = carbonado::file::decode(&MASTER, &archive).expect("decode");
    assert_eq!(recovered.len(), 4 * 1024 * 1024);

    let carbonado::structs::Encoded(verifiable, hash, info) = encode(
        &MASTER,
        &std::fs::read(&input_path).expect("read input"),
        14,
    )
    .expect("buffer encode");
    let buffer_recovered =
        carbonado::decode(&MASTER, hash.as_bytes(), &verifiable, info.padding_len, 14)
            .expect("buffer decode");
    assert_eq!(recovered, buffer_recovered);
}
