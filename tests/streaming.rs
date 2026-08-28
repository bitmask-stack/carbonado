//! Streaming encode/decode roundtrip vs buffer path + multi-MiB smoke.

mod common;

use std::fs::File;
use std::io::{Cursor, Read, Write};

use carbonado::decode;
use carbonado::file::decode_stream;
use carbonado::stream::{
    decode::stream_decode_outboard,
    encode::{stream_encode_outboard, stream_encode_outboard_buffer},
    stream_decode_buffer, stream_decode_outboard_buffer,
};
use common::{encode, file_encode_stream, stream_encode_buffer};
use proptest::prelude::*;
use rand::RngCore;

const MASTER: [u8; 32] = [0x42; 32];

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        .. ProptestConfig::default()
    })]

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
        for &format in &[4u8, 6u8, 7u8, 12u8, 13u8, 14u8, 15u8] {
            let encrypted = format & 1 != 0;
            let has_bao = format & 4 != 0;
            let has_zfec = format & 8 != 0;
            let header_path = encrypted;

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
                has_bao.then_some(&mut bao_buf),
                has_zfec.then_some(&mut par_buf),
                &mut nonce,
                header_path,
                &carbonado::ZstdEncode::level(20),
            )?;

            let buf = stream_encode_outboard_buffer(
                &MASTER,
                &data,
                format,
                if encrypted { Some(nonce) } else { None },
                &carbonado::ZstdEncode::level(20),
            )?;

            prop_assert_eq!(hash, buf.hash);
            prop_assert_eq!(info.padding_len, buf.info.padding_len);
            let main_bytes = main_buf.into_inner();
            prop_assert_eq!(main_bytes.clone(), buf.main);
            if has_bao {
                prop_assert_eq!(
                    bao_buf.clone(),
                    buf.verification_outboard.clone().unwrap_or_default()
                );
            }
            if has_zfec {
                prop_assert_eq!(
                    par_buf.clone(),
                    buf.fec_parity.clone().unwrap_or_default()
                );
            }
            if encrypted {
                prop_assert_ne!(nonce, [0u8; 16]);
            }

            let mut out = Vec::new();
            stream_decode_outboard(
                &MASTER,
                hash.as_bytes(),
                Cursor::new(main_bytes),
                has_bao.then(|| Cursor::new(bao_buf)),
                has_zfec.then(|| Cursor::new(par_buf)),
                info.padding_len,
                format,
                if encrypted { Some(nonce) } else { None },
                &mut out,
            )?;
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
        &carbonado::ZstdEncode::level(20),
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
        &carbonado::ZstdEncode::level(20),
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
    let (header, _info) = file_encode_stream(&MASTER, &mut in_f, 14, None, &mut body_buf)
        .expect("file_encode_stream");

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

/// W1a smoke: codecode (encode→decode→encode) + decodec (decode→encode→decode) for public c14.
/// Full matrix lives in post-R10 W2d; this pins stream dual determinism for one format.
#[test]
fn decode_stream_codecode_decodec_public_c14() {
    const FORMAT: u8 = 14;
    let pt: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();

    let mut body = Vec::new();
    let (h1, _) = file_encode_stream(&MASTER, std::io::Cursor::new(&pt), FORMAT, None, &mut body)
        .expect("enc1");
    let mut a = h1.try_to_vec().expect("hdr");
    a.extend_from_slice(&body);

    let mut out = Vec::new();
    let (_h, n) = decode_stream(&MASTER, std::io::Cursor::new(&a), &mut out).expect("dec1");
    assert_eq!(n as usize, pt.len());
    assert_eq!(out, pt, "decode_stream plaintext");

    // codecode: re-encode must match wire when public (deterministic)
    let mut body2 = Vec::new();
    let (h2, _) = file_encode_stream(
        &MASTER,
        std::io::Cursor::new(&out),
        FORMAT,
        None,
        &mut body2,
    )
    .expect("enc2");
    let mut a2 = h2.try_to_vec().expect("hdr2");
    a2.extend_from_slice(&body2);
    assert_eq!(a2, a, "codecode: second encode must match first archive");

    // decodec: decode → encode → decode recovers plaintext; wire stable
    let mut out2 = Vec::new();
    decode_stream(&MASTER, std::io::Cursor::new(&a2), &mut out2).expect("dec2");
    assert_eq!(out2, pt, "decodec: plaintext roundtrip");
}

/// `file_encode_stream` / `decode_stream` format sweep (~64 KiB) vs buffer path.
#[test]
fn file_stream_format_sweep() {
    const PAYLOAD_LEN: usize = 64 * 1024;
    const PUBLIC_MASTER: [u8; 32] = [0u8; 32];

    let work = std::env::temp_dir().join(format!("carbonado-stream-sweep-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).expect("tmpdir");

    let input: Vec<u8> = (0..PAYLOAD_LEN).map(|i| (i % 251) as u8).collect();
    let input_path = work.join("input.bin");
    File::create(&input_path)
        .expect("create input")
        .write_all(&input)
        .expect("write input");

    let mut enc_master = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut enc_master);

    for &format in &[0u8, 4u8, 8u8, 12u8, 14u8, 15u8] {
        let master = if format & 1 != 0 {
            &enc_master
        } else {
            &PUBLIC_MASTER
        };

        let mut in_f = File::open(&input_path).expect("open input");
        let mut body_buf = Vec::new();
        let (header, _stream_info) =
            file_encode_stream(master, &mut in_f, format, None, &mut body_buf)
                .expect("file_encode_stream");

        let mut archive = header.try_to_vec().expect("header");
        archive.extend_from_slice(&body_buf);
        let archive_path = work.join(format!("archive-c{format}.c0e"));
        File::create(&archive_path)
            .expect("create archive")
            .write_all(&archive)
            .expect("write archive");

        let mut dec_in = File::open(&archive_path).expect("open archive");
        let out_path = work.join(format!("out-c{format}.bin"));
        let mut dec_out = File::create(&out_path).expect("create out");
        let (_hdr, stream_len) =
            decode_stream(master, &mut dec_in, &mut dec_out).expect("decode_stream");
        assert_eq!(stream_len, PAYLOAD_LEN as u64);

        let mut recovered = Vec::new();
        File::open(&out_path)
            .expect("open out")
            .read_to_end(&mut recovered)
            .expect("read out");
        assert_eq!(recovered, input, "decode_stream content for c{format}");

        let carbonado::structs::Encoded(verifiable, hash, buffer_info) =
            encode(master, &input, format).expect("buffer encode");

        let buffer_recovered = decode(
            master,
            hash.as_bytes(),
            &verifiable,
            buffer_info.padding_len,
            format,
        )
        .expect("buffer decode");
        assert_eq!(buffer_recovered, input, "buffer path content for c{format}");
        assert_eq!(
            recovered, buffer_recovered,
            "stream vs buffer for c{format}"
        );
    }
}

/// W1b: public **non-Compression** outboard stream (c4 Bao, c12 Bao+FEC) multi-MiB
/// codecode/decodec.
///
/// S4 O(chunk/stripe) pipeline. Wire must match the buffer path; public re-encode is deterministic.
///
/// **Peak RAM:** architectural O(chunk/stripe) claim (SeekableSpool / stripe FEC / leaf Bao);
/// not RSS-instrumented here (optional W4 measurement residual).
#[test]
fn stream_outboard_public_e2_codecode_decodec_c4_c12() {
    const PAYLOAD_LEN: usize = 2 * 1024 * 1024; // multi-MiB — exercises O(chunk) spool path
    let pt: Vec<u8> = (0..PAYLOAD_LEN).map(|i| (i % 251) as u8).collect();

    for &format in &[4u8, 12u8] {
        let has_bao = format & 4 != 0;
        let has_fec = format & 8 != 0;

        let mut main1 = Cursor::new(Vec::new());
        let mut bao1 = Vec::new();
        let mut par1 = Vec::new();
        let mut nonce = [0u8; 16];
        let (hash1, info1) = stream_encode_outboard(
            &MASTER,
            Cursor::new(&pt),
            format,
            &mut main1,
            has_bao.then_some(&mut bao1),
            has_fec.then_some(&mut par1),
            &mut nonce,
            false,
            &carbonado::ZstdEncode::level(20),
        )
        .expect("encode1");
        let main1_bytes = main1.into_inner();

        // Decode recovers plaintext
        let mut out = Vec::new();
        stream_decode_outboard(
            &MASTER,
            hash1.as_bytes(),
            Cursor::new(&main1_bytes),
            has_bao.then_some(Cursor::new(&bao1)),
            has_fec.then_some(Cursor::new(&par1)),
            info1.padding_len,
            format,
            None,
            &mut out,
        )
        .expect("decode1");
        assert_eq!(out, pt, "c{format} decode plaintext");

        // codecode: re-encode public must bit-match (deterministic)
        let mut main2 = Cursor::new(Vec::new());
        let mut bao2 = Vec::new();
        let mut par2 = Vec::new();
        let mut nonce2 = [0u8; 16];
        let (hash2, info2) = stream_encode_outboard(
            &MASTER,
            Cursor::new(&out),
            format,
            &mut main2,
            has_bao.then_some(&mut bao2),
            has_fec.then_some(&mut par2),
            &mut nonce2,
            false,
            &carbonado::ZstdEncode::level(20),
        )
        .expect("encode2");
        let main2_bytes = main2.into_inner();
        assert_eq!(hash2, hash1, "c{format} codecode hash");
        assert_eq!(main2_bytes, main1_bytes, "c{format} codecode main");
        if has_bao {
            assert_eq!(bao2, bao1, "c{format} codecode bao outboard");
        }
        if has_fec {
            assert_eq!(par2, par1, "c{format} codecode fec parity");
            assert_eq!(info2.padding_len, info1.padding_len);
        }

        // decodec: decode second wire → plaintext
        let mut out2 = Vec::new();
        stream_decode_outboard(
            &MASTER,
            hash2.as_bytes(),
            Cursor::new(&main2_bytes),
            has_bao.then_some(Cursor::new(&bao2)),
            has_fec.then_some(Cursor::new(&par2)),
            info2.padding_len,
            format,
            None,
            &mut out2,
        )
        .expect("decode2");
        assert_eq!(out2, pt, "c{format} decodec plaintext");

        // Match buffer path
        let buf = stream_encode_outboard_buffer(
            &MASTER,
            &pt,
            format,
            None,
            &carbonado::ZstdEncode::level(20),
        )
        .expect("buf encode");
        assert_eq!(buf.hash, hash1, "c{format} stream vs buffer hash");
        assert_eq!(buf.main, main1_bytes, "c{format} stream vs buffer main");
        let buf_dec = stream_decode_outboard_buffer(
            &MASTER,
            buf.hash.as_bytes(),
            &buf.main,
            buf.verification_outboard.as_deref(),
            buf.fec_parity.as_deref(),
            buf.info.padding_len,
            format,
            None,
        )
        .expect("buf decode");
        assert_eq!(buf_dec, pt, "c{format} buffer decode");
    }
}
