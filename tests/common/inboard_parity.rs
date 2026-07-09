//! Shared inboard encode parity helpers (buffer vs `stream_encode_inboard_body`).

use std::io::{Cursor, Read, Seek, SeekFrom};

use bao::Hash;
use carbonado::constants::Format;
use carbonado::file::Header;
use carbonado::stream::encode::{stream_encode_inboard_body, PreprocessStats};
use carbonado::stream::{stream_decode_buffer, stream_encode_buffer, stream_preprocess};
use carbonado::structs::EncodeInfo;

/// Reader that caps each `read` to `max_chunk` bytes.
pub struct BoundedReadSeek {
    data: Vec<u8>,
    pos: u64,
    max_chunk: usize,
}

impl BoundedReadSeek {
    pub fn new(data: Vec<u8>, max_chunk: usize) -> Self {
        Self {
            data,
            pos: 0,
            max_chunk,
        }
    }
}

impl Read for BoundedReadSeek {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.data.len() as u64 {
            return Ok(0);
        }
        let remain = self.data.len() as u64 - self.pos;
        let n = buf.len().min(self.max_chunk).min(remain as usize);
        let start = self.pos as usize;
        buf[..n].copy_from_slice(&self.data[start..start + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

/// Async reader that caps each `poll_read` to `max_chunk` bytes (mirror of [`BoundedReadSeek`]).
#[cfg(feature = "async")]
pub struct BoundedAsyncRead {
    data: Vec<u8>,
    pos: u64,
    max_chunk: usize,
}

#[cfg(feature = "async")]
impl BoundedAsyncRead {
    pub fn new(data: Vec<u8>, max_chunk: usize) -> Self {
        Self {
            data,
            pos: 0,
            max_chunk,
        }
    }
}

#[cfg(feature = "async")]
impl futures_lite::AsyncRead for BoundedAsyncRead {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if this.pos >= this.data.len() as u64 {
            return std::task::Poll::Ready(Ok(0));
        }
        let remain = this.data.len() as u64 - this.pos;
        let n = buf.len().min(this.max_chunk).min(remain as usize);
        let start = this.pos as usize;
        buf[..n].copy_from_slice(&this.data[start..start + n]);
        this.pos += n as u64;
        std::task::Poll::Ready(Ok(n))
    }
}

impl Seek for BoundedReadSeek {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(off) => off,
            SeekFrom::End(off) => {
                if off >= 0 {
                    self.data.len() as u64 + off as u64
                } else {
                    self.data.len() as u64 - (-off) as u64
                }
            }
            SeekFrom::Current(off) => {
                if off >= 0 {
                    self.pos + off as u64
                } else {
                    self.pos - (-off) as u64
                }
            }
        };
        if new_pos > self.data.len() as u64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek past end",
            ));
        }
        self.pos = new_pos;
        Ok(self.pos)
    }
}

pub fn preprocess_and_body(
    master: &[u8; 32],
    format: u8,
    input: &[u8],
) -> (PreprocessStats, Vec<u8>, [u8; 16]) {
    let mut staging = Cursor::new(Vec::new());
    let mut nonce = [0u8; 16];
    let stats = stream_preprocess(
        master,
        Format::from(format),
        Cursor::new(input),
        &mut staging,
        &mut nonce,
        true,
    )
    .expect("preprocess");
    (stats, staging.into_inner(), nonce)
}

fn decode_inboard_body_header_path(
    master: &[u8; 32],
    nonce: [u8; 16],
    hash: &bao::Hash,
    body: &[u8],
    padding: u32,
    format: u8,
    output_len: u32,
) -> Vec<u8> {
    let header = Header::new(
        master,
        nonce,
        hash.as_bytes(),
        [0u8; 32],
        Format::from(format),
        0,
        output_len,
        padding,
        None,
    )
    .expect("test header");
    let mut archive = header.try_to_vec().expect("header bytes");
    archive.extend_from_slice(body);
    carbonado::file::decode(master, &archive)
        .expect("header-path file decode")
        .1
}

fn stream_encode_from_preprocess(
    master: &[u8; 32],
    format: u8,
    input: &[u8],
) -> (
    Vec<u8>,
    bao::Hash,
    EncodeInfo,
    PreprocessStats,
    Vec<u8>,
    [u8; 16],
) {
    let (stats, body, nonce) = preprocess_and_body(master, format, input);
    let mut stream_body = Vec::new();
    let (stream_hash, stream_info) =
        stream_encode_inboard_body(Cursor::new(&body), stats, format, &mut stream_body)
            .expect("stream inboard body");
    (stream_body, stream_hash, stream_info, stats, body, nonce)
}

/// Assert stream inboard body matches buffer encode and roundtrips via `stream_decode_buffer`.
///
/// Encrypted header-path formats (c15 via `encode_stream` / sharding) use `[tag|ct]` with
/// nonce in the header; [`stream_encode_buffer`] embeds the nonce — buffer byte parity is
/// only asserted for non-encrypted formats. Encrypted formats assert deterministic
/// re-encode from the same preprocess staging plus decode roundtrip.
pub fn assert_inboard_body_roundtrip(master: &[u8; 32], format: u8, input: &[u8]) {
    let (stream_body, stream_hash, stream_info, stats, body, nonce) =
        stream_encode_from_preprocess(master, format, input);

    if format & 1 == 0 {
        let (buf_body, buf_hash, buf_info) =
            stream_encode_buffer(master, input, format).expect("buffer encode");
        assert_eq!(stream_body, buf_body, "body bytes must match for c{format}");
        assert_eq!(stream_hash, buf_hash, "bao hash must match for c{format}");
        assert_eq!(stream_info, buf_info, "EncodeInfo must match for c{format}");
    } else {
        let mut reencode_body = Vec::new();
        let (re_hash, re_info) =
            stream_encode_inboard_body(Cursor::new(&body), stats, format, &mut reencode_body)
                .expect("re-encode from same preprocess staging");
        assert_eq!(
            stream_body, reencode_body,
            "deterministic re-encode for c{format}"
        );
        assert_eq!(stream_hash, re_hash, "hash stable for c{format}");
        assert_eq!(stream_info, re_info, "EncodeInfo stable for c{format}");
    }

    let decoded = if format & 1 != 0 {
        decode_inboard_body_header_path(
            master,
            nonce,
            &stream_hash,
            &stream_body,
            stream_info.padding_len,
            format,
            stream_info.output_len,
        )
    } else {
        stream_decode_buffer(
            master,
            stream_hash.as_bytes(),
            &stream_body,
            stream_info.padding_len,
            format,
        )
        .expect("decode roundtrip")
    };
    assert_eq!(decoded, input, "decode roundtrip for c{format}");
}

/// Bounded-read variant of [`assert_inboard_body_roundtrip`].
pub fn assert_bounded_inboard_body_roundtrip(
    master: &[u8; 32],
    format: u8,
    input: &[u8],
    max_chunk: usize,
) {
    let (ref_body, ref_hash, ref_info, stats, body, nonce) =
        stream_encode_from_preprocess(master, format, input);
    let preprocess = PreprocessStats {
        bare_len: stats.bare_len,
        input_len: stats.input_len,
        bytes_compressed: stats.bytes_compressed,
    };

    let mut stream_body = Vec::new();
    let (stream_hash, stream_info) = stream_encode_inboard_body(
        BoundedReadSeek::new(body, max_chunk),
        preprocess,
        format,
        &mut stream_body,
    )
    .expect("bounded-read inboard encode");

    if format & 1 == 0 {
        let (buf_body, buf_hash, buf_info) =
            stream_encode_buffer(master, input, format).expect("buffer encode");
        assert_eq!(stream_body, buf_body, "c{format}");
        assert_eq!(stream_hash, buf_hash, "c{format}");
        assert_eq!(stream_info, buf_info, "c{format}");
    } else {
        assert_eq!(
            stream_body, ref_body,
            "bounded vs cursor re-encode c{format}"
        );
        assert_eq!(stream_hash, ref_hash, "c{format}");
        assert_eq!(stream_info, ref_info, "c{format}");
    }

    let decoded = if format & 1 != 0 {
        decode_inboard_body_header_path(
            master,
            nonce,
            &stream_hash,
            &stream_body,
            stream_info.padding_len,
            format,
            stream_info.output_len,
        )
    } else {
        stream_decode_buffer(
            master,
            stream_hash.as_bytes(),
            &stream_body,
            stream_info.padding_len,
            format,
        )
        .expect("bounded-read decode roundtrip")
    };
    assert_eq!(decoded, input, "bounded-read decode for c{format}");
}

/// Assert a shard segment body matches buffer encode for the same plaintext slice.
pub fn assert_segment_matches_buffer_encode(
    master: &[u8; 32],
    format: u8,
    segment: &[u8],
    body: &[u8],
    hash: &Hash,
    info: &EncodeInfo,
) {
    let (buf_body, buf_hash, buf_info) =
        stream_encode_buffer(master, segment, format).expect("buffer encode segment");
    assert_eq!(body, buf_body, "shard body vs buffer for c{format}");
    assert_eq!(hash, &buf_hash, "shard hash vs buffer for c{format}");
    assert_eq!(info, &buf_info, "shard EncodeInfo vs buffer for c{format}");
}
