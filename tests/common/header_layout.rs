//! v2 symmetric header field byte offsets (177-byte layout).

/// Byte offsets of authenticated header fields.
pub mod offsets {
    pub const MAGIC: usize = 0;
    pub const PAYLOAD_NONCE: usize = 12;
    pub const HEADER_MAC: usize = 28;
    pub const HASH: usize = 92;
    pub const SLH_PUBLIC_KEY: usize = 124;
    pub const FORMAT: usize = 156;
    pub const CHUNK_INDEX: usize = 157;
    pub const ENCODED_LEN: usize = 161;
    pub const PADDING_LEN: usize = 165;
    pub const METADATA: usize = 169;
}

/// Flip one byte at `offset` (XOR 0x55) for tamper tests.
pub fn flip_byte(buf: &mut [u8], offset: usize) {
    buf[offset] ^= 0x55;
}
