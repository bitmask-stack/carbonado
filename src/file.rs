use std::{
    convert::TryFrom,
    fs::File,
    io::{Read, Seek},
};

use bao::Hash;
// nom imports removed — legacy parse_bytes / old header parsing was deleted as part of the v2 replacement.
// (secp256k1 imports removed - clean break, legacy Header parsing deleted)

use crate::{
    constants::{Format, MAGICNO},
    decoding, encoding,
    error::CarbonadoError,
    structs::EncodeInfo,
    utils::{decode_bao_hash, encode_bao_hash},
};

/// Header for the v2 symmetric format (AES-256-CTR + full HMAC-SHA512).
///
/// **Important security property**: The Header is **never encrypted**. It is public but
/// authenticated metadata (protected by `header_mac`). No secret key material (master key
/// or any derived subkeys) ever appears in the Header. See AGENTS.md §"Header Visibility
/// and Confidentiality Model" for the full normative rules.
///
/// The `payload_nonce` field is the AES-CTR nonce for this archive. Like all CTR/GCM-style
/// nonces/IVs, it is not secret; it must simply be unique per (master_key, operation).
///
/// The old ECIES + secp256k1 + Schnorr header was removed as part of the clean cryptographic break.
/// Old v1 files are not supported for reading.
#[derive(Clone, Debug)]
pub struct Header {
    /// 16-byte nonce used for the payload AES-CTR (carried in the header for v2).
    pub payload_nonce: [u8; 16],
    /// 64-byte HMAC-SHA512 header authentication tag (derived subkey).
    pub header_mac: [u8; 64],
    /// Bao hash (32 bytes).
    pub hash: Hash,
    /// 32-byte SLH-DSA public key for the sidecar signature (if any).
    /// Zeroed when no post-quantum signature is associated with this segment.
    pub slh_public_key: [u8; 32],
    /// Format bitmask.
    pub format: Format,
    /// Chunk index (now u32 to support enormous multi-chunk archives).
    pub chunk_index: u32,
    /// Number of verifiable bytes after encoding.
    pub encoded_len: u32,
    /// Padding for FEC/bao alignment.
    pub padding_len: u32,
    /// Optional metadata (8 bytes).
    pub metadata: Option<[u8; 8]>,
}

impl TryFrom<&File> for Header {
    type Error = CarbonadoError;

    /// Attempts to decode a header from a file.
    /// Legacy v1 parsing removed as part of clean break.
    fn try_from(mut file: &File) -> Result<Self, CarbonadoError> {
        let mut magic_no = [0_u8; 12];
        file.rewind()?;
        let mut handle = file.take(12);
        handle.read_exact(&mut magic_no)?;

        if &magic_no != MAGICNO {
            return Err(CarbonadoError::InvalidMagicNumber(format!("{magic_no:#?}")));
        }

        Err(CarbonadoError::InvalidMagicNumber(
            "Legacy file-based Header parsing has been removed. This library only supports the new v2 symmetric header format.".to_string()
        ))
    }
}

impl TryFrom<&[u8]> for Header {
    type Error = CarbonadoError;

    /// Parses a v2 symmetric header.
    fn try_from(bytes: &[u8]) -> Result<Self, CarbonadoError> {
        if bytes.len() < Header::LEN {
            return Err(CarbonadoError::InvalidHeaderLength);
        }

        let magic_no = &bytes[0..12];
        if magic_no != MAGICNO {
            return Err(CarbonadoError::InvalidMagicNumber(format!("{magic_no:#?}")));
        }

        let payload_nonce: [u8; 16] = bytes[12..28]
            .try_into()
            .map_err(|_| CarbonadoError::InvalidHeaderLength)?;
        let header_mac: [u8; 64] = bytes[28..92]
            .try_into()
            .map_err(|_| CarbonadoError::InvalidHeaderLength)?;
        let hash_bytes = &bytes[92..124];
        let slh_public_key: [u8; 32] = bytes[124..156]
            .try_into()
            .map_err(|_| CarbonadoError::InvalidHeaderLength)?;
        let format = Format::from(bytes[156]);
        let chunk_index = u32::from_le_bytes(
            bytes[157..161]
                .try_into()
                .map_err(|_| CarbonadoError::InvalidHeaderLength)?,
        );
        let encoded_len = u32::from_le_bytes(
            bytes[161..165]
                .try_into()
                .map_err(|_| CarbonadoError::InvalidHeaderLength)?,
        );
        let padding_len = u32::from_le_bytes(
            bytes[165..169]
                .try_into()
                .map_err(|_| CarbonadoError::InvalidHeaderLength)?,
        );
        let metadata_bytes = &bytes[169..177];
        let metadata = if metadata_bytes.iter().any(|&b| b != 0) {
            Some(
                metadata_bytes
                    .try_into()
                    .map_err(|_| CarbonadoError::InvalidHeaderLength)?,
            )
        } else {
            None
        };

        let hash = decode_bao_hash(hash_bytes)?;

        // Note: header_mac verification is done at a higher level (file::decode) with the key.
        Ok(Header {
            payload_nonce,
            header_mac,
            hash,
            slh_public_key,
            format,
            chunk_index,
            encoded_len,
            padding_len,
            metadata,
        })
    }
}

impl Header {
    /// Length of a v2 symmetric header.
    ///
    /// Layout: MAGIC(12) + payload_nonce(16) + header_mac(64) + hash(32) +
    ///         slh_public_key(32) + format(1) + chunk_index(4) + encoded_len(4) +
    ///         padding_len(4) + metadata(8) = 177 bytes.
    pub const LEN: usize = 12 + 16 + 64 + 32 + 32 + 1 + 4 + 4 + 4 + 8;

    /// Creates a new v2 Header using a symmetric master key.
    ///
    /// `slh_public_key` should be the 32-byte raw SLH-DSA public key when a sidecar
    /// signature will later be produced over this archive's Bao hash. Pass `[0u8; 32]`
    /// when no post-quantum signature is associated with this segment.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        master_key: &[u8],
        payload_nonce: [u8; 16],
        hash: &[u8],
        slh_public_key: [u8; 32],
        format: Format,
        chunk_index: u32,
        encoded_len: u32,
        padding_len: u32,
        metadata: Option<[u8; 8]>,
    ) -> Result<Self, CarbonadoError> {
        let hash = decode_bao_hash(hash)?;

        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(crate::constants::MAGICNO);
        auth_data.extend_from_slice(&payload_nonce);
        auth_data.extend_from_slice(hash.as_bytes());
        auth_data.extend_from_slice(&slh_public_key);
        auth_data.push(format.bits());
        auth_data.extend_from_slice(&chunk_index.to_le_bytes());
        auth_data.extend_from_slice(&encoded_len.to_le_bytes());
        auth_data.extend_from_slice(&padding_len.to_le_bytes());
        auth_data.extend_from_slice(&metadata.unwrap_or([0u8; 8]));

        let header_mac = crate::crypto::compute_header_mac(master_key, &auth_data)?;

        Ok(Header {
            payload_nonce,
            header_mac,
            hash,
            slh_public_key,
            format,
            chunk_index,
            encoded_len,
            padding_len,
            metadata,
        })
    }

    /// Creates a v2 header to be prepended to files.
    pub fn try_to_vec(&self) -> Result<Vec<u8>, CarbonadoError> {
        let mut out = Vec::with_capacity(Header::LEN);
        out.extend_from_slice(crate::constants::MAGICNO);
        out.extend_from_slice(&self.payload_nonce);
        out.extend_from_slice(&self.header_mac);
        out.extend_from_slice(self.hash.as_bytes());
        out.extend_from_slice(&self.slh_public_key);
        out.push(self.format.bits());
        out.extend_from_slice(&self.chunk_index.to_le_bytes());
        out.extend_from_slice(&self.encoded_len.to_le_bytes());
        out.extend_from_slice(&self.padding_len.to_le_bytes());
        out.extend_from_slice(&self.metadata.unwrap_or([0u8; 8]));
        Ok(out)
    }

    /// Helper function for naming a Carbonado archive file.
    pub fn file_name(&self) -> String {
        let hash = encode_bao_hash(&self.hash);
        let fmt = self.format.bits();
        format!("{hash}.c{fmt}")
    }
}

pub fn decode(master_key: &[u8], encoded: &[u8]) -> Result<(Header, Vec<u8>), CarbonadoError> {
    let (header_bytes, body) = encoded.split_at(Header::LEN);
    let header = Header::try_from(header_bytes)?;

    // Verify header_mac
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(crate::constants::MAGICNO);
    auth_data.extend_from_slice(&header.payload_nonce);
    auth_data.extend_from_slice(header.hash.as_bytes());
    auth_data.extend_from_slice(&header.slh_public_key);
    auth_data.push(header.format.bits());
    auth_data.extend_from_slice(&header.chunk_index.to_le_bytes());
    auth_data.extend_from_slice(&header.encoded_len.to_le_bytes());
    auth_data.extend_from_slice(&header.padding_len.to_le_bytes());
    auth_data.extend_from_slice(&header.metadata.unwrap_or([0u8; 8]));

    let expected_mac = crate::crypto::compute_header_mac(master_key, &auth_data)?;

    // Constant-time comparison for the header MAC to avoid timing side-channels.
    // (See AGENTS.md for the constant-time review of EtM + header auth paths.)
    if !crate::crypto::ct_eq(&expected_mac, &header.header_mac) {
        return Err(CarbonadoError::AuthenticationFailed);
    }

    let decoded = decoding::decode(
        master_key,
        header.hash.as_bytes(),
        body,
        header.padding_len,
        header.format.into(),
    )?;

    Ok((header, decoded))
}

/// High-level encode using the new v2 symmetric model.
pub fn encode(
    master_key: &[u8],
    input: &[u8],
    level: u8,
    metadata: Option<[u8; 8]>,
) -> Result<(Vec<u8>, EncodeInfo), CarbonadoError> {
    let format = Format::from(level);
    let input_len = input.len() as u32;

    let mut data = input.to_vec();
    let mut bytes_compressed = 0u32;

    if format.contains(Format::Snappy) {
        data = encoding::compress(&data)?;
        bytes_compressed = data.len() as u32;
    }

    let mut payload_nonce = [0u8; 16];
    let mut bytes_encrypted = 0u32;

    let encrypted = if format.contains(Format::Encrypted) {
        getrandom::getrandom(&mut payload_nonce).map_err(|_| CarbonadoError::RandomnessError)?;
        let enc = crate::crypto::symmetric_encrypt_with_nonce(master_key, payload_nonce, &data)?;
        bytes_encrypted = enc.len() as u32;
        enc
    } else {
        data
    };

    // zfec + bao
    let (after_zfec, padding_len, chunk_len) = if format.contains(Format::Zfec) {
        encoding::zfec(&encrypted)?
    } else {
        (encrypted, 0u32, 0u32)
    };

    let bytes_ecc = after_zfec.len() as u32;
    let verifiable_slice_count = if format.contains(Format::Zfec) {
        bytes_ecc / crate::constants::SLICE_LEN as u32
    } else {
        0
    };
    let chunk_slice_count = verifiable_slice_count / 8; // 8 = total FEC shards (FEC_M)

    let (verifiable, hash) = if format.contains(Format::Bao) {
        encoding::bao(&after_zfec, format.bits())?
    } else {
        (after_zfec, bao::Hash::from([0u8; 32]))
    };

    let bytes_verifiable = verifiable.len() as u32;
    let output_len = bytes_verifiable;

    let header = Header::new(
        master_key,
        payload_nonce,
        hash.as_bytes(),
        [0u8; 32], // slh_public_key — populated by caller when producing a sidecar signature
        format,
        0u32,
        output_len,
        padding_len,
        metadata,
    )?;

    let mut body = header.try_to_vec()?;
    body.extend_from_slice(&verifiable);

    let compression_factor = if bytes_compressed > 0 {
        bytes_compressed as f32 / input_len as f32
    } else {
        0.0
    };
    let amplification_factor = bytes_verifiable as f32 / input_len as f32;

    let encode_info = EncodeInfo {
        input_len,
        output_len,
        bytes_compressed,
        bytes_encrypted,
        bytes_ecc,
        bytes_verifiable,
        compression_factor,
        amplification_factor,
        padding_len,
        chunk_len,
        verifiable_slice_count,
        chunk_slice_count,
    };

    Ok((body, encode_info))
}
