use std::{
    convert::TryFrom,
    fs::{self, File},
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
};

use bao::Hash;
// nom imports removed — legacy parse_bytes / old header parsing was deleted as part of the v2 replacement.
// (secp256k1 imports removed - clean break, legacy Header parsing deleted)

use crate::{
    adamantine::{
        decode_adamantine, encode_adamantine, AdamantineHeader, ADAMANTINE_CARBONADO_FMT_ENCRYPTED,
        ADAMANTINE_CARBONADO_FMT_PUBLIC, ADAMANTINE_FLAG_REQUIRE_OTS, ADAMANTINE_HEADER_LEN,
    },
    adamantine_payload::{
        bao_slice_from_bundle, build_adamantine_payload, split_adamantine_payload,
        MAX_ADAMANTINE_PAYLOAD_LEN, MAX_BAO_BUNDLE_LEN,
    },
    constants::{Format, MAGICNO},
    decoding,
    directory::{format_policy::resolve_catalog_format, SegmentFormatPolicy},
    encoding,
    error::CarbonadoError,
    filepack_manifest::{
        FilepackEntry, FilepackManifest, SegmentRef, FILEPACK_MANIFEST_FORMAT_LEVEL_ENCRYPTED,
        FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC, FILEPACK_MANIFEST_VERSION,
    },
    paths::parse_bao_root_from_filename,
    stream::{
        decode::stream_decrypt_header_path,
        encode::{
            stream_encode_inboard_body_from_bytes, stream_encode_outboard, stream_preprocess,
        },
        DEFAULT_SEGMENT_PLAINTEXT_BUDGET,
    },
    structs::{EncodeInfo, OutboardEncoded},
    utils::{decode_bao_hash, encode_bao_hash},
};

#[cfg(feature = "ots")]
use crate::ots::{stamp_bao_root, verify_stamp, OtsPolicy};

/// Default format for public directory archives (c14: public compressed + bao + zfec).
pub const DIRECTORY_ARCHIVE_FORMAT: u8 = FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC;

/// Encrypted directory archive format (c15).
pub const DIRECTORY_ARCHIVE_FORMAT_ENCRYPTED: u8 = FILEPACK_MANIFEST_FORMAT_LEVEL_ENCRYPTED;

/// Test-friendly segment plaintext budget for directory sharding tests (64 KiB).
pub const DIRECTORY_TEST_SEGMENT_BUDGET: u64 = 64 * 1024;

/// Options for [`encode_directory_with_options`].
#[derive(Clone, Debug)]
pub struct DirectoryEncodeOptions {
    /// When true, emit encrypted catalog c15 and encrypted segment formats (c5/c7).
    pub encrypted: bool,
    /// Per-file segment format selection (heterogeneous c4/c6 or c5/c7 within one archive).
    pub segment_format_policy: SegmentFormatPolicy,
    /// Max logical plaintext bytes per segment before sharding a file.
    pub segment_plaintext_budget: u64,
    /// Optional OpenTimestamps stamping policy (requires `ots` feature).
    #[cfg(feature = "ots")]
    pub ots_policy: Option<OtsPolicy>,
}

impl Default for DirectoryEncodeOptions {
    fn default() -> Self {
        Self {
            encrypted: false,
            segment_format_policy: SegmentFormatPolicy::default(),
            segment_plaintext_budget: DEFAULT_SEGMENT_PLAINTEXT_BUDGET,
            #[cfg(feature = "ots")]
            ots_policy: None,
        }
    }
}

impl DirectoryEncodeOptions {
    /// Resolve the catalog format level (c14 public or c15 encrypted).
    pub fn resolved_catalog_format(&self) -> u8 {
        resolve_catalog_format(self.encrypted)
    }
}

/// Result of [`encode_directory`]: catalog bao root and entry count.
#[derive(Clone, Debug)]
pub struct DirectoryArchive {
    /// Keyed Bao root of the `{root}.adam.c{N}` catalog artifact (decimal N = format level).
    pub catalog_bao_root: [u8; 32],
    /// Number of file entries in the catalog.
    pub entry_count: usize,
}

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
    /// Chunk index (u32; supports enormous multi-chunk archives up to u32::MAX segments).
    ///
    /// High-level `file::encode` (and `encode_outboard`) always emits `0` for the primary segment.
    /// True large-file sharding (non-zero chunk_index >0 for continuation segments) is an
    /// application-level concern (format supports it fully via u32 + header_mac coverage).
    /// See AGENTS.md §10 and encoding docs.
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

    /// Legacy v1 ECIES header parsing was removed in the v2 clean break.
    ///
    /// This implementation **always errors** after reading the magic prefix: there is no
    /// supported path to decode headers from a live `File` handle. Retained only for API
    /// surface compatibility. Prefer [`TryFrom<&[u8]>`](Header#impl-TryFrom%3C%26%5Bu8%5D%3E-for-Header).
    #[allow(dead_code)]
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
    ///
    /// The many arguments are required to bind all public metadata (nonce, hash, slh_pk,
    /// format, lengths, meta) under the header_mac (authenticated with dedicated subkey).
    /// This is legitimate for the authenticated container header ctor (see AGENTS §10).
    /// Kept as-is (no refactor) per smallest-change + API stability rules.
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

/// Stream decode from headered inboard archive.
///
/// Note: the body is fully buffered before Bao/FEC reverse (known P2 limitation).
pub fn decode_stream<R: Read, W: Write>(
    master_key: &[u8],
    mut input: R,
    output: &mut W,
) -> Result<(Header, u64), CarbonadoError> {
    let mut header_bytes = [0u8; Header::LEN];
    input
        .read_exact(&mut header_bytes)
        .map_err(CarbonadoError::StdIoError)?;
    let header = Header::try_from(&header_bytes[..])?;

    let auth_data = build_header_auth_data(&header);
    let expected_mac = crate::crypto::compute_header_mac(master_key, &auth_data)?;
    if !crate::crypto::ct_eq(&expected_mac, &header.header_mac) {
        return Err(CarbonadoError::AuthenticationFailed);
    }

    let fmt = header.format;
    let mut body = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = input.read(&mut buf).map_err(CarbonadoError::StdIoError)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
    }

    let mut stage = body;
    if fmt.contains(Format::Bao) {
        stage = decoding::bao(&stage, header.hash.as_bytes(), fmt.bits())?;
    }
    if fmt.contains(Format::Zfec) {
        stage = decoding::zfec(&stage, header.padding_len)?;
    }
    let out_len = if fmt.contains(Format::Encrypted) {
        stream_decrypt_header_path(
            master_key,
            header.payload_nonce,
            std::io::Cursor::new(&stage),
            fmt.bits(),
            output,
        )?
    } else if fmt.contains(Format::Snappy) {
        crate::stream::compress::stream_decompress(std::io::Cursor::new(&stage), output)?
    } else {
        output
            .write_all(&stage)
            .map_err(CarbonadoError::StdIoError)?;
        stage.len() as u64
    };

    Ok((header, out_len))
}

pub fn decode(master_key: &[u8], encoded: &[u8]) -> Result<(Header, Vec<u8>), CarbonadoError> {
    if encoded.len() < Header::LEN {
        return Err(CarbonadoError::InvalidHeaderLength);
    }
    let (header_bytes, body) = encoded.split_at(Header::LEN);
    let header = Header::try_from(header_bytes)?;

    // Verify header_mac
    let auth_data = build_header_auth_data(&header);
    let expected_mac = crate::crypto::compute_header_mac(master_key, &auth_data)?;

    // Constant-time comparison for the header MAC to avoid timing side-channels.
    // (See AGENTS.md for the constant-time review of EtM + header auth paths.)
    if !crate::crypto::ct_eq(&expected_mac, &header.header_mac) {
        return Err(CarbonadoError::AuthenticationFailed);
    }

    // High-level decode must use explicit nonce + with_nonce decrypt for Encrypted case
    // (high encode uses symmetric_encrypt_with_nonce producing [tag|ct] without embedded nonce;
    // low decoding::decode always assumes embedded-nonce blob from low encode).
    // Pipeline reverse mirrors decoding::decode but with correct decrypt for header path.
    let fmt = header.format;
    let after_bao = if fmt.contains(Format::Bao) {
        decoding::bao(body, header.hash.as_bytes(), fmt.bits())?
    } else {
        body.to_owned()
    };
    let after_fec = if fmt.contains(Format::Zfec) {
        decoding::zfec(&after_bao, header.padding_len)?
    } else {
        after_bao
    };
    let decrypted = if fmt.contains(Format::Encrypted) {
        crate::crypto::symmetric_decrypt_with_nonce(master_key, header.payload_nonce, &after_fec)?
    } else {
        after_fec
    };
    let decompressed = if fmt.contains(Format::Snappy) {
        decoding::decompress(&decrypted)?
    } else {
        decrypted
    };

    Ok((header, decompressed))
}

/// High-level encode using the new v2 symmetric model (always inboard with Header prepended).
///
/// `chunk_index` emitted in Header is always 0 (app-level sharding uses non-zero for additional segments;
/// format supports u32 chunk_index + full header_mac auth on it).
///
/// For outboard (bare mains + sidecars for webservers), use `encode_outboard` / `decode_outboard` below
/// (public and encrypted formats share the same artifact split; optional out-of-band Header).
/// Sidecar naming convention: <bao-hash>.cXX.out (Bao), <bao-hash>.cXX.par (FEC parity).
/// See AGENTS §11.2 (completed) and low-level `encoding::encode_outboard`.
pub fn encode(
    master_key: &[u8],
    input: &[u8],
    level: u8,
    metadata: Option<[u8; 8]>,
) -> Result<(Vec<u8>, EncodeInfo), CarbonadoError> {
    let mut out = Vec::new();
    let (header, info) = encode_stream(master_key, input, level, metadata, &mut out)?;
    let mut body = header.try_to_vec()?;
    body.extend_from_slice(&out);
    Ok((body, info))
}

/// Headered inboard encode over [`Read`] / [`Write`]. Header is returned for staging; body
/// hash is known after the pipeline completes.
///
/// `chunk_index` in the returned [`Header`] is always `0` (single-segment encode). For
/// multi-segment archives use [`encode_shard_stream`](crate::stream::encode_shard_stream)
/// with monotonic `chunk_index` values and [`decode_shards_stream`](crate::stream::decode_shards_stream).
pub fn encode_stream<R: Read, W: Write>(
    master_key: &[u8],
    mut input: R,
    level: u8,
    metadata: Option<[u8; 8]>,
    output: &mut W,
) -> Result<(Header, EncodeInfo), CarbonadoError> {
    let format = Format::from(level);
    let mut staging = std::io::Cursor::new(Vec::new());
    let mut payload_nonce = [0u8; 16];
    let stats = stream_preprocess(
        master_key,
        format,
        &mut input,
        &mut staging,
        &mut payload_nonce,
        true,
    )?;
    let body_bytes = staging.into_inner();

    let mut body_out = Vec::new();
    let (hash, info) =
        stream_encode_inboard_body_from_bytes(&body_bytes, stats, level, &mut body_out)?;
    output
        .write_all(&body_out)
        .map_err(CarbonadoError::StdIoError)?;

    let header = Header::new(
        master_key,
        payload_nonce,
        hash.as_bytes(),
        [0u8; 32],
        format,
        0,
        info.output_len,
        info.padding_len,
        metadata,
    )?;
    Ok((header, info))
}

/// Helper to build the exact auth_data for header_mac (avoids duplication in verify paths).
fn build_header_auth_data(hdr: &Header) -> Vec<u8> {
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(MAGICNO);
    auth_data.extend_from_slice(&hdr.payload_nonce);
    auth_data.extend_from_slice(hdr.hash.as_bytes());
    auth_data.extend_from_slice(&hdr.slh_public_key);
    auth_data.push(hdr.format.bits());
    auth_data.extend_from_slice(&hdr.chunk_index.to_le_bytes());
    auth_data.extend_from_slice(&hdr.encoded_len.to_le_bytes());
    auth_data.extend_from_slice(&hdr.padding_len.to_le_bytes());
    auth_data.extend_from_slice(&hdr.metadata.unwrap_or([0u8; 8]));
    auth_data
}

/// High-level outboard encode at the `file` layer (parallel to low-level, smallest extension).
///
/// Returns (optional Header for out-of-band/manifest use with header_mac, OutboardEncoded).
///
/// - For public (!Encrypted) formats: Header is Some (out-of-band; authenticated; contains metadata if any),
///   OutboardEncoded.main is the bare data (post-Snappy if requested; pre-FEC; **no** Carbonado header prepended
///   so main can be served directly), + bao_outboard / fec_parity sidecars when bits set.
/// - For Encrypted: same artifact split as public — bare main (`[tag|ct]` ciphertext, no embedded nonce),
///   sidecars when Bao/Zfec bits set, `payload_nonce` in the out-of-band Header (header-path decrypt).
/// - Low-level [`crate::encoding::encode_outboard`] uses embedded nonce in main (no header required).
/// - Always threads exact format.bits() to keyed Bao (multi-dimensional root commits to c#).
/// - Header (when present) never contains secrets; verify header_mac before trusting (done in matching decode).
///
/// Use returned header or oenc.hash for naming/sidecar discovery and decode. For pure bare serving with no
/// master/header, prefer low-level `encode_outboard` + bao outboard alone.
pub fn encode_outboard(
    master_key: &[u8],
    input: &[u8],
    level: u8,
    metadata: Option<[u8; 8]>,
) -> Result<(Option<Header>, OutboardEncoded), CarbonadoError> {
    let format = Format::from(level);
    let mut payload_nonce = [0u8; 16];
    let explicit_nonce = if format.contains(Format::Encrypted) {
        getrandom::getrandom(&mut payload_nonce).map_err(|_| CarbonadoError::RandomnessError)?;
        Some(payload_nonce)
    } else {
        None
    };
    let oenc = crate::stream::encode::stream_encode_outboard_buffer(
        master_key,
        input,
        format.bits(),
        explicit_nonce,
    )?;
    let hdr = Header::new(
        master_key,
        payload_nonce,
        oenc.hash.as_bytes(),
        [0u8; 32],
        format,
        0,
        oenc.info.bytes_verifiable,
        oenc.info.padding_len,
        metadata,
    )?;
    Ok((Some(hdr), oenc))
}

/// Outboard encode to main + optional sidecar [`File`] writers (public + encrypted).
pub fn encode_outboard_stream<R: Read>(
    master_key: &[u8],
    input: R,
    level: u8,
    metadata: Option<[u8; 8]>,
    main_out: &mut File,
    mut bao_out: Option<&mut File>,
    mut parity_out: Option<&mut File>,
) -> Result<(Option<Header>, OutboardEncoded), CarbonadoError> {
    let format = Format::from(level);
    let mut payload_nonce = [0u8; 16];
    let bao_ref = bao_out.as_deref_mut();
    let par_ref = parity_out.as_deref_mut();
    let (hash, info) = stream_encode_outboard(
        master_key,
        input,
        level,
        main_out,
        bao_ref,
        par_ref,
        &mut payload_nonce,
        true,
    )?;

    let main_bytes = read_file_from_start(main_out)?;
    let bao_sidecar = if format.contains(Format::Bao) {
        Some(read_file_from_start(
            bao_out.ok_or(CarbonadoError::MissingBaoOutboard)?,
        )?)
    } else {
        None
    };
    let fec_sidecar = if format.contains(Format::Zfec) {
        Some(read_file_from_start(
            parity_out.ok_or(CarbonadoError::MissingFecParity)?,
        )?)
    } else {
        None
    };

    let hdr = Header::new(
        master_key,
        payload_nonce,
        hash.as_bytes(),
        [0u8; 32],
        format,
        0,
        info.bytes_verifiable,
        info.padding_len,
        metadata,
    )?;

    Ok((
        Some(hdr),
        OutboardEncoded {
            main: main_bytes,
            bao_outboard: bao_sidecar,
            fec_parity: fec_sidecar,
            hash,
            info,
        },
    ))
}

fn read_file_from_start(f: &mut File) -> Result<Vec<u8>, CarbonadoError> {
    f.rewind().map_err(CarbonadoError::StdIoError)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
        .map_err(CarbonadoError::StdIoError)?;
    Ok(buf)
}

/// High-level outboard decode at the `file` layer (accepts bare main + sidecars + optional out-of-band header).
///
/// `hash` is required (the keyed Bao root; from Header or filename); used for bao_with_outboard verify.
/// `header`: optional out-of-band header bytes. If present, header_mac is verified (using master) before
/// processing; enables auth for public bare cases too. If absent, public bare decode relies on bao outboard
/// integrity (no mac).
/// `main`: the bare main bytes (for public outboard) or post-header body (for enc inboard cases).
/// Automatically tolerates accidental header prefix in main (strips if MAGIC present) for convenience.
/// For Encrypted formats, `header` is required (provides payload_nonce); sidecars are ignored (not produced for enc).
/// Sidecars required only when respective bits set (public paths); specific errors (MissingBaoOutboard etc) on absence.
/// Uses decode_outboard (which threads format for keyed bao verify).
///
/// Many args are for flexibility (optional header for mac, bare main or inboard body,
/// optional sidecars); this mirrors low-level + supports outboard public use cases.
#[allow(clippy::too_many_arguments)]
pub fn decode_outboard(
    master_key: &[u8],
    hash: &[u8],
    header: Option<&[u8]>,
    main: &[u8],
    bao_outboard: Option<&[u8]>,
    fec_parity: Option<&[u8]>,
    padding: u32,
    format: u8,
) -> Result<Vec<u8>, CarbonadoError> {
    let fmt = Format::from(format);

    let mut use_nonce: Option<[u8; 16]> = None;
    let mut use_hash = hash.to_vec();
    let mut use_pad = padding;

    if let Some(hbytes) = header {
        if hbytes.len() < Header::LEN {
            return Err(CarbonadoError::InvalidHeaderLength);
        }
        let hdr = Header::try_from(hbytes)?;

        // Verify header_mac (binds metadata, hash, format, nonce, lengths). Constant-time.
        let auth_data = build_header_auth_data(&hdr);
        let expected_mac = crate::crypto::compute_header_mac(master_key, &auth_data)?;
        if !crate::crypto::ct_eq(&expected_mac, &hdr.header_mac) {
            return Err(CarbonadoError::AuthenticationFailed);
        }

        // Cross-check authenticated fields from header against caller params (early specific error for mismatch/tampering).
        // Hash mismatch -> AuthenticationFailed (tamper signal, post-mac); format/pad/len -> InvalidHeaderLength.
        if hdr.hash.as_bytes() != hash {
            return Err(CarbonadoError::AuthenticationFailed);
        }
        if hdr.format.bits() != format || hdr.padding_len != padding {
            return Err(CarbonadoError::InvalidHeaderLength);
        }

        use_nonce = Some(hdr.payload_nonce);
        use_hash = hdr.hash.as_bytes().to_vec();
        use_pad = hdr.padding_len;
    }

    // For Encrypted, high-level inboard results (produced by file::encode / encode_outboard for enc) require the header
    // (for payload_nonce) and use embedded inboard body (sides=None). Public outboard uses bare + sides.
    if fmt.contains(Format::Encrypted) && header.is_none() {
        return Err(CarbonadoError::MissingOutboardHeader);
    }

    // Tolerate if caller accidentally passed a header-prepended main (e.g. from enc inboard result);
    // strip only the known header for the decode body part. Does not affect bare public mains.
    let main_body = if main.len() > Header::LEN && &main[0..12] == MAGICNO {
        &main[Header::LEN..]
    } else {
        main
    };

    // Encrypted outboard uses bare main + sidecars with header-path nonce; tolerate legacy
    // inboard-embedded bodies (header prefix in main) via main_body strip above.
    if fmt.contains(Format::Encrypted) && main.len() > Header::LEN && &main[0..12] == MAGICNO {
        let mut stage = main_body.to_vec();
        if fmt.contains(Format::Bao) {
            stage = decoding::bao(&stage, &use_hash, format)?;
        }
        if fmt.contains(Format::Zfec) {
            stage = decoding::zfec(&stage, use_pad)?;
        }
        let nonce = use_nonce.ok_or(CarbonadoError::InvalidHeaderLength)?;
        let decrypted = crate::crypto::symmetric_decrypt_with_nonce(master_key, nonce, &stage)?;
        if fmt.contains(Format::Snappy) {
            Ok(decoding::decompress(&decrypted)?)
        } else {
            Ok(decrypted)
        }
    } else {
        crate::stream::decode::stream_decode_outboard_buffer(
            master_key,
            &use_hash,
            main_body,
            bao_outboard,
            fec_parity,
            use_pad,
            format,
            use_nonce,
        )
    }
}

/// Recursively encode a directory tree into bare per-file segment mains (c4/c6 or c5/c7) plus an
/// inboard Adamantine-wrapped rkyv `FilepackManifest` catalog at `{catalog_bao_root}.adam.c14`
/// (or `.adam.c15` when encrypted).
///
/// Segment Bao outboard data is centralized in the Adamantine payload bundle (no per-segment
/// `.out`/`.par` sidecars). The catalog is always inboard c14/c15 with a `CARBONADO20\n` header.
///
/// Uses public c14 by default; `master_key` must be zeroed for public catalogs.
pub fn encode_directory(
    master_key: &[u8],
    dir: &Path,
    outdir: &Path,
) -> Result<DirectoryArchive, CarbonadoError> {
    encode_directory_with_options(master_key, dir, outdir, DirectoryEncodeOptions::default())
}

/// Encode a directory with explicit options (encryption, sharding budget, OTS policy).
///
/// Segment mains are written before the catalog artifact. If catalog assembly fails after
/// segment writes, written segment files are removed before the error is returned.
pub fn encode_directory_with_options(
    master_key: &[u8],
    dir: &Path,
    outdir: &Path,
    options: DirectoryEncodeOptions,
) -> Result<DirectoryArchive, CarbonadoError> {
    if !dir.is_dir() {
        return Err(CarbonadoError::NotADirectory(dir.display().to_string()));
    }
    let catalog_format = options.resolved_catalog_format();
    if catalog_format & 1 != 0 && master_key.iter().all(|&b| b == 0) {
        return Err(CarbonadoError::ZeroMasterKeyNotAllowed);
    }
    if catalog_format & 1 == 0 && !master_key.iter().all(|&b| b == 0) {
        return Err(CarbonadoError::EncryptedDirectoryNotRequested);
    }

    fs::create_dir_all(outdir)?;
    let mut entries: Vec<FilepackEntry> = Vec::new();
    let mut bao_bundle = BaoBundleBuilder::new();
    let mut rollback = DirectoryEncodeRollback {
        segment_paths: Vec::new(),
        catalog_path: None,
    };
    let mut state = DirectoryEncodeState {
        master_key,
        outdir,
        catalog_format,
        options: &options,
        entries: &mut entries,
        bao_bundle: &mut bao_bundle,
        written_segment_paths: &mut rollback.segment_paths,
    };

    if let Err(err) = collect_and_encode_files(dir, Path::new(""), &mut state) {
        rollback_directory_encode_artifacts(&rollback);
        return Err(err);
    }
    entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));

    match write_catalog_artifact(
        master_key,
        &entries,
        outdir,
        catalog_format,
        &options,
        &bao_bundle,
        &mut rollback.catalog_path,
    ) {
        Ok(catalog_bao_root) => Ok(DirectoryArchive {
            catalog_bao_root,
            entry_count: entries.len(),
        }),
        Err(err) => {
            rollback_directory_encode_artifacts(&rollback);
            Err(err)
        }
    }
}

/// Decode an inboard Adamantine catalog (`.adam.c14` or `.adam.c15`) and reconstruct the tree.
pub fn decode_directory(
    master_key: &[u8],
    catalog_adam: &Path,
    outdir: &Path,
) -> Result<(), CarbonadoError> {
    let (expected_root, catalog_format) = parse_catalog_bao_root_and_format(catalog_adam)?;
    if catalog_format != FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC
        && catalog_format != FILEPACK_MANIFEST_FORMAT_LEVEL_ENCRYPTED
    {
        return Err(CarbonadoError::InvalidCatalogPath(format!(
            "directory catalog must be .adam.c14 or .adam.c15, got format {catalog_format}"
        )));
    }
    if catalog_format & 1 != 0 && master_key.iter().all(|&b| b == 0) {
        return Err(CarbonadoError::ZeroMasterKeyNotAllowed);
    }
    if catalog_format & 1 == 0 && !master_key.iter().all(|&b| b == 0) {
        return Err(CarbonadoError::EncryptedDirectoryNotRequested);
    }

    guard_directory_catalog_file_len(catalog_adam)?;
    let main_raw = read_file(catalog_adam)?;
    let (main, catalog_ots_from_file) = split_catalog_file_ots_trailer(&main_raw)?;
    if !is_inboard_wire(&main) {
        return Err(CarbonadoError::DirectoryLayoutMismatch(
            "directory catalog must be inboard headered c14/c15".into(),
        ));
    }
    let (header, carbonado_body) = decode(master_key, &main).map_err(map_catalog_decode_err)?;
    if header.hash.as_bytes() != &expected_root {
        return Err(CarbonadoError::CatalogBaoRootMismatch);
    }

    let (adam_payload, adam_hdr) = decode_adamantine(&carbonado_body)?;
    validate_adamantine_format_consistency(&adam_hdr, catalog_format)?;
    let (rkyv_payload, bao_bundle) = split_adamantine_payload(&adam_payload)?;
    let mut index = FilepackManifest::from_bytes_with_root(&rkyv_payload, expected_root)?;
    index.catalog_ots_proof = catalog_ots_from_file;
    validate_filepack_manifest_format_level(&index, catalog_format)?;
    index.validate_bao_bundle_refs(bao_bundle.len())?;

    let catalog_dir = catalog_adam
        .parent()
        .ok_or_else(|| CarbonadoError::NotADirectory("catalog has no parent".into()))?;

    #[cfg(feature = "ots")]
    verify_catalog_ots_at_decode(&adam_hdr, &index)?;
    #[cfg(not(feature = "ots"))]
    if adam_hdr.flags & ADAMANTINE_FLAG_REQUIRE_OTS != 0 {
        return Err(CarbonadoError::OtsFeatureRequired);
    }

    fs::create_dir_all(outdir)?;
    let outdir_canon = outdir.canonicalize().map_err(CarbonadoError::StdIoError)?;

    for entry in &index.entries {
        #[cfg(feature = "ots")]
        verify_entry_ots_at_decode(&adam_hdr, entry)?;

        let rel = &entry.rel_path;
        let mut recovered = Vec::new();
        for seg_ref in &entry.segments {
            let segment_root = seg_ref.segment_bao_root;
            let main_name = segment_filename(&segment_root, entry.segment_format, "");
            let main_path = catalog_dir.join(&main_name);

            check_segment_artifact_root(&main_path, &segment_root, rel, seg_ref.chunk_index)?;
            guard_segment_main_file_len(&main_path, seg_ref.main_len, rel, seg_ref.chunk_index)?;
            let seg_main = read_file(&main_path)
                .map_err(|_| CarbonadoError::MissingSegment(format!("{rel} ({main_name})")))?;
            if is_inboard_wire(&seg_main) {
                return Err(CarbonadoError::DirectoryLayoutMismatch(
                    "segment artifact must be bare main, not headered inboard".into(),
                ));
            }
            if seg_main.len() as u64 != seg_ref.main_len {
                return Err(CarbonadoError::SegmentMainLenMismatch {
                    rel_path: rel.clone(),
                    chunk_index: seg_ref.chunk_index,
                });
            }
            let bao_ob = bao_slice_from_bundle(
                &bao_bundle,
                seg_ref.bao_outboard_offset,
                seg_ref.bao_outboard_len,
            )?;
            let part = decoding::decode_outboard(
                master_key,
                &segment_root,
                &seg_main,
                Some(bao_ob),
                None,
                0,
                entry.segment_format,
            )?;
            recovered.extend_from_slice(&part);
        }

        let content_hash = blake3::hash(&recovered);
        if *content_hash.as_bytes() != entry.content_blake3 {
            return Err(CarbonadoError::ContentBlake3Mismatch(rel.clone()));
        }

        let out_path = resolve_output_path(&outdir_canon, rel)?;
        reject_symlink_components_under(&outdir_canon, &out_path)?;
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_file(&out_path, &recovered)?;
    }

    Ok(())
}

/// Debug-only hook to inject catalog assembly failure (integration tests in debug builds).
#[cfg(debug_assertions)]
pub mod directory_encode_test_hooks {
    use std::cell::Cell;

    thread_local! {
        static FAIL_NEXT_CATALOG_WRITE: Cell<bool> = const { Cell::new(false) };
    }

    /// Arm the next [`encode_directory_with_options`] call on this thread to fail at catalog assembly.
    pub fn arm_catalog_write_failure() {
        FAIL_NEXT_CATALOG_WRITE.with(|flag| flag.set(true));
    }

    pub(crate) fn take_catalog_write_failure() -> bool {
        FAIL_NEXT_CATALOG_WRITE.with(|flag| {
            let armed = flag.get();
            flag.set(false);
            armed
        })
    }
}

/// Mutable state shared while walking a source tree during directory encode.
struct DirectoryEncodeState<'a> {
    master_key: &'a [u8],
    outdir: &'a Path,
    catalog_format: u8,
    options: &'a DirectoryEncodeOptions,
    entries: &'a mut Vec<FilepackEntry>,
    bao_bundle: &'a mut BaoBundleBuilder,
    written_segment_paths: &'a mut Vec<PathBuf>,
}

/// Accumulates segment Bao outboard blobs for the Adamantine payload bundle.
struct BaoBundleBuilder {
    bytes: Vec<u8>,
}

impl BaoBundleBuilder {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn append(&mut self, blob: &[u8]) -> Result<(u32, u32), CarbonadoError> {
        let offset = self.bytes.len() as u32;
        let len = blob.len() as u32;
        let end = self
            .bytes
            .len()
            .checked_add(blob.len())
            .ok_or(CarbonadoError::InvalidAdamantineHeader)?;
        if end > MAX_BAO_BUNDLE_LEN {
            return Err(CarbonadoError::InvalidAdamantinePayloadTooLarge {
                declared: end as u32,
                max: MAX_BAO_BUNDLE_LEN,
            });
        }
        self.bytes.extend_from_slice(blob);
        Ok((offset, len))
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

fn collect_and_encode_files(
    base: &Path,
    rel: &Path,
    state: &mut DirectoryEncodeState<'_>,
) -> Result<(), CarbonadoError> {
    for item in fs::read_dir(base).map_err(CarbonadoError::StdIoError)? {
        let item = item.map_err(CarbonadoError::StdIoError)?;
        let name = item.file_name().to_string_lossy().to_string();
        if name == "." || name == ".." || name.contains('/') || name.contains('\\') {
            continue;
        }
        let path = item.path();
        let file_type = item.file_type().map_err(CarbonadoError::StdIoError)?;
        if file_type.is_symlink() {
            return Err(CarbonadoError::SymlinkNotAllowed(
                path.display().to_string(),
            ));
        }
        let child_rel = if rel.as_os_str().is_empty() {
            PathBuf::from(&name)
        } else {
            rel.join(&name)
        };
        let rel_str = child_rel.to_string_lossy().replace('\\', "/");
        FilepackManifest::validate_rel_path(&rel_str)?;
        if file_type.is_dir() {
            collect_and_encode_files(&path, &child_rel, state)?;
        } else if file_type.is_file() {
            let data = read_file(&path)?;
            let content_blake3 = *blake3::hash(&data).as_bytes();
            let segment_format = state
                .options
                .segment_format_policy
                .resolve_segment_format(state.catalog_format & 1 != 0, &data)?;
            let segments = encode_file_segments(
                state.master_key,
                &data,
                segment_format,
                state.outdir,
                state.options,
                state.bao_bundle,
                state.written_segment_paths,
            )?;
            #[cfg(feature = "ots")]
            let ots_proof = if state
                .options
                .ots_policy
                .as_ref()
                .is_some_and(|p| p.stamp_entries)
            {
                let primary_root = segments[0].segment_bao_root;
                Some(stamp_bao_root(&primary_root)?)
            } else {
                None
            };
            state.entries.push(FilepackEntry {
                rel_path: rel_str,
                content_blake3,
                segment_format,
                segments,
                #[cfg(feature = "ots")]
                ots_proof,
                #[cfg(not(feature = "ots"))]
                ots_proof: None,
            });
        } else {
            return Err(CarbonadoError::UnsupportedFileType(
                path.display().to_string(),
            ));
        }
    }
    Ok(())
}

/// Encode and write segment(s) for one file, sharding when over budget.
fn encode_file_segments(
    master_key: &[u8],
    data: &[u8],
    segment_format: u8,
    outdir: &Path,
    options: &DirectoryEncodeOptions,
    bao_bundle: &mut BaoBundleBuilder,
    written_segment_paths: &mut Vec<PathBuf>,
) -> Result<Vec<SegmentRef>, CarbonadoError> {
    let budget = options.segment_plaintext_budget.max(1);
    let chunks: Vec<&[u8]> = if data.is_empty() || data.len() as u64 <= budget {
        vec![data]
    } else {
        data.chunks(budget as usize).collect()
    };

    let mut segments = Vec::with_capacity(chunks.len());
    for (chunk_index, chunk) in chunks.into_iter().enumerate() {
        let seg_ref = write_bare_segment(
            master_key,
            chunk,
            segment_format,
            outdir,
            chunk_index,
            bao_bundle,
            written_segment_paths,
        )?;
        segments.push(seg_ref);
    }
    Ok(segments)
}

/// Encode one bare segment main and append its Bao outboard blob to the bundle.
fn write_bare_segment(
    master_key: &[u8],
    data: &[u8],
    segment_format: u8,
    outdir: &Path,
    chunk_index: usize,
    bao_bundle: &mut BaoBundleBuilder,
    written_segment_paths: &mut Vec<PathBuf>,
) -> Result<SegmentRef, CarbonadoError> {
    let oenc = encoding::encode_outboard(master_key, data, segment_format)?;
    let root = *oenc.hash.as_bytes();
    let main_len = oenc.main.len() as u64;
    let main_name = segment_filename(&root, segment_format, "");
    let main_path = outdir.join(&main_name);
    write_file(&main_path, &oenc.main)?;
    written_segment_paths.push(main_path);
    let bao_ob = oenc
        .bao_outboard
        .as_deref()
        .ok_or(CarbonadoError::MissingBaoOutboard)?;
    let (offset, len) = bao_bundle.append(bao_ob)?;
    Ok(SegmentRef {
        segment_bao_root: root,
        chunk_index: chunk_index as u32,
        main_len,
        bao_outboard_offset: offset,
        bao_outboard_len: len,
    })
}

fn write_catalog_artifact(
    master_key: &[u8],
    entries: &[FilepackEntry],
    outdir: &Path,
    catalog_format: u8,
    options: &DirectoryEncodeOptions,
    bao_bundle: &BaoBundleBuilder,
    written_catalog_path: &mut Option<PathBuf>,
) -> Result<[u8; 32], CarbonadoError> {
    let mut flags = 0u8;
    #[cfg(feature = "ots")]
    if options.ots_policy.as_ref().is_some_and(|p| p.stamp_entries) {
        flags |= ADAMANTINE_FLAG_REQUIRE_OTS;
    }

    let adam_fmt = if catalog_format & 1 != 0 {
        ADAMANTINE_CARBONADO_FMT_ENCRYPTED
    } else {
        ADAMANTINE_CARBONADO_FMT_PUBLIC
    };

    let bundle = bao_bundle.as_slice();
    let encoded =
        encode_inboard_catalog_bytes(master_key, entries, catalog_format, adam_fmt, flags, bundle)?;
    #[cfg(debug_assertions)]
    if directory_encode_test_hooks::take_catalog_write_failure() {
        return Err(CarbonadoError::StdIoError(std::io::Error::other(
            "test-injected catalog assembly failure",
        )));
    }
    let header = Header::try_from(&encoded[..Header::LEN])?;
    let root = hash_to_root(header.hash.as_bytes());

    let mut on_disk = encoded;
    #[cfg(feature = "ots")]
    if options.ots_policy.as_ref().is_some_and(|p| p.stamp_catalog) {
        let proof = stamp_bao_root(&root)?;
        on_disk = append_catalog_ots_trailer(&on_disk, &proof)?;
    }

    let main_name = segment_filename(&root, catalog_format, ".adam");
    let catalog_path = outdir.join(&main_name);
    *written_catalog_path = Some(catalog_path.clone());
    if let Err(err) = write_file(&catalog_path, &on_disk) {
        let _ = fs::remove_file(&catalog_path);
        *written_catalog_path = None;
        return Err(err);
    }
    Ok(root)
}

fn encode_inboard_catalog_bytes(
    master_key: &[u8],
    entries: &[FilepackEntry],
    catalog_format: u8,
    adam_fmt: u8,
    flags: u8,
    bao_bundle: &[u8],
) -> Result<Vec<u8>, CarbonadoError> {
    let index = FilepackManifest {
        version: FILEPACK_MANIFEST_VERSION,
        format_level: catalog_format,
        catalog_bao_root: [0u8; 32],
        catalog_ots_proof: None,
        entries: entries.to_vec(),
    };
    index.validate()?;
    let rkyv = index.into_bytes()?;
    let adam_payload = build_adamantine_payload(&rkyv, bao_bundle)?;
    let adamantine = encode_adamantine(&adam_payload, adam_fmt, flags);
    let (encoded, _info) = encode(master_key, &adamantine, catalog_format, None)?;
    Ok(encoded)
}

/// Magic prefix for optional catalog OTS trailer after inboard catalog bytes.
const CATALOG_OTS_TRAILER_MAGIC: &[u8; 4] = b"COTS";

/// Maximum optional catalog `COTS` trailer: magic + u32 len + proof bytes.
const CATALOG_OTS_TRAILER_MAX_LEN: usize = 4 + 4 + crate::filepack_manifest::MAX_OTS_PROOF_LEN;

/// Upper bound on directory catalog on-disk bytes before `read_file` (DoS guard).
fn max_directory_catalog_on_disk_bytes() -> usize {
    let adam_wrapped = ADAMANTINE_HEADER_LEN.saturating_add(MAX_ADAMANTINE_PAYLOAD_LEN);
    // c14/c15 FEC 4/8 worst-case expansion on the verifiable body.
    let carbonado_body = adam_wrapped.saturating_mul(2).saturating_add(4096);
    Header::LEN
        .saturating_add(carbonado_body)
        .saturating_add(CATALOG_OTS_TRAILER_MAX_LEN)
}

fn path_file_len(path: &Path) -> Result<u64, CarbonadoError> {
    fs::metadata(path)
        .map(|m| m.len())
        .map_err(CarbonadoError::StdIoError)
}

fn guard_directory_catalog_file_len(path: &Path) -> Result<(), CarbonadoError> {
    let len = path_file_len(path)? as usize;
    let max = max_directory_catalog_on_disk_bytes();
    if len > max {
        return Err(CarbonadoError::InvalidAdamantinePayloadTooLarge {
            declared: len.min(u32::MAX as usize) as u32,
            max,
        });
    }
    Ok(())
}

fn guard_segment_main_file_len(
    path: &Path,
    expected_main_len: u64,
    rel_path: &str,
    chunk_index: u32,
) -> Result<(), CarbonadoError> {
    let len = match fs::metadata(path) {
        Ok(meta) => meta.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(CarbonadoError::MissingSegment(format!(
                "{rel_path} ({})",
                path.display()
            )));
        }
        Err(e) => return Err(CarbonadoError::StdIoError(e)),
    };
    if len != expected_main_len {
        if len as usize >= Header::LEN {
            let prefix = peek_file_prefix(path, Header::LEN)?;
            if has_carbonado_header_magic_prefix(&prefix) {
                return Err(CarbonadoError::DirectoryLayoutMismatch(
                    "segment artifact must be bare main, not headered inboard".into(),
                ));
            }
        }
        return Err(CarbonadoError::SegmentMainLenMismatch {
            rel_path: rel_path.to_string(),
            chunk_index,
        });
    }
    Ok(())
}

fn peek_file_prefix(path: &Path, n: usize) -> Result<Vec<u8>, CarbonadoError> {
    let mut f = File::open(path).map_err(CarbonadoError::StdIoError)?;
    let mut buf = vec![0u8; n];
    let got = f.read(&mut buf).map_err(CarbonadoError::StdIoError)?;
    buf.truncate(got);
    Ok(buf)
}

fn has_carbonado_header_magic_prefix(bytes: &[u8]) -> bool {
    bytes.len() >= 12 && &bytes[0..12] == MAGICNO
}

/// Append `[COTS][u32 LE ots_len][ots_proof]` after inboard catalog bytes (does not affect Bao root).
fn append_catalog_ots_trailer(
    carbonado_bytes: &[u8],
    proof: &[u8],
) -> Result<Vec<u8>, CarbonadoError> {
    if proof.len() > crate::filepack_manifest::MAX_OTS_PROOF_LEN {
        return Err(CarbonadoError::InvalidOtsProof(format!(
            "catalog_ots_proof exceeds {}",
            crate::filepack_manifest::MAX_OTS_PROOF_LEN
        )));
    }
    let mut out = Vec::with_capacity(carbonado_bytes.len() + 8 + proof.len());
    out.extend_from_slice(carbonado_bytes);
    out.extend_from_slice(CATALOG_OTS_TRAILER_MAGIC);
    out.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    out.extend_from_slice(proof);
    Ok(out)
}

/// Split optional catalog OTS trailer from on-disk inboard catalog bytes.
///
/// Scans backward from the file end for a `COTS` magic within `MAX_OTS_PROOF_LEN + 8` bytes.
/// A false positive is possible if the Carbonado ciphertext body contains a `COTS` substring
/// aligned so that following bytes look like a valid proof length and EOF boundary; callers
/// should treat extracted proofs as untrusted until `verify_stamp` succeeds.
fn split_catalog_file_ots_trailer(
    bytes: &[u8],
) -> Result<(Vec<u8>, Option<Vec<u8>>), CarbonadoError> {
    if bytes.len() < Header::LEN + 8 {
        return Ok((bytes.to_vec(), None));
    }
    let max_scan = crate::filepack_manifest::MAX_OTS_PROOF_LEN + 8;
    let scan_start = bytes.len().saturating_sub(max_scan).max(Header::LEN);
    for i in (scan_start..=bytes.len().saturating_sub(8)).rev() {
        if &bytes[i..i + 4] != CATALOG_OTS_TRAILER_MAGIC {
            continue;
        }
        let ots_len =
            u32::from_le_bytes(bytes[i + 4..i + 8].try_into().map_err(|_| {
                CarbonadoError::InvalidOtsProof("catalog ots trailer corrupt".into())
            })?) as usize;
        if ots_len > crate::filepack_manifest::MAX_OTS_PROOF_LEN {
            return Err(CarbonadoError::InvalidOtsProof(format!(
                "catalog_ots_proof exceeds {}",
                crate::filepack_manifest::MAX_OTS_PROOF_LEN
            )));
        }
        if i + 8 + ots_len != bytes.len() {
            continue;
        }
        let proof = bytes[i + 8..].to_vec();
        return Ok((bytes[..i].to_vec(), Some(proof)));
    }
    Ok((bytes.to_vec(), None))
}

fn validate_adamantine_format_consistency(
    hdr: &AdamantineHeader,
    format: u8,
) -> Result<(), CarbonadoError> {
    if hdr.carbonado_fmt != format {
        return Err(CarbonadoError::AdamantineFormatFilenameMismatch {
            header: hdr.carbonado_fmt,
            filename: format,
        });
    }
    Ok(())
}

fn validate_filepack_manifest_format_level(
    index: &FilepackManifest,
    format: u8,
) -> Result<(), CarbonadoError> {
    if index.format_level != format {
        return Err(CarbonadoError::InvalidFilepackManifest(format!(
            "format_level 0x{:02x} does not match catalog format 0x{:02x}",
            index.format_level, format
        )));
    }
    Ok(())
}

fn is_inboard_wire(bytes: &[u8]) -> bool {
    bytes.len() > Header::LEN && &bytes[0..12] == MAGICNO
}

fn hash_to_root(hash_bytes: &[u8]) -> [u8; 32] {
    let mut root = [0u8; 32];
    root.copy_from_slice(hash_bytes);
    root
}

#[cfg(feature = "ots")]
fn require_valid_ots_proof(proof: &[u8], root: &[u8; 32]) -> Result<(), CarbonadoError> {
    let v = verify_stamp(proof, root)?;
    if !v.valid {
        return Err(CarbonadoError::OtsVerificationFailed);
    }
    Ok(())
}

#[cfg(feature = "ots")]
fn verify_catalog_ots_at_decode(
    _adam_hdr: &AdamantineHeader,
    index: &FilepackManifest,
) -> Result<(), CarbonadoError> {
    // Catalog OTS lives in the optional COTS file trailer; verify when present.
    // REQUIRE_OTS applies to per-entry proofs only (see AGENTS §7.1).
    if let Some(proof) = &index.catalog_ots_proof {
        require_valid_ots_proof(proof, &index.catalog_bao_root)?;
    }
    Ok(())
}

#[cfg(feature = "ots")]
fn verify_entry_ots_at_decode(
    adam_hdr: &AdamantineHeader,
    entry: &FilepackEntry,
) -> Result<(), CarbonadoError> {
    if adam_hdr.flags & ADAMANTINE_FLAG_REQUIRE_OTS != 0 {
        let proof = entry
            .ots_proof
            .as_ref()
            .ok_or_else(|| CarbonadoError::OtsProofRequired(entry.rel_path.clone()))?;
        let primary_root = entry.segments.first().ok_or_else(|| {
            CarbonadoError::InvalidFilepackManifest(format!(
                "entry {} has no segments",
                entry.rel_path
            ))
        })?;
        require_valid_ots_proof(proof, &primary_root.segment_bao_root)?;
    } else if let Some(proof) = &entry.ots_proof {
        let primary_root = entry.segments.first().ok_or_else(|| {
            CarbonadoError::InvalidFilepackManifest(format!(
                "entry {} has no segments",
                entry.rel_path
            ))
        })?;
        require_valid_ots_proof(proof, &primary_root.segment_bao_root)?;
    }
    Ok(())
}

/// Verify an on-disk segment main filename stem matches the manifest Bao root.
fn check_segment_artifact_root(
    main_path: &Path,
    expected_root: &[u8; 32],
    rel_path: &str,
    chunk_index: u32,
) -> Result<(), CarbonadoError> {
    let on_disk_root = parse_bao_root_from_filename(main_path).ok_or_else(|| {
        CarbonadoError::MissingSegment(format!(
            "{rel_path} (invalid segment filename {})",
            main_path.display()
        ))
    })?;
    if on_disk_root != *expected_root {
        return Err(CarbonadoError::SegmentBaoRootMismatch {
            rel_path: rel_path.to_string(),
            chunk_index,
        });
    }
    Ok(())
}

/// Paths written during an in-progress directory encode (for rollback on failure).
struct DirectoryEncodeRollback {
    segment_paths: Vec<PathBuf>,
    catalog_path: Option<PathBuf>,
}

/// Best-effort removal of segment mains and catalog stub after a failed directory encode.
fn rollback_directory_encode_artifacts(rollback: &DirectoryEncodeRollback) {
    for path in &rollback.segment_paths {
        let _ = fs::remove_file(path);
    }
    if let Some(path) = &rollback.catalog_path {
        let _ = fs::remove_file(path);
    }
}

fn segment_filename(root: &[u8; 32], format: u8, name_infix: &str) -> String {
    if name_infix == ".adam" {
        format!("{}.adam.c{format}", hex_encode(root))
    } else {
        format!("{}.c{format}", hex_encode(root))
    }
}

fn map_catalog_decode_err(err: CarbonadoError) -> CarbonadoError {
    match err {
        CarbonadoError::OutboardVerificationFailed(_) => CarbonadoError::CatalogBaoRootMismatch,
        other => other,
    }
}

fn resolve_output_path(outdir: &Path, rel: &str) -> Result<PathBuf, CarbonadoError> {
    FilepackManifest::validate_rel_path(rel)?;
    let mut target = outdir.to_path_buf();
    for component in rel.split('/').filter(|c| !c.is_empty() && *c != ".") {
        if component == ".." {
            return Err(CarbonadoError::OutputPathEscape(
                "rel_path must not contain '..' components".into(),
            ));
        }
        target.push(component);
    }
    if !target.starts_with(outdir) {
        return Err(CarbonadoError::OutputPathEscape(
            "resolved path escapes output directory".into(),
        ));
    }
    Ok(target)
}

/// Reject extraction when an existing path component under `outdir` is a symlink.
fn reject_symlink_components_under(base: &Path, target: &Path) -> Result<(), CarbonadoError> {
    if !target.starts_with(base) {
        return Err(CarbonadoError::OutputPathEscape(
            "resolved path escapes output directory".into(),
        ));
    }
    let rel = target
        .strip_prefix(base)
        .map_err(|_| CarbonadoError::OutputPathEscape("invalid output path".into()))?;
    let mut current = base.to_path_buf();
    for component in rel.components() {
        if let std::path::Component::Normal(name) = component {
            current.push(name);
            if let Ok(meta) = fs::symlink_metadata(&current) {
                if meta.file_type().is_symlink() {
                    return Err(CarbonadoError::SymlinkNotAllowed(
                        current.display().to_string(),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn parse_catalog_bao_root_and_format(path: &Path) -> Result<([u8; 32], u8), CarbonadoError> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| CarbonadoError::InvalidCatalogPath("catalog path has no filename".into()))?;
    if !crate::paths::is_adam_catalog(path) {
        return Err(CarbonadoError::InvalidCatalogPath(format!(
            "expected filename ending with .adam.c0 through .adam.c15, got {name}"
        )));
    }
    let format = crate::paths::guess_format_from_filename(path).ok_or_else(|| {
        CarbonadoError::InvalidCatalogPath(format!(
            "could not determine catalog format from {name}"
        ))
    })?;
    let root = crate::paths::parse_bao_root_from_filename(path).ok_or_else(|| {
        CarbonadoError::InvalidCatalogPath(format!(
            "catalog root must be 64 hex chars in filename, got invalid prefix in {name}"
        ))
    })?;
    Ok((root, format))
}

fn read_file(path: &Path) -> Result<Vec<u8>, CarbonadoError> {
    let mut f = File::open(path).map_err(CarbonadoError::StdIoError)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
        .map_err(CarbonadoError::StdIoError)?;
    Ok(buf)
}

fn write_file(path: &Path, data: &[u8]) -> Result<(), CarbonadoError> {
    let mut f = File::create(path).map_err(CarbonadoError::StdIoError)?;
    f.write_all(data).map_err(CarbonadoError::StdIoError)?;
    Ok(())
}

fn hex_encode(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod directory_decode_path_tests {
    use super::*;
    use std::fs;

    #[test]
    fn reject_symlink_components_under_rejects_path_outside_base() {
        let base = std::env::temp_dir().join(format!("base_{}", std::process::id()));
        let outside = std::env::temp_dir().join(format!("outside_{}", std::process::id()));
        fs::create_dir_all(&base).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let err = reject_symlink_components_under(&base, &outside).unwrap_err();
        assert!(
            matches!(err, CarbonadoError::OutputPathEscape(_)),
            "got {err:?}"
        );
        let _ = fs::remove_dir_all(&base);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn guard_segment_main_file_len_mismatch_without_read() {
        let dir = std::env::temp_dir().join(format!("seg_len_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("abc.c6");
        fs::write(&path, vec![0u8; 128]).unwrap();
        let err = guard_segment_main_file_len(&path, 64, "f.txt", 0).unwrap_err();
        assert!(matches!(
            err,
            CarbonadoError::SegmentMainLenMismatch {
                rel_path,
                chunk_index: 0
            } if rel_path == "f.txt"
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn guard_directory_catalog_file_len_rejects_oversized_metadata() {
        let dir = std::env::temp_dir().join(format!("cat_len_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("catalog.adam.c14");
        fs::write(&path, vec![0u8; 64]).unwrap();
        let f = fs::OpenOptions::new().write(true).open(&path).unwrap();
        let oversize = max_directory_catalog_on_disk_bytes().saturating_add(1) as u64;
        f.set_len(oversize).unwrap();
        let err = guard_directory_catalog_file_len(&path).unwrap_err();
        assert!(matches!(
            err,
            CarbonadoError::InvalidAdamantinePayloadTooLarge { .. }
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_segment_artifact_root_mismatch() {
        let dir = std::env::temp_dir().join(format!("seg_root_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let on_disk = [2u8; 32];
        let expected = [1u8; 32];
        let path = dir.join(format!("{}.c6", hex_encode(&on_disk)));
        fs::write(&path, b"seg").unwrap();
        let err = check_segment_artifact_root(&path, &expected, "f.txt", 0).unwrap_err();
        assert!(matches!(
            err,
            CarbonadoError::SegmentBaoRootMismatch {
                rel_path,
                chunk_index: 0
            } if rel_path == "f.txt"
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(not(feature = "ots"))]
    #[test]
    fn decode_directory_require_ots_without_feature() {
        let index = FilepackManifest {
            version: FILEPACK_MANIFEST_VERSION,
            format_level: FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
            catalog_bao_root: [0u8; 32],
            catalog_ots_proof: None,
            entries: vec![],
        };
        let rkyv = index.into_bytes().expect("rkyv");
        let payload = build_adamantine_payload(&rkyv, &[]).expect("payload");
        let adam = encode_adamantine(
            &payload,
            ADAMANTINE_CARBONADO_FMT_PUBLIC,
            ADAMANTINE_FLAG_REQUIRE_OTS,
        );
        let (encoded, _) = encode(
            &[0u8; 32],
            &adam,
            FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
            None,
        )
        .unwrap();
        let header = Header::try_from(&encoded[..Header::LEN]).unwrap();
        let root = *header.hash.as_bytes();
        let dir = std::env::temp_dir().join(format!("ots_feat_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let catalog = dir.join(format!("{}.adam.c14", hex_encode(&root)));
        fs::write(&catalog, &encoded).unwrap();
        let out = dir.join("out");
        let err = decode_directory(&[0u8; 32], &catalog, &out).unwrap_err();
        assert!(matches!(err, CarbonadoError::OtsFeatureRequired));
        let _ = fs::remove_dir_all(&dir);
    }
}
