//! rkyv [`FilepackManifest`] schema for Adamantine 1.0 directory catalogs.
//!
//! This is the canonical manifest format for recursive directory archives.
//! Legacy CBOR [`filepack`](crate::filepack) remains for **interop only** — canonical on-disk
//! wire is rkyv inside Adamantine 1.0 (`ADAMANTINE10\n`).
//!
//! ## CBOR interop (Phase 4)
//!
//! | Direction | API |
//! |-----------|-----|
//! | CBOR → rkyv | [`from_filepack_cbor`](FilepackManifest::from_filepack_cbor), [`from_packed`](FilepackManifest::from_packed) |
//! | rkyv → CBOR | [`to_filepack_cbor`](FilepackManifest::to_filepack_cbor) |
//!
//! CBOR filepack only carries `hash` + `size` per file. Supply a [`FilepackSegmentMap`] keyed by
//! `rel_path` when importing so Carbonado segment refs (Bao root, `main_len`, `chunk_index`) can
//! be attached. Export drops segment sharding, `format_level`, `catalog_bao_root`, `ots_proof`,
//! and plaintext `size` (written as `0`).
//!
//! Each [`FilepackEntry`] references one or more per-file outboard segments via
//! [`SegmentRef`] (sorted by `chunk_index`, contiguous `0..N-1`).
//! `content_blake3` hashes the original plaintext file bytes.
//! `ots_proof` carries optional OpenTimestamps attestations for the file's Bao root binding.
//!
//! `catalog_bao_root` is carried in the [`FilepackManifest`] API and bound from the
//! `{root}.adam.c{N}` filename on decode (decimal N = format level; the rkyv wire body omits it).

use std::collections::BTreeMap;

use rkyv::rancor::Error as RkyvError;
use rkyv::{Archive, Deserialize, Serialize};

use crate::constants::{Format, FEC_K, FEC_M};
use crate::directory::format_policy::validate_segment_format_for_catalog;
use crate::error::CarbonadoError;
use crate::filepack::{self, FilepackCborEntry, Packed};
use crate::utils::calc_padding_len;

/// FilepackManifest wire schema version (v2).
pub const FILEPACK_MANIFEST_VERSION: u32 = 2;

/// Public directory archive format level (c14 = 0x0E).
pub const FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC: u8 = 0x0E;

/// Encrypted directory archive format level (c15 = 0x0F).
pub const FILEPACK_MANIFEST_FORMAT_LEVEL_ENCRYPTED: u8 = 0x0F;

/// Back-compat alias for public c14 catalogs.
pub const FILEPACK_MANIFEST_FORMAT_LEVEL: u8 = FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC;

/// Maximum file entries in a directory catalog (DoS guard).
pub const MAX_FILEPACK_MANIFEST_ENTRIES: usize = 100_000;

/// Maximum bytes per `rel_path` string.
pub const MAX_REL_PATH_LEN: usize = 4096;

/// Maximum `ots_proof` blob size.
pub const MAX_OTS_PROOF_LEN: usize = 65_536;

/// Maximum rkyv `FilepackManifestWire` payload bytes inside Adamantine (DoS guard).
pub const MAX_RKYV_PAYLOAD_LEN: usize = 16 * 1024 * 1024;

/// Maximum outboard segments per file entry (DoS guard).
pub const MAX_SEGMENTS_PER_ENTRY: usize = 10_000;

/// Maximum total segment refs across all entries (DoS guard for bundle validation).
pub const MAX_TOTAL_SEGMENT_REFS: usize = 1_000_000;

/// Maximum bare segment main bytes (DoS guard; aligned with bundle caps).
pub const MAX_SEGMENT_MAIN_LEN: u64 = 256 * 1024 * 1024;

/// Reference to one bare segment main shard for a file entry.
#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct SegmentRef {
    /// Keyed Bao root of this segment main (`{root}.c{N}`, decimal format suffix).
    pub segment_bao_root: [u8; 32],
    /// Shard index within the file (0 for single-segment files).
    pub chunk_index: u32,
    /// Length of the bare main artifact for this segment.
    pub main_len: u64,
    /// Byte offset of this segment's verification outboard blob in the Adamantine payload bundle.
    pub verification_outboard_offset: u32,
    /// Length of this segment's verification outboard blob in the Adamantine payload bundle.
    pub verification_outboard_len: u32,
    /// Byte offset of this segment's FEC parity blob in the Adamantine payload bundle (0 when absent).
    pub fec_parity_offset: u32,
    /// Length of this segment's FEC parity blob in the Adamantine payload bundle (0 when absent).
    pub fec_parity_len: u32,
}

/// A single file entry in a directory catalog.
#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct FilepackEntry {
    /// Relative path within the archived directory tree (POSIX separators).
    pub rel_path: String,
    /// BLAKE3 digest of the original file content (pre-Carbonado).
    pub content_blake3: [u8; 32],
    /// Carbonado format for this file's segment mains (c12/c14 public or c13/c15 encrypted).
    pub segment_format: u8,
    /// Segment references (sorted by `chunk_index`, contiguous from 0).
    pub segments: Vec<SegmentRef>,
    /// Optional OpenTimestamps proof bytes for the file content Bao binding.
    pub ots_proof: Option<Vec<u8>>,
}

/// rkyv wire body (catalog root is bound after inboard encode; see [`FilepackManifest`]).
#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(derive(Debug, PartialEq, Eq))]
struct FilepackManifestWire {
    pub version: u32,
    /// Catalog Carbonado format only (c14 public or c15 encrypted).
    pub format_level: u8,
    pub entries: Vec<FilepackEntry>,
}

/// Carbonado segment refs keyed by `rel_path` for CBOR filepack import.
///
/// CBOR filepack manifests do not encode Bao roots or shard indices. When converting
/// [`from_filepack_cbor`](FilepackManifest::from_filepack_cbor), every flattened package path
/// must have a corresponding entry here (typically produced by [`encode_directory`](crate::file::encode_directory)
/// or an equivalent segment-encoding walk).
///
/// ## `insert` semantics
///
/// [`insert`](Self::insert) **overwrites** any existing entry for the same `rel_path` (no merge,
/// no error). Segment slices are not validated at insert time; invalid refs (unsorted
/// `chunk_index`, gaps, empty list) surface as [`CarbonadoError::InvalidFilepackManifest`] when
/// [`from_filepack_cbor`](FilepackManifest::from_filepack_cbor) calls [`validate`](FilepackManifest::validate).
///
/// ## Typical workflow
///
/// ```no_run
/// use carbonado::file::{encode_directory, DirectoryArchive};
/// use carbonado::filepack::{pack_directory, Packed};
/// use carbonado::filepack_manifest::{FilepackManifest, FilepackSegmentMap};
///
/// # fn example(master: &[u8; 32], src: &std::path::Path, enc: &std::path::Path) -> Result<(), carbonado::error::CarbonadoError> {
/// let archive: DirectoryArchive = encode_directory(master, src, enc)?;
/// let packed: Packed = pack_directory(src)?;
/// // Load rkyv manifest from catalog (see tests/filepack_interop.rs), then:
/// # let encoded_entries: Vec<carbonado::filepack_manifest::FilepackEntry> = vec![];
/// let segment_map = FilepackSegmentMap::from_manifest_entries(&encoded_entries);
/// let imported = FilepackManifest::from_filepack_cbor(
///     &packed.manifest,
///     &segment_map,
///     0x0E,
///     archive.catalog_bao_root,
/// )?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilepackSegmentMap {
    by_path: BTreeMap<String, Vec<SegmentRef>>,
}

impl FilepackSegmentMap {
    /// Empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert segment refs for one `rel_path` (overwrites any prior entry for that path).
    pub fn insert(&mut self, rel_path: impl Into<String>, segments: Vec<SegmentRef>) {
        self.by_path.insert(rel_path.into(), segments);
    }

    /// Lookup segment refs for a path.
    pub fn segments_for(&self, rel_path: &str) -> Option<&[SegmentRef]> {
        self.by_path.get(rel_path).map(Vec::as_slice)
    }

    /// Build a map from an existing rkyv manifest (e.g. after `encode_directory`).
    pub fn from_manifest_entries(entries: &[FilepackEntry]) -> Self {
        let mut map = Self::new();
        for entry in entries {
            map.insert(entry.rel_path.clone(), entry.segments.clone());
        }
        map
    }
}

/// Directory catalog manifest (Adamantine payload rkyv body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilepackManifest {
    /// FilepackManifest schema version (must be [`FILEPACK_MANIFEST_VERSION`]).
    pub version: u32,
    /// Catalog Carbonado format only (c14 public or c15 encrypted).
    pub format_level: u8,
    /// Bao root of this catalog's `.adam.c14` / `.adam.c15` artifact (must match filename prefix).
    pub catalog_bao_root: [u8; 32],
    /// Optional OpenTimestamps proof for the catalog Bao root.
    pub catalog_ots_proof: Option<Vec<u8>>,
    /// Per-file segment entries (sorted by `rel_path` for determinism).
    pub entries: Vec<FilepackEntry>,
}

impl FilepackManifest {
    fn into_wire(self) -> FilepackManifestWire {
        FilepackManifestWire {
            version: self.version,
            format_level: self.format_level,
            entries: self.entries,
        }
    }

    fn from_wire(catalog_bao_root: [u8; 32], wire: FilepackManifestWire) -> Self {
        Self {
            version: wire.version,
            format_level: wire.format_level,
            catalog_bao_root,
            catalog_ots_proof: None,
            entries: wire.entries,
        }
    }
}

impl FilepackManifest {
    /// Serialize the wire body (entries + version; catalog root is bound via Adamantine+outboard).
    ///
    /// Prefer [`into_bytes`](Self::into_bytes) on the encode path to avoid cloning `entries`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CarbonadoError> {
        let wire = FilepackManifestWire {
            version: self.version,
            format_level: self.format_level,
            entries: self.entries.clone(),
        };
        Self::wire_to_bytes(&wire)
    }

    /// Serialize by moving `entries` (encode path; avoids cloning the entry vec).
    pub fn into_bytes(self) -> Result<Vec<u8>, CarbonadoError> {
        Self::wire_to_bytes(&self.into_wire())
    }

    fn wire_to_bytes(wire: &FilepackManifestWire) -> Result<Vec<u8>, CarbonadoError> {
        let bytes = rkyv::to_bytes::<RkyvError>(wire)
            .map_err(|e| CarbonadoError::InvalidFilepackManifest(e.to_string()))?;
        Ok(bytes.into_vec())
    }

    /// Deserialize wire body; `catalog_bao_root` is supplied from the `.adam.cXX` filename on decode.
    pub fn from_bytes_with_root(
        bytes: &[u8],
        catalog_bao_root: [u8; 32],
    ) -> Result<Self, CarbonadoError> {
        if bytes.len() > MAX_RKYV_PAYLOAD_LEN {
            return Err(CarbonadoError::InvalidFilepackManifest(format!(
                "rkyv payload exceeds {MAX_RKYV_PAYLOAD_LEN} bytes"
            )));
        }
        Self::check_archived_wire_limits(bytes)?;
        let wire: FilepackManifestWire = rkyv::from_bytes::<FilepackManifestWire, RkyvError>(bytes)
            .map_err(|e| CarbonadoError::InvalidFilepackManifest(e.to_string()))?;
        let index = Self::from_wire(catalog_bao_root, wire);
        index.validate()?;
        Ok(index)
    }

    /// Pre-deserialize limits on archived layout (entry count, string/proof sizes).
    fn check_archived_wire_limits(bytes: &[u8]) -> Result<(), CarbonadoError> {
        let archived = rkyv::access::<ArchivedFilepackManifestWire, RkyvError>(bytes)
            .map_err(|e| CarbonadoError::InvalidFilepackManifest(e.to_string()))?;
        if archived.entries.len() > MAX_FILEPACK_MANIFEST_ENTRIES {
            return Err(CarbonadoError::InvalidFilepackManifest(format!(
                "entry count exceeds maximum {MAX_FILEPACK_MANIFEST_ENTRIES}"
            )));
        }
        let catalog_encrypted = archived.format_level & 1 != 0;
        for entry in archived.entries.iter() {
            if entry.rel_path.len() > MAX_REL_PATH_LEN {
                return Err(CarbonadoError::InvalidFilepackManifest(format!(
                    "rel_path exceeds {MAX_REL_PATH_LEN} bytes"
                )));
            }
            if entry.segments.len() > MAX_SEGMENTS_PER_ENTRY {
                return Err(CarbonadoError::InvalidFilepackManifest(format!(
                    "segment count exceeds maximum {MAX_SEGMENTS_PER_ENTRY}"
                )));
            }
            if let Some(proof) = entry.ots_proof.as_ref() {
                if proof.len() > MAX_OTS_PROOF_LEN {
                    return Err(CarbonadoError::InvalidFilepackManifest(format!(
                        "ots_proof exceeds {MAX_OTS_PROOF_LEN} bytes"
                    )));
                }
            }
            validate_segment_format_for_catalog(entry.segment_format, catalog_encrypted).map_err(
                |e| match e {
                    CarbonadoError::SegmentFormatMismatch(msg) => {
                        CarbonadoError::InvalidFilepackManifest(msg)
                    }
                    other => other,
                },
            )?;
        }
        Ok(())
    }

    /// Deserialize and validate rkyv bytes into a `FilepackManifest` (bytecheck on decode).
    ///
    /// For directory catalogs, prefer [`from_bytes_with_root`](Self::from_bytes_with_root) so
    /// `catalog_bao_root` matches the outer `.adam.cXX` artifact name.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CarbonadoError> {
        Self::from_bytes_with_root(bytes, [0u8; 32])
    }

    /// Validate a relative path component string (no `..`, absolute paths, or oversize).
    pub fn validate_rel_path(rel: &str) -> Result<(), CarbonadoError> {
        if rel.is_empty() {
            return Err(CarbonadoError::InvalidFilepackManifest(
                "empty rel_path".into(),
            ));
        }
        if rel.len() > MAX_REL_PATH_LEN {
            return Err(CarbonadoError::InvalidFilepackManifest(format!(
                "rel_path exceeds {MAX_REL_PATH_LEN} bytes"
            )));
        }
        if rel.contains('\\') {
            return Err(CarbonadoError::InvalidFilepackManifest(
                "rel_path must use forward slashes".into(),
            ));
        }
        if rel.starts_with('/') || rel.starts_with('\\') {
            return Err(CarbonadoError::InvalidFilepackManifest(
                "rel_path must be relative".into(),
            ));
        }
        if Path::new(rel).is_absolute() {
            return Err(CarbonadoError::InvalidFilepackManifest(
                "rel_path must be relative".into(),
            ));
        }
        for component in rel.split('/') {
            if component == ".." {
                return Err(CarbonadoError::InvalidFilepackManifest(
                    "rel_path must not contain '..' components".into(),
                ));
            }
        }
        Ok(())
    }

    /// Validate segment refs: sorted by chunk_index, contiguous 0..N-1, non-empty.
    pub fn validate_segments(segments: &[SegmentRef]) -> Result<(), CarbonadoError> {
        if segments.is_empty() {
            return Err(CarbonadoError::InvalidFilepackManifest(
                "entry must have at least one segment".into(),
            ));
        }
        if segments.len() > MAX_SEGMENTS_PER_ENTRY {
            return Err(CarbonadoError::InvalidFilepackManifest(format!(
                "segment count exceeds maximum {MAX_SEGMENTS_PER_ENTRY}"
            )));
        }
        for window in segments.windows(2) {
            if window[0].chunk_index >= window[1].chunk_index {
                return Err(CarbonadoError::InvalidFilepackManifest(
                    "segments must be strictly sorted by chunk_index".into(),
                ));
            }
        }
        for (expected, seg) in segments.iter().enumerate() {
            if seg.chunk_index != expected as u32 {
                return Err(CarbonadoError::InvalidFilepackManifest(format!(
                    "segments must be contiguous from 0; expected chunk_index {expected}, got {}",
                    seg.chunk_index
                )));
            }
        }
        Ok(())
    }

    /// Semantic validation beyond bytecheck structural checks.
    pub fn validate(&self) -> Result<(), CarbonadoError> {
        if self.version != FILEPACK_MANIFEST_VERSION {
            return Err(CarbonadoError::InvalidFilepackManifest(format!(
                "unsupported version {}",
                self.version
            )));
        }
        if self.format_level != FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC
            && self.format_level != FILEPACK_MANIFEST_FORMAT_LEVEL_ENCRYPTED
        {
            return Err(CarbonadoError::InvalidFilepackManifest(format!(
                "catalog format_level must be c14 or c15, got 0x{:02x}",
                self.format_level
            )));
        }
        let catalog_encrypted = self.format_level & 1 != 0;
        if let Some(proof) = &self.catalog_ots_proof {
            if proof.len() > MAX_OTS_PROOF_LEN {
                return Err(CarbonadoError::InvalidFilepackManifest(format!(
                    "catalog_ots_proof exceeds {MAX_OTS_PROOF_LEN} bytes"
                )));
            }
        }
        if self.entries.len() > MAX_FILEPACK_MANIFEST_ENTRIES {
            return Err(CarbonadoError::InvalidFilepackManifest(format!(
                "entry count exceeds maximum {MAX_FILEPACK_MANIFEST_ENTRIES}"
            )));
        }
        let mut prev: Option<&str> = None;
        for entry in &self.entries {
            Self::validate_rel_path(&entry.rel_path)?;
            validate_segment_format_for_catalog(entry.segment_format, catalog_encrypted).map_err(
                |e| match e {
                    CarbonadoError::SegmentFormatMismatch(msg) => {
                        CarbonadoError::InvalidFilepackManifest(msg)
                    }
                    other => other,
                },
            )?;
            Self::validate_segments(&entry.segments)?;
            let seg_fmt = Format::from(entry.segment_format);
            for seg in &entry.segments {
                validate_segment_bundle_semantics(seg_fmt, seg, &entry.rel_path)?;
            }
            if let Some(proof) = &entry.ots_proof {
                if proof.len() > MAX_OTS_PROOF_LEN {
                    return Err(CarbonadoError::InvalidFilepackManifest(format!(
                        "ots_proof exceeds {MAX_OTS_PROOF_LEN} bytes"
                    )));
                }
            }
            if let Some(p) = prev {
                if entry.rel_path.as_str() <= p {
                    return Err(CarbonadoError::InvalidFilepackManifest(
                        "entries must be strictly sorted by rel_path".into(),
                    ));
                }
            }
            prev = Some(entry.rel_path.as_str());
        }
        Ok(())
    }

    /// Validate bundle offsets (verification + FEC parity) against decoded bundle length.
    pub fn validate_bao_bundle_refs(&self, bundle_len: usize) -> Result<(), CarbonadoError> {
        let mut ranges: Vec<(u32, u32, String)> = Vec::new();
        let mut segment_ref_count = 0usize;

        for entry in &self.entries {
            let seg_fmt = Format::from(entry.segment_format);
            for seg in &entry.segments {
                segment_ref_count = segment_ref_count.saturating_add(1);
                if segment_ref_count > MAX_TOTAL_SEGMENT_REFS {
                    return Err(CarbonadoError::InvalidFilepackManifest(format!(
                        "segment ref count exceeds maximum {MAX_TOTAL_SEGMENT_REFS}"
                    )));
                }
                validate_segment_bundle_semantics(seg_fmt, seg, &entry.rel_path)?;

                let ver_end = seg
                    .verification_outboard_offset
                    .checked_add(seg.verification_outboard_len)
                    .ok_or_else(|| {
                        CarbonadoError::InvalidFilepackManifest(
                            "verification_outboard offset overflow".into(),
                        )
                    })?;
                if ver_end as usize > bundle_len {
                    return Err(CarbonadoError::InvalidFilepackManifest(format!(
                        "verification_outboard range for {} chunk {} exceeds bundle length {bundle_len}",
                        entry.rel_path, seg.chunk_index
                    )));
                }

                let fec_end = seg
                    .fec_parity_offset
                    .checked_add(seg.fec_parity_len)
                    .ok_or_else(|| {
                        CarbonadoError::InvalidFilepackManifest("fec_parity offset overflow".into())
                    })?;
                if fec_end as usize > bundle_len {
                    return Err(CarbonadoError::InvalidFilepackManifest(format!(
                        "fec_parity range for {} chunk {} exceeds bundle length {bundle_len}",
                        entry.rel_path, seg.chunk_index
                    )));
                }

                if seg.verification_outboard_len > 0 {
                    ranges.push((
                        seg.verification_outboard_offset,
                        ver_end,
                        format!(
                            "{} chunk {} verification_outboard",
                            entry.rel_path, seg.chunk_index
                        ),
                    ));
                }
                if seg.fec_parity_len > 0 {
                    ranges.push((
                        seg.fec_parity_offset,
                        fec_end,
                        format!("{} chunk {} fec_parity", entry.rel_path, seg.chunk_index),
                    ));
                }
            }
        }

        ranges.sort_by_key(|(off, _, _)| *off);
        let mut high_water: u32 = 0;
        let mut prev_label: Option<&str> = None;
        for (off, end, label) in &ranges {
            if *off < high_water {
                return Err(CarbonadoError::InvalidFilepackManifest(format!(
                    "bundle ranges overlap: {} vs {}",
                    prev_label.unwrap_or("(prior range)"),
                    label
                )));
            }
            high_water = *end;
            prev_label = Some(label.as_str());
        }
        Ok(())
    }

    /// Import a legacy CBOR filepack manifest into the rkyv schema.
    ///
    /// `segment_map` must supply Carbonado [`SegmentRef`] lists for every `rel_path` in the
    /// package tree — CBOR filepack only has content hash and plaintext size. The CBOR `size`
    /// field is **ignored** on import; segment bounds come from `FilepackSegmentMap` /
    /// [`SegmentRef::main_len`].
    ///
    /// `format_level` and `catalog_bao_root` are caller-supplied (not present in CBOR filepack).
    pub fn from_filepack_cbor(
        manifest: &[u8],
        segment_map: &FilepackSegmentMap,
        format_level: u8,
        catalog_bao_root: [u8; 32],
    ) -> Result<Self, CarbonadoError> {
        let flat = filepack::parse_filepack_cbor(manifest)?;
        Self::from_filepack_cbor_entries(&flat, segment_map, format_level, catalog_bao_root)
    }

    /// Import from a [`Packed`](crate::filepack::Packed) directory walk plus segment refs.
    pub fn from_packed(
        packed: &Packed,
        segment_map: &FilepackSegmentMap,
        format_level: u8,
        catalog_bao_root: [u8; 32],
    ) -> Result<Self, CarbonadoError> {
        Self::from_filepack_cbor(
            &packed.manifest,
            segment_map,
            format_level,
            catalog_bao_root,
        )
    }

    fn from_filepack_cbor_entries(
        flat: &[FilepackCborEntry],
        segment_map: &FilepackSegmentMap,
        format_level: u8,
        catalog_bao_root: [u8; 32],
    ) -> Result<Self, CarbonadoError> {
        if flat.len() > MAX_FILEPACK_MANIFEST_ENTRIES {
            return Err(CarbonadoError::InvalidFilepackCbor(format!(
                "entry count exceeds maximum {MAX_FILEPACK_MANIFEST_ENTRIES}"
            )));
        }
        let mut entries = Vec::with_capacity(flat.len());
        for row in flat {
            let segments = segment_map.segments_for(&row.rel_path).ok_or_else(|| {
                CarbonadoError::InvalidFilepackCbor(format!(
                    "missing segment refs for rel_path {}",
                    row.rel_path
                ))
            })?;
            let segment_format = segments
                .first()
                .map(|_| {
                    if format_level & 1 != 0 {
                        crate::directory::format_policy::SEGMENT_FORMAT_ENCRYPTED_COMPRESSED
                    } else {
                        crate::directory::format_policy::SEGMENT_FORMAT_PUBLIC_COMPRESSED
                    }
                })
                .unwrap_or_else(|| {
                    if format_level & 1 != 0 {
                        crate::directory::format_policy::SEGMENT_FORMAT_ENCRYPTED_COMPRESSED
                    } else {
                        crate::directory::format_policy::SEGMENT_FORMAT_PUBLIC_COMPRESSED
                    }
                });
            entries.push(FilepackEntry {
                rel_path: row.rel_path.clone(),
                content_blake3: row.content_blake3,
                segment_format,
                segments: segments.to_vec(),
                ots_proof: None,
            });
        }
        let manifest = Self {
            version: FILEPACK_MANIFEST_VERSION,
            format_level,
            catalog_bao_root,
            catalog_ots_proof: None,
            entries,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Export to legacy CBOR filepack for upstream / Casey interop.
    ///
    /// **Dropped on export** (not in standard filepack package tree):
    /// - per-segment Bao roots, `main_len`, and shard indices
    /// - `format_level`, `catalog_bao_root`, `version`
    /// - `ots_proof`
    /// - plaintext file `size` (written as `0`; rkyv entries do not store it)
    ///
    /// Package paths and `content_blake3` hashes are preserved.
    pub fn to_filepack_cbor(&self) -> Result<Vec<u8>, CarbonadoError> {
        self.validate()?;
        let flat: Vec<(String, [u8; 32], u64)> = self
            .entries
            .iter()
            .map(|e| (e.rel_path.clone(), e.content_blake3, 0))
            .collect();
        let package = filepack::entries_to_package_tree(&flat)?;
        filepack::build_filepack_cbor_manifest(&package)
    }
}

use std::path::Path;

/// Expected FEC parity sidecar length for a bare main of `main_len` bytes (0 when empty).
pub fn expected_fec_parity_len(main_len: u64) -> u32 {
    if main_len == 0 {
        return 0;
    }
    let (_, chunk_len) = calc_padding_len(main_len as usize);
    (FEC_M - FEC_K) as u32 * chunk_len
}

fn validate_segment_bundle_semantics(
    seg_fmt: Format,
    seg: &SegmentRef,
    rel_path: &str,
) -> Result<(), CarbonadoError> {
    if seg.main_len > MAX_SEGMENT_MAIN_LEN {
        return Err(CarbonadoError::InvalidFilepackManifest(format!(
            "main_len for {rel_path} chunk {} exceeds maximum {MAX_SEGMENT_MAIN_LEN}",
            seg.chunk_index
        )));
    }

    if seg_fmt.contains(Format::Fec) {
        if seg.main_len > 0 && seg.fec_parity_len == 0 {
            return Err(CarbonadoError::MissingFecParity);
        }
        if seg.main_len > 0 {
            let expected = expected_fec_parity_len(seg.main_len);
            if seg.fec_parity_len != expected {
                return Err(CarbonadoError::InvalidFilepackManifest(format!(
                    "fec_parity_len for {rel_path} chunk {} must be {expected} (encode geometry), got {}",
                    seg.chunk_index, seg.fec_parity_len
                )));
            }
        } else if seg.fec_parity_len != 0 {
            return Err(CarbonadoError::InvalidFilepackManifest(format!(
                "fec_parity present for {rel_path} chunk {} with zero main_len",
                seg.chunk_index
            )));
        }
    } else if seg.fec_parity_len != 0 {
        return Err(CarbonadoError::InvalidFilepackManifest(format!(
            "fec_parity present for {rel_path} chunk {} but segment format lacks FEC",
            seg.chunk_index
        )));
    }

    if seg.fec_parity_len > 0 {
        let expected_fec_off = seg
            .verification_outboard_offset
            .checked_add(seg.verification_outboard_len)
            .ok_or_else(|| {
                CarbonadoError::InvalidFilepackManifest(
                    "verification_outboard offset overflow".into(),
                )
            })?;
        if seg.fec_parity_offset != expected_fec_off {
            return Err(CarbonadoError::InvalidFilepackManifest(format!(
                "fec_parity_offset for {rel_path} chunk {} must follow verification_outboard contiguously",
                seg.chunk_index
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_segment_ref(main_len: u64, chunk_index: u32, root_byte: u8) -> SegmentRef {
        let ver_len = if main_len > 0 { 64 } else { 0 };
        let fec_len = expected_fec_parity_len(main_len);
        SegmentRef {
            segment_bao_root: [root_byte; 32],
            chunk_index,
            main_len,
            verification_outboard_offset: 0,
            verification_outboard_len: ver_len,
            fec_parity_offset: ver_len,
            fec_parity_len: fec_len,
        }
    }

    fn sample_manifest() -> FilepackManifest {
        FilepackManifest {
            version: FILEPACK_MANIFEST_VERSION,
            format_level: FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
            catalog_bao_root: [1u8; 32],
            catalog_ots_proof: None,
            entries: vec![FilepackEntry {
                rel_path: "a.txt".into(),
                content_blake3: [2u8; 32],
                segment_format: crate::directory::format_policy::SEGMENT_FORMAT_PUBLIC_COMPRESSED,
                segments: vec![sample_segment_ref(42, 0, 3)],
                ots_proof: None,
            }],
        }
    }

    #[test]
    fn filepack_manifest_roundtrip() {
        let manifest = sample_manifest();
        let bytes = manifest.to_bytes().expect("to_bytes");
        let decoded = FilepackManifest::from_bytes_with_root(&bytes, manifest.catalog_bao_root)
            .expect("from_bytes");
        assert_eq!(decoded, manifest);
    }

    #[test]
    fn filepack_manifest_multi_segment_roundtrip() {
        let mut manifest = sample_manifest();
        manifest.entries[0]
            .segments
            .push(sample_segment_ref(99, 1, 4));
        let bytes = manifest.to_bytes().expect("to_bytes");
        let decoded = FilepackManifest::from_bytes_with_root(&bytes, manifest.catalog_bao_root)
            .expect("from_bytes");
        assert_eq!(decoded, manifest);
    }

    #[test]
    fn malformed_rkyv_errors_no_panic() {
        let garbage = b"not-valid-rkyv-bytes";
        let err = FilepackManifest::from_bytes(garbage).unwrap_err();
        assert!(matches!(err, CarbonadoError::InvalidFilepackManifest(_)));
    }

    #[test]
    fn rejects_unsorted_entries() {
        let mut manifest = sample_manifest();
        manifest.entries.push(FilepackEntry {
            rel_path: "0.txt".into(),
            content_blake3: [0u8; 32],
            segment_format: crate::directory::format_policy::SEGMENT_FORMAT_PUBLIC_COMPRESSED,
            segments: vec![sample_segment_ref(1, 0, 0)],
            ots_proof: None,
        });
        let err = manifest.validate().unwrap_err();
        assert!(
            matches!(err, CarbonadoError::InvalidFilepackManifest(ref msg) if msg.contains("rel_path")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_non_contiguous_segments() {
        let mut manifest = sample_manifest();
        manifest.entries[0].segments.push(SegmentRef {
            segment_bao_root: [5u8; 32],
            chunk_index: 2,
            main_len: 10,
            verification_outboard_offset: 0,
            verification_outboard_len: 0,
            fec_parity_offset: 0,
            fec_parity_len: 0,
        });
        let err = manifest.validate().unwrap_err();
        assert!(
            matches!(err, CarbonadoError::InvalidFilepackManifest(ref msg) if msg.contains("contiguous")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_path_traversal_rel_path() {
        let err = FilepackManifest::validate_rel_path("../pwned").unwrap_err();
        assert!(
            matches!(err, CarbonadoError::InvalidFilepackManifest(ref msg) if msg.contains("..")),
            "got {err:?}"
        );
        let err = FilepackManifest::validate_rel_path("foo/../../etc/passwd").unwrap_err();
        assert!(
            matches!(err, CarbonadoError::InvalidFilepackManifest(ref msg) if msg.contains("..")),
            "got {err:?}"
        );
        let err = FilepackManifest::validate_rel_path("/etc/passwd").unwrap_err();
        assert!(
            matches!(err, CarbonadoError::InvalidFilepackManifest(ref msg) if msg.contains("relative")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_oversized_ots_proof() {
        let mut manifest = sample_manifest();
        manifest.entries[0].ots_proof = Some(vec![0u8; MAX_OTS_PROOF_LEN + 1]);
        let err = manifest.validate().unwrap_err();
        assert!(
            matches!(err, CarbonadoError::InvalidFilepackManifest(ref msg) if msg.contains("ots_proof")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_unsupported_format_level() {
        let mut manifest = sample_manifest();
        manifest.format_level = 16;
        let err = manifest.validate().unwrap_err();
        assert!(
            matches!(err, CarbonadoError::InvalidFilepackManifest(ref msg) if msg.contains("c14 or c15")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_non_catalog_format_level() {
        let mut manifest = sample_manifest();
        manifest.format_level = 6;
        let err = manifest.validate().unwrap_err();
        assert!(
            matches!(err, CarbonadoError::InvalidFilepackManifest(ref msg) if msg.contains("c14 or c15")),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_bao_bundle_refs_missing_fec_parity() {
        let manifest = FilepackManifest {
            version: FILEPACK_MANIFEST_VERSION,
            format_level: FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
            catalog_bao_root: [1u8; 32],
            catalog_ots_proof: None,
            entries: vec![FilepackEntry {
                rel_path: "a.txt".into(),
                content_blake3: [2u8; 32],
                segment_format: crate::directory::format_policy::SEGMENT_FORMAT_PUBLIC_COMPRESSED,
                segments: vec![SegmentRef {
                    segment_bao_root: [3u8; 32],
                    chunk_index: 0,
                    main_len: 42,
                    verification_outboard_offset: 0,
                    verification_outboard_len: 8,
                    fec_parity_offset: 0,
                    fec_parity_len: 0,
                }],
                ots_proof: None,
            }],
        };
        let err = manifest.validate_bao_bundle_refs(64).unwrap_err();
        assert!(
            matches!(err, CarbonadoError::MissingFecParity),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_bao_bundle_refs_rejects_cross_segment_overlap() {
        let fec_len = expected_fec_parity_len(100);
        let manifest = FilepackManifest {
            version: FILEPACK_MANIFEST_VERSION,
            format_level: FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
            catalog_bao_root: [1u8; 32],
            catalog_ots_proof: None,
            entries: vec![FilepackEntry {
                rel_path: "a.txt".into(),
                content_blake3: [2u8; 32],
                segment_format: crate::directory::format_policy::SEGMENT_FORMAT_PUBLIC_COMPRESSED,
                segments: vec![
                    SegmentRef {
                        segment_bao_root: [3u8; 32],
                        chunk_index: 0,
                        main_len: 100,
                        verification_outboard_offset: 0,
                        verification_outboard_len: 64,
                        fec_parity_offset: 64,
                        fec_parity_len: fec_len,
                    },
                    SegmentRef {
                        segment_bao_root: [4u8; 32],
                        chunk_index: 1,
                        main_len: 100,
                        verification_outboard_offset: 32,
                        verification_outboard_len: 64,
                        fec_parity_offset: 96,
                        fec_parity_len: fec_len,
                    },
                ],
                ots_proof: None,
            }],
        };
        let err = manifest.validate_bao_bundle_refs(1_000_000).unwrap_err();
        assert!(
            matches!(err, CarbonadoError::InvalidFilepackManifest(ref m) if m.contains("bundle ranges overlap")),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_bao_bundle_refs_scales_with_many_ranges() {
        let fec_len = expected_fec_parity_len(64);
        let ver_len = 32u32;
        let range_stride = ver_len + fec_len;
        let segment_count = 2000usize;
        let mut segments = Vec::with_capacity(segment_count);
        let mut bundle_cursor = 0u32;
        for i in 0..segment_count {
            let ver_off = bundle_cursor;
            bundle_cursor = bundle_cursor.saturating_add(ver_len);
            let fec_off = bundle_cursor;
            bundle_cursor = bundle_cursor.saturating_add(fec_len);
            segments.push(SegmentRef {
                segment_bao_root: [i as u8; 32],
                chunk_index: i as u32,
                main_len: 64,
                verification_outboard_offset: ver_off,
                verification_outboard_len: ver_len,
                fec_parity_offset: fec_off,
                fec_parity_len: fec_len,
            });
        }
        let manifest = FilepackManifest {
            version: FILEPACK_MANIFEST_VERSION,
            format_level: FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
            catalog_bao_root: [1u8; 32],
            catalog_ots_proof: None,
            entries: vec![FilepackEntry {
                rel_path: "many.txt".into(),
                content_blake3: [2u8; 32],
                segment_format: crate::directory::format_policy::SEGMENT_FORMAT_PUBLIC_COMPRESSED,
                segments,
                ots_proof: None,
            }],
        };
        let bundle_len = (segment_count as u32 * range_stride) as usize;
        manifest
            .validate_bao_bundle_refs(bundle_len)
            .unwrap_or_else(|e| panic!("many contiguous ranges must validate: {e:?}"));
    }

    #[test]
    fn validate_bao_bundle_refs_rejects_fec_geometry_mismatch() {
        let mut manifest = sample_manifest();
        manifest.entries[0].segments[0].fec_parity_len = 1;
        let err = manifest.validate_bao_bundle_refs(1_000_000).unwrap_err();
        assert!(
            matches!(err, CarbonadoError::InvalidFilepackManifest(ref m) if m.contains("fec_parity_len")),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_bao_bundle_refs_rejects_fec_on_non_fec_format() {
        let manifest = FilepackManifest {
            version: FILEPACK_MANIFEST_VERSION,
            format_level: FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
            catalog_bao_root: [1u8; 32],
            catalog_ots_proof: None,
            entries: vec![FilepackEntry {
                rel_path: "a.txt".into(),
                content_blake3: [2u8; 32],
                segment_format: 0x04,
                segments: vec![SegmentRef {
                    segment_bao_root: [3u8; 32],
                    chunk_index: 0,
                    main_len: 10,
                    verification_outboard_offset: 0,
                    verification_outboard_len: 8,
                    fec_parity_offset: 8,
                    fec_parity_len: 16,
                }],
                ots_proof: None,
            }],
        };
        let err = manifest.validate().unwrap_err();
        assert!(
            matches!(err, CarbonadoError::InvalidFilepackManifest(ref m) if m.contains("c4–c7")),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_accepts_zero_length_verification_outboard_for_nonempty_main() {
        let mut manifest = sample_manifest();
        manifest.entries[0].segments[0].verification_outboard_len = 0;
        manifest.entries[0].segments[0].fec_parity_offset = 0;
        manifest
            .validate()
            .expect("zero-length outboard is valid for small Bao trees");
    }

    #[test]
    fn decode_outboard_rejects_missing_verification_outboard() {
        use crate::decoding::decode_outboard;
        use crate::directory::format_policy::SEGMENT_FORMAT_PUBLIC_COMPRESSED;
        use crate::encoding::encode_outboard;

        let payload = b"payload";
        let oenc = encode_outboard(&[0u8; 32], payload, SEGMENT_FORMAT_PUBLIC_COMPRESSED)
            .expect("encode_outboard");
        let err = decode_outboard(
            &[0u8; 32],
            oenc.hash.as_bytes(),
            &oenc.main,
            None,
            oenc.fec_parity.as_deref(),
            oenc.info.padding_len,
            SEGMENT_FORMAT_PUBLIC_COMPRESSED,
        )
        .unwrap_err();
        assert!(
            matches!(err, CarbonadoError::MissingVerificationOutboard),
            "got {err:?}"
        );
    }

    #[test]
    fn encode_outboard_empty_verification_outboard_still_roundtrips() {
        use crate::decoding::decode_outboard;
        use crate::directory::format_policy::SEGMENT_FORMAT_PUBLIC_COMPRESSED;
        use crate::encoding::encode_outboard;

        let payload = b"payload";
        let oenc = encode_outboard(&[0u8; 32], payload, SEGMENT_FORMAT_PUBLIC_COMPRESSED)
            .expect("encode_outboard");
        let ver = oenc.verification_outboard.as_deref().expect("Some");
        assert_eq!(ver.len(), 0, "small payloads may have zero-length outboard");
        let decoded = decode_outboard(
            &[0u8; 32],
            oenc.hash.as_bytes(),
            &oenc.main,
            Some(ver),
            oenc.fec_parity.as_deref(),
            oenc.info.padding_len,
            SEGMENT_FORMAT_PUBLIC_COMPRESSED,
        )
        .expect("roundtrip");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn validate_accepts_zero_byte_segment_refs() {
        let manifest = FilepackManifest {
            version: FILEPACK_MANIFEST_VERSION,
            format_level: FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
            catalog_bao_root: [1u8; 32],
            catalog_ots_proof: None,
            entries: vec![FilepackEntry {
                rel_path: "empty.txt".into(),
                content_blake3: *blake3::hash(b"").as_bytes(),
                segment_format: crate::directory::format_policy::SEGMENT_FORMAT_PUBLIC_COMPRESSED,
                segments: vec![sample_segment_ref(0, 0, 5)],
                ots_proof: None,
            }],
        };
        manifest.validate().expect("zero-byte segment semantics");
    }

    #[test]
    fn rejects_oversized_rel_path() {
        let long = "a".repeat(MAX_REL_PATH_LEN + 1);
        let err = FilepackManifest::validate_rel_path(&long).unwrap_err();
        assert!(matches!(err, CarbonadoError::InvalidFilepackManifest(_)));
    }
}
