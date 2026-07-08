//! Minimal integration of Casey's filepack standard for multi-file archival.
//!
//! **Legacy / interop only.** New directory archives use rkyv
//! [`FilepackManifest`](crate::filepack_manifest::FilepackManifest) inside Adamantine 1.0
//! inboard catalogs (`{catalog_bao_root}.adam.c14` or `.adam.c15`). See
//! [`encode_directory`](crate::file::encode_directory).
//!
//! Does NOT depend on the filepack lib crate (per its "not for general consumption" note).
//! Uses blake3 for content hashes + ciborium for CBOR manifest (standard `manifest.filepack`).
//! Supports packing a directory to manifest + fingerprint (merkle-ish root over package map).
//! The resulting pack can be archived with Carbonado (manifest as catalog, files separately by their blake3).
//!
//! ## CBOR ↔ rkyv interop
//!
//! | Direction | API |
//! |-----------|-----|
//! | CBOR → rkyv | [`FilepackManifest::from_filepack_cbor`](crate::filepack_manifest::FilepackManifest::from_filepack_cbor) or [`from_packed`](crate::filepack_manifest::FilepackManifest::from_packed) |
//! | rkyv → CBOR | [`FilepackManifest::to_filepack_cbor`](crate::filepack_manifest::FilepackManifest::to_filepack_cbor) |
//! | Parse CBOR only | [`parse_filepack_cbor`](parse_filepack_cbor) |
//!
//! CBOR filepack carries only `hash` + `size` per file. Carbonado segment metadata (Bao roots,
//! `main_len`, sharding) is **not** in the standard package tree — supply a
//! [`FilepackSegmentMap`](crate::filepack_manifest::FilepackSegmentMap) on import keyed by `rel_path`.
//!
//! Export to CBOR preserves package paths and `content_blake3` hashes. Fields absent from the
//! filepack standard are dropped: per-segment refs, `format_level`, `catalog_bao_root`, `ots_proof`,
//! and plaintext `size` (exported as `0` because rkyv entries do not store it).
//!
//! Manifest shape (CBOR, convertible to the described JSON):
//! ```json
//! {
//!   "embedded": {},
//!   "package": { "pathcomp": { "hash": "hex", "size": 0 } | subdir map },
//!   "signatures": []
//! }
//! ```
//!
//! Fingerprint: blake3 hash over canonical CBOR of the "package" subtree (content addressing root).

use blake3::Hasher;
use ciborium::value::Value as CborValue;
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::error::CarbonadoError;
use crate::filepack_manifest::{MAX_FILEPACK_MANIFEST_ENTRIES, MAX_REL_PATH_LEN};

/// Maximum legacy CBOR filepack manifest bytes (aligns with [`MAX_RKYV_PAYLOAD_LEN`](crate::filepack_manifest::MAX_RKYV_PAYLOAD_LEN)).
pub const MAX_FILEPACK_CBOR_MANIFEST_LEN: usize = 16 * 1024 * 1024;

/// Maximum nesting depth of the CBOR `package` tree during flatten (DoS guard).
pub const MAX_FILEPACK_PACKAGE_DEPTH: usize = 256;

/// A file entry in package: hash + size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEntry {
    pub hash: [u8; 32], // raw blake3
    pub size: u64,
}

/// Recursive package tree: files or subdirs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PackageEntry {
    File(FileEntry),
    Dir(BTreeMap<String, PackageEntry>),
}

/// One flattened file row parsed from a CBOR filepack `package` tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilepackCborEntry {
    /// Relative path within the archived directory tree (POSIX separators).
    pub rel_path: String,
    /// BLAKE3 digest of the original file content.
    pub content_blake3: [u8; 32],
    /// Plaintext size from the CBOR `size` field.
    pub size: u64,
}

/// Pack result: serialized manifest.cbor bytes + fingerprint (root id).
pub struct Packed {
    pub manifest: Vec<u8>,
    pub fingerprint: [u8; 32],
    /// List of (relative_path, file_bytes) for separate archiving if desired.
    pub files: Vec<(String, Vec<u8>)>,
}

/// Compute blake3 of a file's content (used for filepack + naming).
pub fn hash_file_content(data: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(data);
    h.finalize().into()
}

/// Parse a CBOR filepack manifest and flatten the `package` tree to sorted entries.
///
/// Enforces [`MAX_FILEPACK_CBOR_MANIFEST_LEN`], [`MAX_FILEPACK_PACKAGE_DEPTH`],
/// [`MAX_FILEPACK_MANIFEST_ENTRIES`], and [`MAX_REL_PATH_LEN`] during flatten (before full
/// materialization of an unbounded tree).
///
/// **File vs directory heuristic:** a CBOR map containing a `"hash"` key is treated as a file
/// leaf (`hash` + `size`); otherwise the map is recursed as a subdirectory. Maps with both `hash`
/// and unknown extra keys fail with [`CarbonadoError::InvalidFilepackCbor`].
pub fn parse_filepack_cbor(manifest: &[u8]) -> Result<Vec<FilepackCborEntry>, CarbonadoError> {
    if manifest.len() > MAX_FILEPACK_CBOR_MANIFEST_LEN {
        return Err(CarbonadoError::InvalidFilepackCbor(format!(
            "CBOR manifest exceeds {MAX_FILEPACK_CBOR_MANIFEST_LEN} bytes"
        )));
    }
    let root = ciborium::de::from_reader(manifest)
        .map_err(|e| CarbonadoError::InvalidFilepackCbor(e.to_string()))?;
    let package = extract_top_level_map(&root, "package")?;
    let mut entries = Vec::new();
    flatten_package_map(package, "", &mut entries, 0)?;
    entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    Ok(entries)
}

/// Serialize a package tree to a full CBOR filepack manifest (embedded + package + signatures).
pub(crate) fn build_filepack_cbor_manifest(
    package: &BTreeMap<String, PackageEntry>,
) -> Result<Vec<u8>, CarbonadoError> {
    let pkg_cbor = package_to_cbor_value(package);
    let mut manifest_entries: Vec<(CborValue, CborValue)> = vec![
        (CborValue::Text("embedded".into()), CborValue::Map(vec![])),
        (CborValue::Text("package".into()), pkg_cbor),
        (
            CborValue::Text("signatures".into()),
            CborValue::Array(vec![]),
        ),
    ];
    manifest_entries.sort_by(|a, b| cbor_text_key(&a.0).cmp(&cbor_text_key(&b.0)));
    let manifest_val = CborValue::Map(manifest_entries);
    let mut manifest = vec![];
    ciborium::ser::into_writer(&manifest_val, &mut manifest)
        .map_err(|e| CarbonadoError::InvalidFilepackCbor(e.to_string()))?;
    Ok(manifest)
}

/// Build a nested package tree from sorted flat entries (hash + size per leaf).
pub(crate) fn entries_to_package_tree(
    entries: &[(String, [u8; 32], u64)],
) -> Result<BTreeMap<String, PackageEntry>, CarbonadoError> {
    let mut root = BTreeMap::new();
    for (rel_path, hash, size) in entries {
        let parts: Vec<&str> = rel_path.split('/').collect();
        if parts.is_empty() || parts.iter().any(|p| p.is_empty()) {
            return Err(CarbonadoError::InvalidFilepackCbor(format!(
                "invalid rel_path in package tree: {rel_path}"
            )));
        }
        let mut current = &mut root;
        for (idx, part) in parts.iter().enumerate() {
            let is_leaf = idx + 1 == parts.len();
            if is_leaf {
                if current.contains_key(*part) {
                    return Err(CarbonadoError::InvalidFilepackCbor(format!(
                        "duplicate package path: {rel_path}"
                    )));
                }
                current.insert(
                    (*part).to_string(),
                    PackageEntry::File(FileEntry {
                        hash: *hash,
                        size: *size,
                    }),
                );
            } else {
                let entry = current
                    .entry((*part).to_string())
                    .or_insert_with(|| PackageEntry::Dir(BTreeMap::new()));
                match entry {
                    PackageEntry::Dir(sub) => current = sub,
                    PackageEntry::File(_) => {
                        return Err(CarbonadoError::InvalidFilepackCbor(format!(
                            "path component conflicts with file: {rel_path}"
                        )));
                    }
                }
            }
        }
    }
    Ok(root)
}

/// Recursively walk dir, collect file contents+paths, build package tree, compute fingerprint, emit CBOR manifest.
pub fn pack_directory(dir: &Path) -> Result<Packed, CarbonadoError> {
    if !dir.is_dir() {
        return Err(CarbonadoError::StdIoError(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a directory for filepack",
        )));
    }
    let mut package: BTreeMap<String, PackageEntry> = BTreeMap::new();
    let mut files: Vec<(String, Vec<u8>)> = vec![];
    pack_dir_recursive(dir, Path::new(""), &mut package, &mut files)?;

    // Fingerprint = blake3 over canonical representation of package (for content addr root)
    let pkg_cbor = package_to_cbor_value(&package);
    let mut ser = vec![];
    ciborium::ser::into_writer(&pkg_cbor, &mut ser)
        .map_err(|e| CarbonadoError::InvalidFilepackCbor(e.to_string()))?;
    let mut h = Hasher::new();
    h.update(&ser);
    let fp: [u8; 32] = h.finalize().into();

    let manifest = build_filepack_cbor_manifest(&package)?;

    Ok(Packed {
        manifest,
        fingerprint: fp,
        files,
    })
}

fn pack_dir_recursive(
    base: &Path,
    rel: &Path,
    package: &mut BTreeMap<String, PackageEntry>,
    files: &mut Vec<(String, Vec<u8>)>,
) -> Result<(), CarbonadoError> {
    for entry in fs::read_dir(base).map_err(CarbonadoError::StdIoError)? {
        let entry = entry.map_err(CarbonadoError::StdIoError)?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "." || name == ".." || name.contains('/') || name.contains('\\') {
            continue; // per filepack path rules
        }
        let p = entry.path();
        let child_rel = if rel.as_os_str().is_empty() {
            PathBuf::from(&name)
        } else {
            rel.join(&name)
        };
        if p.is_dir() {
            let mut sub: BTreeMap<String, PackageEntry> = BTreeMap::new();
            pack_dir_recursive(&p, &child_rel, &mut sub, files)?;
            package.insert(name, PackageEntry::Dir(sub));
        } else if p.is_file() {
            let mut data = vec![];
            let mut f = fs::File::open(&p).map_err(CarbonadoError::StdIoError)?;
            f.read_to_end(&mut data)
                .map_err(CarbonadoError::StdIoError)?;
            let h = hash_file_content(&data);
            let size = data.len() as u64;
            package.insert(
                name.clone(),
                PackageEntry::File(FileEntry { hash: h, size }),
            );
            files.push((child_rel.to_string_lossy().replace('\\', "/"), data));
        }
    }
    Ok(())
}

fn flatten_package_map(
    map: &CborValue,
    prefix: &str,
    out: &mut Vec<FilepackCborEntry>,
    depth: usize,
) -> Result<(), CarbonadoError> {
    if depth > MAX_FILEPACK_PACKAGE_DEPTH {
        return Err(CarbonadoError::InvalidFilepackCbor(format!(
            "package tree depth exceeds maximum {MAX_FILEPACK_PACKAGE_DEPTH}"
        )));
    }
    let entries = cbor_map_entries(map)?;
    for (key, value) in entries {
        if out.len() >= MAX_FILEPACK_MANIFEST_ENTRIES {
            return Err(CarbonadoError::InvalidFilepackCbor(format!(
                "entry count exceeds maximum {MAX_FILEPACK_MANIFEST_ENTRIES}"
            )));
        }
        let name = cbor_text_key(key).ok_or_else(|| {
            CarbonadoError::InvalidFilepackCbor("package map keys must be text".into())
        })?;
        if name.is_empty() || name.contains('/') || name.contains('\\') {
            return Err(CarbonadoError::InvalidFilepackCbor(format!(
                "invalid package path component: {name}"
            )));
        }
        let rel_path = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        if rel_path.len() > MAX_REL_PATH_LEN {
            return Err(CarbonadoError::InvalidFilepackCbor(format!(
                "rel_path exceeds {MAX_REL_PATH_LEN} bytes"
            )));
        }
        match value {
            CborValue::Map(m) if is_file_entry_map(m) => {
                let file = parse_file_entry_map(m)?;
                out.push(FilepackCborEntry {
                    rel_path,
                    content_blake3: file.hash,
                    size: file.size,
                });
            }
            CborValue::Map(m) => {
                flatten_package_map(&CborValue::Map(m.clone()), &rel_path, out, depth + 1)?
            }
            other => {
                return Err(CarbonadoError::InvalidFilepackCbor(format!(
                    "unexpected package entry type at {rel_path}: {other:?}"
                )));
            }
        }
    }
    Ok(())
}

fn is_file_entry_map(map: &[(CborValue, CborValue)]) -> bool {
    map.iter().any(|(k, _)| cbor_text_key(k) == Some("hash"))
}

fn parse_file_entry_map(map: &[(CborValue, CborValue)]) -> Result<FileEntry, CarbonadoError> {
    let mut hash: Option<[u8; 32]> = None;
    let mut size: Option<u64> = None;
    for (key, value) in map {
        match cbor_text_key(key) {
            Some("hash") => {
                let hex = cbor_text_value(value).ok_or_else(|| {
                    CarbonadoError::InvalidFilepackCbor("file hash must be hex text".into())
                })?;
                hash = Some(hex::decode32(hex)?);
            }
            Some("size") => {
                size = Some(cbor_u64_value(value).ok_or_else(|| {
                    CarbonadoError::InvalidFilepackCbor("file size must be integer".into())
                })?);
            }
            Some(other) => {
                return Err(CarbonadoError::InvalidFilepackCbor(format!(
                    "unknown file entry field: {other}"
                )));
            }
            None => {
                return Err(CarbonadoError::InvalidFilepackCbor(
                    "file entry keys must be text".into(),
                ));
            }
        }
    }
    Ok(FileEntry {
        hash: hash
            .ok_or_else(|| CarbonadoError::InvalidFilepackCbor("file entry missing hash".into()))?,
        size: size
            .ok_or_else(|| CarbonadoError::InvalidFilepackCbor("file entry missing size".into()))?,
    })
}

fn extract_top_level_map<'a>(
    root: &'a CborValue,
    field: &str,
) -> Result<&'a CborValue, CarbonadoError> {
    let entries = cbor_map_entries(root)?;
    for (key, value) in entries {
        if cbor_text_key(key) == Some(field) {
            return Ok(value);
        }
    }
    Err(CarbonadoError::InvalidFilepackCbor(format!(
        "manifest missing {field}"
    )))
}

fn cbor_map_entries(value: &CborValue) -> Result<&[(CborValue, CborValue)], CarbonadoError> {
    match value {
        CborValue::Map(entries) => Ok(entries.as_slice()),
        other => Err(CarbonadoError::InvalidFilepackCbor(format!(
            "expected CBOR map, got {other:?}"
        ))),
    }
}

fn cbor_text_key(value: &CborValue) -> Option<&str> {
    match value {
        CborValue::Text(s) => Some(s.as_str()),
        _ => None,
    }
}

fn cbor_text_value(value: &CborValue) -> Option<&str> {
    cbor_text_key(value)
}

fn cbor_u64_value(value: &CborValue) -> Option<u64> {
    match value {
        CborValue::Integer(i) => u64::try_from(*i).ok(),
        _ => None,
    }
}

fn package_to_cbor_value(pkg: &BTreeMap<String, PackageEntry>) -> CborValue {
    let mut entries = vec![];
    for (k, v) in pkg {
        let val = match v {
            PackageEntry::File(fe) => {
                let m = vec![
                    (
                        CborValue::Text("hash".into()),
                        CborValue::Text(hex::encode(fe.hash)),
                    ),
                    (
                        CborValue::Text("size".into()),
                        CborValue::Integer(fe.size.into()),
                    ),
                ];
                CborValue::Map(m)
            }
            PackageEntry::Dir(sub) => package_to_cbor_value(sub),
        };
        entries.push((CborValue::Text(k.clone()), val));
    }
    CborValue::Map(entries)
}

mod hex {
    use crate::error::CarbonadoError;

    pub fn encode(bytes: [u8; 32]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn decode32(s: &str) -> Result<[u8; 32], CarbonadoError> {
        if s.len() != 64 {
            return Err(CarbonadoError::InvalidFilepackCbor(format!(
                "hash hex must be 64 characters, got {}",
                s.len()
            )));
        }
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = from_hex_digit(chunk.first().copied())?;
            let lo = from_hex_digit(chunk.get(1).copied())?;
            out[i] = (hi << 4) | lo;
        }
        Ok(out)
    }

    fn from_hex_digit(b: Option<u8>) -> Result<u8, CarbonadoError> {
        let b =
            b.ok_or_else(|| CarbonadoError::InvalidFilepackCbor("truncated hash hex".into()))?;
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(CarbonadoError::InvalidFilepackCbor(format!(
                "invalid hex digit: {b}"
            ))),
        }
    }
}

pub fn fingerprint_to_hex(fp: &[u8; 32]) -> String {
    hex::encode(*fp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_hash_hex() -> String {
        "0".repeat(64)
    }

    fn file_leaf_cbor() -> CborValue {
        CborValue::Map(vec![
            (
                CborValue::Text("hash".into()),
                CborValue::Text(zero_hash_hex()),
            ),
            (CborValue::Text("size".into()), CborValue::Integer(1.into())),
        ])
    }

    fn package_map_with_leaf(name: &str) -> CborValue {
        CborValue::Map(vec![(CborValue::Text(name.into()), file_leaf_cbor())])
    }

    fn manifest_with_package(package: CborValue) -> Vec<u8> {
        let manifest = CborValue::Map(vec![
            (CborValue::Text("embedded".into()), CborValue::Map(vec![])),
            (CborValue::Text("package".into()), package),
            (
                CborValue::Text("signatures".into()),
                CborValue::Array(vec![]),
            ),
        ]);
        let mut out = vec![];
        ciborium::ser::into_writer(&manifest, &mut out).expect("serialize");
        out
    }

    #[test]
    fn is_file_entry_map_canonical_leaf() {
        let m = match file_leaf_cbor() {
            CborValue::Map(m) => m,
            _ => panic!("expected map"),
        };
        assert!(is_file_entry_map(&m));
    }

    #[test]
    fn is_file_entry_map_nested_dir_without_hash() {
        let dir = CborValue::Map(vec![(
            CborValue::Text("child.txt".into()),
            file_leaf_cbor(),
        )]);
        let m = match dir {
            CborValue::Map(m) => m,
            _ => panic!("expected map"),
        };
        assert!(!is_file_entry_map(&m));
    }

    #[test]
    fn parse_rejects_map_with_hash_and_unknown_field() {
        let package = CborValue::Map(vec![(
            CborValue::Text("a.txt".into()),
            CborValue::Map(vec![
                (
                    CborValue::Text("hash".into()),
                    CborValue::Text(zero_hash_hex()),
                ),
                (CborValue::Text("size".into()), CborValue::Integer(1.into())),
                (
                    CborValue::Text("extra".into()),
                    CborValue::Text("nope".into()),
                ),
            ]),
        )]);
        let manifest = manifest_with_package(package);
        let err = parse_filepack_cbor(&manifest).unwrap_err();
        assert!(
            matches!(err, CarbonadoError::InvalidFilepackCbor(ref m) if m.contains("unknown file entry field")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_oversized_cbor_input() {
        let oversized = vec![0u8; MAX_FILEPACK_CBOR_MANIFEST_LEN + 1];
        let err = parse_filepack_cbor(&oversized).unwrap_err();
        assert!(
            matches!(err, CarbonadoError::InvalidFilepackCbor(ref m) if m.contains("exceeds")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_excessive_package_depth() {
        let mut inner = file_leaf_cbor();
        // Need one more directory level than allowed so flatten recurses with depth 257.
        for i in 0..=MAX_FILEPACK_PACKAGE_DEPTH + 1 {
            inner = CborValue::Map(vec![(CborValue::Text(format!("d{i}")), inner)]);
        }
        let mut out = vec![];
        let err = flatten_package_map(&inner, "", &mut out, 0).unwrap_err();
        assert!(
            matches!(err, CarbonadoError::InvalidFilepackCbor(ref m) if m.contains("depth exceeds")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_excessive_entry_count_during_flatten() {
        let mut package_entries = vec![];
        for i in 0..=MAX_FILEPACK_MANIFEST_ENTRIES {
            package_entries.push((CborValue::Text(format!("f{i}")), file_leaf_cbor()));
        }
        let manifest = manifest_with_package(CborValue::Map(package_entries));
        let err = parse_filepack_cbor(&manifest).unwrap_err();
        assert!(
            matches!(err, CarbonadoError::InvalidFilepackCbor(ref m) if m.contains("entry count exceeds")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_oversized_rel_path_during_flatten() {
        let long = "a".repeat(MAX_REL_PATH_LEN + 1);
        let manifest = manifest_with_package(package_map_with_leaf(&long));
        let err = parse_filepack_cbor(&manifest).unwrap_err();
        assert!(
            matches!(err, CarbonadoError::InvalidFilepackCbor(ref m) if m.contains("rel_path exceeds")),
            "got {err:?}"
        );
    }

    #[test]
    fn parse_pack_directory_manifest() {
        let samples = Path::new("tests/samples");
        if !samples.exists() {
            return;
        }
        let packed = pack_directory(samples).expect("pack_directory");
        let parsed = parse_filepack_cbor(&packed.manifest).expect("parse");
        assert!(!parsed.is_empty());
        for (rel, size) in parsed.iter().map(|e| (e.rel_path.as_str(), e.size)) {
            assert!(packed
                .files
                .iter()
                .any(|(p, data)| p == rel && data.len() as u64 == size));
        }
    }

    #[test]
    fn malformed_cbor_errors() {
        let err = parse_filepack_cbor(b"not-cbor").unwrap_err();
        assert!(matches!(err, CarbonadoError::InvalidFilepackCbor(_)));
    }
}
