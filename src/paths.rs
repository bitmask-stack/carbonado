//! On-disk artifact path helpers (format/hash parsing, archive layout detection).
//!
//! Used by the `carbonado` CLI and [`crate::file::decode_directory`]. Directory archives
//! use inboard `.adam.c14`/`.adam.c15` catalogs and decimal segment suffixes `c12`–`c15`;
//! single-file outboard uses hex `c{fmt:02x}` plus optional `.out`/`.par` sidecars.
//!
//! Decimal suffix parsing tries longest match first (`15` down to `0`) so e.g. `.c14` resolves
//! to format 14, not format 1 via a `.c1` prefix.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::{constants::MAGICNO, error::CarbonadoError};

/// Detected on-disk archive layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArchiveLayout {
    /// `{catalog_bao_root}.adam.c14` or `.adam.c15` inboard catalog (`CARBONADO20\n` prefix).
    InboardAdam { catalog: PathBuf },
    /// Headered inboard single-file archive starting with `CARBONADO20\n`.
    InboardHeadered { path: PathBuf },
    /// Bare outboard single-file main with sidecar siblings.
    OutboardBare { main: PathBuf },
}

/// Detect archive layout per plan §2.6:
/// 1. Outboard adam first when `.out`/`.par` siblings exist
/// 2. Inboard fallback when input starts with `CARBONADO20\n`
/// 3. `MissingCatalog` when segment mains/sidecars exist but `{catalog}.adam.cXX` missing
pub fn detect_archive_layout(input: &Path) -> Result<ArchiveLayout, CarbonadoError> {
    if input.is_file() {
        if is_adam_catalog(input) {
            if !starts_with_magic(input)? {
                return Err(CarbonadoError::DirectoryLayoutMismatch(
                    "directory catalog must be inboard headered .adam.c14 or .adam.c15".into(),
                ));
            }
            return Ok(ArchiveLayout::InboardAdam {
                catalog: input.to_path_buf(),
            });
        }
        return detect_single_file(input);
    }

    if input.is_dir() {
        return detect_directory_layout(input, None);
    }

    Err(CarbonadoError::NotADirectory(format!(
        "path not found or not a file/directory: {}",
        input.display()
    )))
}

fn detect_single_file(path: &Path) -> Result<ArchiveLayout, CarbonadoError> {
    if starts_with_magic(path)? {
        return Ok(ArchiveLayout::InboardHeadered {
            path: path.to_path_buf(),
        });
    }
    let out = sidecar_sibling_path(path, "out");
    let par = sidecar_sibling_path(path, "par");
    if out.exists() || par.exists() {
        return Ok(ArchiveLayout::OutboardBare {
            main: path.to_path_buf(),
        });
    }
    // Bare main without sidecar siblings: still outboard-capable when CLI supplies
    // explicit `--bao-outboard` / `--fec-parity` / `--hash` overrides.
    if guess_format_from_filename(path).is_some() {
        return Ok(ArchiveLayout::OutboardBare {
            main: path.to_path_buf(),
        });
    }
    Err(CarbonadoError::InvalidMagicNumber(format!(
        "unrecognized archive file: {}",
        path.display()
    )))
}

fn detect_directory_layout(
    dir: &Path,
    hint: Option<&Path>,
) -> Result<ArchiveLayout, CarbonadoError> {
    let mut adam_catalogs: Vec<PathBuf> = Vec::new();
    let mut segment_mains: Vec<PathBuf> = Vec::new();
    let mut has_orphan_sidecars = false;

    for entry in fs::read_dir(dir).map_err(CarbonadoError::StdIoError)? {
        let entry = entry.map_err(CarbonadoError::StdIoError)?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if is_adam_catalog_name(name) {
            adam_catalogs.push(path);
            continue;
        }
        if is_segment_main_name(name) {
            segment_mains.push(path);
            continue;
        }
        if (name.ends_with(".out") || name.ends_with(".par"))
            && (has_decimal_carbonado_suffix(name) || is_hex_carbonado_sidecar(name))
        {
            has_orphan_sidecars = true;
        }
    }

    adam_catalogs.sort();
    segment_mains.sort();

    if let Some(hint_path) = hint {
        if is_adam_catalog(hint_path) {
            if !starts_with_magic(hint_path)? {
                return Err(CarbonadoError::DirectoryLayoutMismatch(
                    "directory catalog must be inboard headered .adam.c14 or .adam.c15".into(),
                ));
            }
            return Ok(ArchiveLayout::InboardAdam {
                catalog: hint_path.to_path_buf(),
            });
        }
        if starts_with_magic(hint_path)? {
            return Ok(ArchiveLayout::InboardHeadered {
                path: hint_path.to_path_buf(),
            });
        }
    }

    for catalog in &adam_catalogs {
        if starts_with_magic(catalog)? {
            return Ok(ArchiveLayout::InboardAdam {
                catalog: catalog.clone(),
            });
        }
    }

    if !adam_catalogs.is_empty() {
        let has_segments = !segment_mains.is_empty() || has_orphan_sidecars;
        if has_segments {
            return Err(CarbonadoError::MissingCatalog(format!(
                "segment artifacts in {} but no inboard .adam.c14/.adam.c15 catalog",
                dir.display()
            )));
        }
        return Err(CarbonadoError::DirectoryLayoutMismatch(
            "directory catalog must be inboard headered .adam.c14 or .adam.c15".into(),
        ));
    }

    if !segment_mains.is_empty() || has_orphan_sidecars {
        return Err(CarbonadoError::MissingCatalog(format!(
            "segment artifacts in {} but no inboard .adam.c14/.adam.c15 catalog",
            dir.display()
        )));
    }

    if let Some(hint_path) = hint {
        return detect_single_file(hint_path);
    }

    Err(CarbonadoError::NotADirectory(format!(
        "no Carbonado archive found in {}",
        dir.display()
    )))
}

fn strip_decimal_adam_suffix(name: &str) -> Option<(&str, u8)> {
    for n in (0..=15).rev() {
        let suffix = format!(".adam.c{n}");
        if let Some(stem) = name.strip_suffix(&suffix) {
            return Some((stem, n));
        }
    }
    None
}

fn strip_decimal_suffix(name: &str) -> Option<(&str, u8)> {
    for n in (0..=15).rev() {
        let suffix = format!(".c{n}");
        if let Some(stem) = name.strip_suffix(&suffix) {
            return Some((stem, n));
        }
    }
    None
}

fn has_decimal_carbonado_suffix(name: &str) -> bool {
    strip_decimal_adam_suffix(name).is_some() || strip_decimal_suffix(name).is_some()
}

fn is_decimal_sidecar_stem(stem: &str) -> bool {
    strip_decimal_adam_suffix(stem).is_some() || strip_decimal_suffix(stem).is_some()
}

fn is_adam_catalog_name(name: &str) -> bool {
    strip_decimal_adam_suffix(name).is_some_and(|(_, fmt)| fmt == 14 || fmt == 15)
}

fn is_segment_main_name(name: &str) -> bool {
    if is_adam_catalog_name(name) || name.contains(".adam.c") {
        return false;
    }
    if let Some((stem, ext)) = name.rsplit_once('.') {
        if (ext == "out" || ext == "par") && is_decimal_sidecar_stem(stem) {
            return false;
        }
    }
    if strip_decimal_suffix(name).is_some() {
        return true;
    }
    if let Some((_, ext)) = name.rsplit_once('.') {
        if ext.len() == 3 && ext.starts_with('c') && ext[1..].chars().all(|c| c.is_ascii_hexdigit())
        {
            return !name.ends_with(".out") && !name.ends_with(".par");
        }
    }
    false
}

fn is_hex_carbonado_sidecar(name: &str) -> bool {
    name.rsplit_once('.').is_some_and(|(stem, ext)| {
        (ext == "out" || ext == "par")
            && stem.rsplit_once('.').is_some_and(|(_, sfx)| {
                sfx.len() == 3
                    && sfx.starts_with('c')
                    && sfx[1..].chars().all(|c| c.is_ascii_hexdigit())
            })
    })
}

fn starts_with_magic(path: &Path) -> Result<bool, CarbonadoError> {
    let mut f = fs::File::open(path).map_err(CarbonadoError::StdIoError)?;
    let mut buf = [0u8; MAGICNO.len()];
    let n = f.read(&mut buf).map_err(CarbonadoError::StdIoError)?;
    Ok(n >= MAGICNO.len() && &buf[..MAGICNO.len()] == MAGICNO)
}

/// Whether `path` names an Adamantine directory catalog (`.adam.c14` or `.adam.c15`).
pub fn is_adam_catalog(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(is_adam_catalog_name)
}

/// Sibling sidecar path for a main artifact: same directory, `{filename}.{ext}`.
pub fn sidecar_sibling_path(main: &Path, ext: &str) -> PathBuf {
    let stem = main
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_else(|| main.to_string_lossy());
    main.with_file_name(format!("{stem}.{ext}"))
}

/// Guess Carbonado format level from an on-disk artifact filename.
pub fn guess_format_from_filename(path: &Path) -> Option<u8> {
    let name = path.file_name()?.to_str()?;
    if let Some((_, fmt)) = strip_decimal_adam_suffix(name) {
        return Some(fmt);
    }
    if let Some((_, fmt)) = strip_decimal_suffix(name) {
        return Some(fmt);
    }
    let ext = name.rsplit_once('.')?.1;
    if ext.len() == 3 && ext.starts_with('c') {
        let hex_digits: String = ext[1..].chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if hex_digits.len() == 2 {
            return u8::from_str_radix(&hex_digits, 16).ok();
        }
    }
    None
}

/// Parse the 64-hex-char keyed Bao root prefix from an artifact filename.
pub fn parse_bao_root_from_filename(path: &Path) -> Option<[u8; 32]> {
    let name = path.file_name()?.to_str()?;
    let stem = carbonado_stem(name)?;
    if stem.len() != 64 || !stem.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    parse_hash_hex(stem).ok()
}

fn carbonado_stem(name: &str) -> Option<&str> {
    if let Some((stem, _)) = strip_decimal_adam_suffix(name) {
        return Some(stem);
    }
    if let Some((stem, _)) = strip_decimal_suffix(name) {
        return Some(stem);
    }
    name.rsplit_once('.').and_then(|(s, ext)| {
        if ext.len() == 3 && ext.starts_with('c') && ext[1..].chars().all(|c| c.is_ascii_hexdigit())
        {
            Some(s)
        } else {
            None
        }
    })
}

fn parse_hash_hex(hs: &str) -> Result<[u8; 32], ()> {
    if hs.len() != 64 {
        return Err(());
    }
    let mut hb = [0u8; 32];
    for (i, c) in hs.as_bytes().chunks(2).enumerate() {
        let byte_str = std::str::from_utf8(c).map_err(|_| ())?;
        hb[i] = u8::from_str_radix(byte_str, 16).map_err(|_| ())?;
    }
    Ok(hb)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tempdir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("carbonado_paths_{name}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("tempdir");
        dir
    }

    #[test]
    fn detect_inboard_adam_directory_layout() {
        let dir = tempdir("inboard_dir");
        let mut catalog_body = MAGICNO.to_vec();
        catalog_body.extend_from_slice(&[0u8; 64]);
        fs::write(dir.join("catalog.adam.c14"), &catalog_body).expect("catalog");
        fs::write(dir.join("seg.c14"), &catalog_body).expect("segment");
        let layout = detect_archive_layout(&dir).expect("detect");
        assert_eq!(
            layout,
            ArchiveLayout::InboardAdam {
                catalog: dir.join("catalog.adam.c14")
            }
        );
    }

    #[test]
    fn detect_inboard_adam_prefers_magic_over_stray_catalog_sidecars() {
        let dir = tempdir("inboard_sidecar");
        let mut catalog_body = MAGICNO.to_vec();
        catalog_body.extend_from_slice(&[0u8; 64]);
        let catalog = dir.join("catalog.adam.c14");
        fs::write(&catalog, &catalog_body).expect("catalog");
        fs::write(sidecar_sibling_path(&catalog, "out"), b"orphan-out").expect("orphan out");
        let layout = detect_archive_layout(&dir).expect("detect");
        assert_eq!(
            layout,
            ArchiveLayout::InboardAdam {
                catalog: catalog.clone()
            }
        );
    }

    #[test]
    fn detect_inboard_adam_catalog_file() {
        let dir = tempdir("inboard_adam");
        let path = dir.join("deadbeef.adam.c14");
        let mut body = MAGICNO.to_vec();
        body.extend_from_slice(&[0u8; 64]);
        fs::write(&path, &body).expect("write");
        let layout = detect_archive_layout(&path).expect("detect");
        assert_eq!(
            layout,
            ArchiveLayout::InboardAdam {
                catalog: path.clone()
            }
        );
    }

    #[test]
    fn detect_inboard_headered() {
        let dir = tempdir("inboard");
        let path = dir.join("archive.c0e");
        let mut body = MAGICNO.to_vec();
        body.extend_from_slice(&[0u8; 64]);
        fs::write(&path, &body).expect("write");
        let layout = detect_archive_layout(&path).expect("detect");
        assert_eq!(
            layout,
            ArchiveLayout::InboardHeadered { path: path.clone() }
        );
    }

    #[test]
    fn detect_missing_catalog_strict() {
        let dir = tempdir("orphan");
        fs::write(dir.join("abc.c14"), b"main").expect("main");
        fs::write(dir.join("abc.c14.out"), b"out").expect("out");
        let err = detect_archive_layout(&dir).unwrap_err();
        assert!(matches!(err, CarbonadoError::MissingCatalog(_)));
    }

    #[test]
    fn detect_decoy_adam_with_segments_strict_missing_catalog() {
        let dir = tempdir("decoy_adam");
        fs::write(dir.join("abc.c14"), b"main").expect("main");
        fs::write(dir.join("abc.c14.out"), b"out").expect("out");
        fs::write(dir.join("deadbeef.adam.c14"), b"").expect("decoy");
        let err = detect_archive_layout(&dir).unwrap_err();
        assert!(matches!(err, CarbonadoError::MissingCatalog(_)));
    }

    #[test]
    fn is_adam_catalog_only_c14_c15() {
        for n in 0..=15 {
            let adam = is_adam_catalog(Path::new(&format!("root.adam.c{n}")));
            if n == 14 || n == 15 {
                assert!(adam, "expected .adam.c{n} to be catalog");
            } else {
                assert!(!adam, "expected .adam.c{n} not to be catalog");
            }
            assert!(!is_adam_catalog(Path::new(&format!("root.c{n}"))));
        }
    }

    #[test]
    fn guess_format_decimal_directory_suffixes() {
        assert_eq!(
            guess_format_from_filename(Path::new("deadbeef.c14")),
            Some(14)
        );
        assert_ne!(
            guess_format_from_filename(Path::new("deadbeef.c14")),
            Some(1)
        );
        assert_eq!(
            guess_format_from_filename(Path::new("deadbeef.adam.c15")),
            Some(15)
        );
        assert_eq!(
            guess_format_from_filename(Path::new("deadbeef.c8")),
            Some(8)
        );
        assert_eq!(
            guess_format_from_filename(Path::new("deadbeef.adam.c4")),
            Some(4)
        );
        assert_eq!(
            guess_format_from_filename(Path::new("deadbeef.c0")),
            Some(0)
        );
    }

    #[test]
    fn parse_bao_root_decimal_suffixes() {
        let root_hex = "a".repeat(64);
        assert_eq!(
            parse_bao_root_from_filename(Path::new(&format!("{root_hex}.adam.c6"))),
            parse_bao_root_from_filename(Path::new(&format!("{root_hex}.c6")))
        );
    }

    #[test]
    fn sidecar_adam_catalog_nested() {
        let main = Path::new("/nested/archive/abc123deadbeef.adam.c14");
        assert_eq!(
            sidecar_sibling_path(main, "out"),
            PathBuf::from("/nested/archive/abc123deadbeef.adam.c14.out")
        );
        let enc = Path::new("/nested/archive/abc123deadbeef.adam.c15");
        assert_eq!(
            sidecar_sibling_path(enc, "par"),
            PathBuf::from("/nested/archive/abc123deadbeef.adam.c15.par")
        );
        let c8 = Path::new("/nested/archive/abc123deadbeef.adam.c8");
        assert_eq!(
            sidecar_sibling_path(c8, "out"),
            PathBuf::from("/nested/archive/abc123deadbeef.adam.c8.out")
        );
    }

    #[test]
    fn is_segment_main_decimal_c0_through_c15() {
        for n in 0..=15 {
            assert!(is_segment_main_name(&format!("seg.c{n}")));
            assert!(!is_segment_main_name(&format!("seg.c{n}.out")));
            assert!(!is_segment_main_name(&format!("seg.adam.c{n}")));
        }
    }
}
