//! BIP39 mnemonic persistence and Carbonado master-key derivation for the CLI.
//!
//! Stored mnemonics live at [`mnemonic_path`] (override with `CARBONADO_MNEMONIC_PATH`).
//! Plaintext on disk with mode `0600` on Unix — no encryption in this layer.
//!
//! First encrypted encode without `--master` auto-generates a 24-word mnemonic here unless one
//! already exists (`ensure_mnemonic`).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use bip39::{Language, Mnemonic};
use carbonado::crypto::derive_subkey;

const BIP39_MASTER_LABEL: &str = "bip39-master";

/// Default config-relative filename for the persisted English BIP39 mnemonic.
pub const MNEMONIC_FILENAME: &str = "mnemonic";

/// Default word count for auto-generated mnemonics.
pub const DEFAULT_AUTO_MNEMONIC_WORDS: usize = 24;

/// Result of first-time mnemonic creation during an encrypt operation.
pub struct MnemonicInitNotice {
    pub path: PathBuf,
    pub mnemonic: Mnemonic,
}

/// Resolve the on-disk path for the persisted mnemonic.
///
/// Precedence: `CARBONADO_MNEMONIC_PATH` → XDG-style config dir (`directories` crate).
pub fn mnemonic_path() -> PathBuf {
    if let Ok(p) = std::env::var("CARBONADO_MNEMONIC_PATH") {
        return PathBuf::from(p);
    }
    let proj = directories::ProjectDirs::from("com", "bitmask-stack", "carbonado")
        .expect("home directory required for default mnemonic path");
    proj.config_dir().join(MNEMONIC_FILENAME)
}

pub fn mnemonic_exists() -> bool {
    mnemonic_path().is_file()
}

/// Generate a new English BIP39 mnemonic (`word_count` must be 12, 15, 18, 21, or 24).
pub fn generate_mnemonic(word_count: usize) -> Result<Mnemonic, String> {
    validate_word_count(word_count)?;
    Mnemonic::generate_in(Language::English, word_count).map_err(|e| e.to_string())
}

/// Parse and validate an English BIP39 mnemonic phrase.
pub fn parse_mnemonic(words: &[String]) -> Result<Mnemonic, String> {
    if words.is_empty() {
        return Err("mnemonic must contain at least one word".into());
    }
    let phrase = words.join(" ");
    Mnemonic::parse_in(Language::English, &phrase).map_err(|e| e.to_string())
}

/// Create and persist a mnemonic when none exists (used before first encrypted encode).
pub fn ensure_mnemonic() -> Result<Option<MnemonicInitNotice>, String> {
    if mnemonic_exists() {
        return Ok(None);
    }
    let mnemonic = generate_mnemonic(DEFAULT_AUTO_MNEMONIC_WORDS)?;
    let path = save_mnemonic(&mnemonic, false)?;
    Ok(Some(MnemonicInitNotice { path, mnemonic }))
}

/// Write mnemonic to [`mnemonic_path`] (fails if file exists unless `force`).
pub fn save_mnemonic(mnemonic: &Mnemonic, force: bool) -> Result<PathBuf, String> {
    let path = mnemonic_path();
    if path.exists() && !force {
        return Err(format!(
            "mnemonic already exists at {}; use --force to overwrite or `carbonado key import`",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let phrase = mnemonic.to_string();
    write_mnemonic_file(&path, &phrase)?;
    Ok(path)
}

/// Load persisted mnemonic from disk.
pub fn load_mnemonic() -> Result<Mnemonic, String> {
    let path = mnemonic_path();
    let raw = fs::read_to_string(&path)
        .map_err(|e| format!("failed to read mnemonic at {}: {e}", path.display()))?;
    let phrase = raw.trim();
    if phrase.is_empty() {
        return Err(format!("mnemonic file at {} is empty", path.display()));
    }
    Mnemonic::parse_in(Language::English, phrase)
        .map_err(|e| format!("invalid mnemonic in {}: {e}", mnemonic_path().display()))
}

/// Derive the 32-byte Carbonado master key from a BIP39 mnemonic (empty BIP39 passphrase).
pub fn master_from_mnemonic(mnemonic: &Mnemonic) -> Result<[u8; 32], String> {
    let seed = mnemonic.to_seed("");
    master_from_bip39_seed(&seed)
}

/// Derive master from stored mnemonic file.
pub fn master_from_stored_mnemonic() -> Result<[u8; 32], String> {
    master_from_mnemonic(&load_mnemonic()?)
}

/// Domain-separated derivation: `HMAC-SHA512(bip39_seed, "carbonado-v2/bip39-master")` → first 32 bytes.
fn master_from_bip39_seed(seed: &[u8]) -> Result<[u8; 32], String> {
    let derived = derive_subkey(seed, BIP39_MASTER_LABEL).map_err(|e| e.to_string())?;
    let mut master = [0u8; 32];
    master.copy_from_slice(&derived[..32]);
    Ok(master)
}

fn validate_word_count(count: usize) -> Result<(), String> {
    match count {
        12 | 15 | 18 | 21 | 24 => Ok(()),
        _ => Err("word count must be 12, 15, 18, 21, or 24".into()),
    }
}

fn write_mnemonic_file(path: &Path, phrase: &str) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(phrase.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .map_err(|e| e.to_string())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_derivation_is_deterministic() {
        let mnemonic = Mnemonic::parse_in(
            Language::English,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let a = master_from_mnemonic(&mnemonic).unwrap();
        let b = master_from_mnemonic(&mnemonic).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, [0u8; 32]);
    }
}
