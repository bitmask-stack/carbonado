//! Carbonado CLI: unified single-file and directory archive encode/decode.
//!
//! ## Key material
//!
//! - `--master` accepts **64 hex characters** (32 bytes). Omitted → stored BIP39 seed or all-zero key
//!   (public formats only).
//! - First **encrypted encode** without `--master` auto-generates a 24-word BIP39 mnemonic, saves it
//!   in plaintext at `carbonado key path`, and prints a backup notice. Decode never auto-generates.
//! - Override or import with `carbonado key import`; regenerate with `carbonado key init --force`.
//! - Master key = first 32 bytes of `HMAC-SHA512(bip39_seed, "carbonado-v2/bip39-master")`.
//! - The binary does **not** zeroize derived keys or mnemonic strings after use.
//!
//! See [AGENTS.md §7.2](https://github.com/bitmask-stack/carbonado/blob/main/AGENTS.md#72-cli-key-material-handling-srcbincarbonadors)
//! and the Header Visibility model (§2, `header_mac` is a public authentication tag, not secret key material).

mod key_store;

use carbonado::cli_app::{Cli, Commands, KeyCommands};
use carbonado::constants::Format;

use carbonado::file::{
    DIRECTORY_ARCHIVE_FORMAT_ENCRYPTED, DirectoryEncodeOptions, EncodeToDirOptions,
    decode_directory, decode_stream, encode_directory_with_options, encode_to_dir,
};
use carbonado::paths::{
    ArchiveLayout, adamantine_sidecar_for_main, companion_main_for_adam_sidecar,
    detect_archive_layout, guess_format_from_filename, parse_bao_root_from_filename,
};
use carbonado::stream::ZstdEncode;
use carbonado::stream::decode::stream_decode_outboard_with_dict;
use clap::Parser;
use std::fs::{self, File};
use std::io::{Cursor, Read, Seek};
use std::path::{Path, PathBuf};

fn validate_format(format: u8) -> Result<(), Box<dyn std::error::Error>> {
    if format > 15 {
        return Err(format!("format must be 0-15; got {format}").into());
    }
    Ok(())
}

/// When to create or require a persisted BIP39 seed (see [`resolve_master_key`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MasterKeyPolicy {
    /// Public encode/decode: zero key unless a seed file already exists.
    Public,
    /// Encrypted encode: auto-generate seed on first use.
    Encrypt,
    /// Encrypted decode: require `--master` or existing seed; never auto-generate.
    Decrypt,
}

fn reject_zero_encrypted_master(
    format: u8,
    key: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    if (format & 1) != 0 && key.iter().all(|&b| b == 0) {
        return Err("encrypted format requires a non-zero master key".into());
    }
    Ok(())
}

fn hex_encode_slice(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn reject_bare_outboard_flags_on_headered(
    format: &Option<u8>,
    hash: &Option<String>,
    padding: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    if format.is_some() {
        return Err(
            "--format is for bare outboard decode only; headered inboard archives embed format in the file header"
                .into(),
        );
    }
    if hash.is_some() {
        return Err("--hash is for bare outboard decode only".into());
    }
    if padding != 0 {
        return Err("--padding is for bare outboard decode only".into());
    }
    Ok(())
}

fn zstd_from_cli(
    format: u8,
    zstd_level: Option<i32>,
    zstd_dict: Option<PathBuf>,
) -> Result<ZstdEncode, Box<dyn std::error::Error>> {
    let fmt = Format::from(format);
    let dict = match zstd_dict {
        Some(p) => Some(fs::read(p)?),
        None => None,
    };
    if fmt.contains(Format::Compression) && zstd_level.is_none() {
        return Err(
            "this format uses compression; pass --zstd-level (level is encoder input, not a default)"
                .into(),
        );
    }
    Ok(ZstdEncode {
        level: zstd_level,
        dict,
    })
}

fn parse_master_hex(hexs: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if hexs.len() != 64 {
        return Err("master must be 64 hex chars (32 bytes)".into());
    }
    let mut k = [0u8; 32];
    for (i, c) in hexs.as_bytes().chunks(2).enumerate() {
        let byte_str = std::str::from_utf8(c).map_err(|_| "invalid utf8 in master hex")?;
        k[i] = u8::from_str_radix(byte_str, 16).map_err(|_| "invalid hex in master")?;
    }
    Ok(k)
}

fn print_mnemonic_init_notice(notice: key_store::MnemonicInitNotice) {
    eprintln!(
        "Note: generated a new BIP39 mnemonic ({} words) and saved it to {}.",
        key_store::DEFAULT_AUTO_MNEMONIC_WORDS,
        notice.path.display()
    );
    eprintln!("Stored in plaintext (mode 0600 on Unix). Back it up with `carbonado key show`.");
    eprintln!("Mnemonic: {}", notice.mnemonic);
}

/// Resolve master key: `--master` hex overrides persisted seed; encrypt auto-inits when missing.
fn resolve_master_key(
    master: Option<String>,
    policy: MasterKeyPolicy,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if let Some(hexs) = master {
        return parse_master_hex(&hexs);
    }
    if key_store::mnemonic_exists() {
        return key_store::master_from_stored_mnemonic().map_err(Into::into);
    }
    match policy {
        MasterKeyPolicy::Public => Ok([0u8; 32]),
        MasterKeyPolicy::Encrypt => {
            if let Some(notice) = key_store::ensure_mnemonic().map_err(cli_string_err)? {
                print_mnemonic_init_notice(notice);
            }
            key_store::master_from_stored_mnemonic().map_err(Into::into)
        }
        MasterKeyPolicy::Decrypt => Err(
            "encrypted archive requires --master or a stored BIP39 seed; \
             use `carbonado key import` if you have the original mnemonic"
                .into(),
        ),
    }
}

fn master_policy_for_format(format: u8, encrypting: bool) -> MasterKeyPolicy {
    if (format & 1) == 0 {
        MasterKeyPolicy::Public
    } else if encrypting {
        MasterKeyPolicy::Encrypt
    } else {
        MasterKeyPolicy::Decrypt
    }
}

fn is_encrypted_adam_catalog(path: &Path) -> bool {
    guess_format_from_filename(path).is_some_and(|f| f & 1 != 0)
}

fn default_directory_output(input: &Path) -> PathBuf {
    let base = input
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| input.to_string_lossy().to_string());
    input.with_file_name(format!("{base}-archive"))
}

fn main() {
    if let Err(e) = run_cli() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn cli_string_err(message: String) -> Box<dyn std::error::Error> {
    message.into()
}

fn run_key_command(command: KeyCommands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        KeyCommands::Init { words, force } => {
            let mnemonic = key_store::generate_mnemonic(words).map_err(cli_string_err)?;
            let path = key_store::save_mnemonic(&mnemonic, force).map_err(cli_string_err)?;
            println!("mnemonic saved to {}", path.display());
            println!("{mnemonic}");
            eprintln!(
                "Warning: backup this mnemonic now. It is stored in plaintext (mode 0600 on Unix)."
            );
        }
        KeyCommands::Import { words, force } => {
            let mnemonic = key_store::parse_mnemonic(&words).map_err(cli_string_err)?;
            let path = key_store::save_mnemonic(&mnemonic, force).map_err(cli_string_err)?;
            println!("mnemonic imported to {}", path.display());
        }
        KeyCommands::Show => {
            let mnemonic = key_store::load_mnemonic().map_err(cli_string_err)?;
            println!("{mnemonic}");
        }
        KeyCommands::Path => {
            println!(
                "{}",
                key_store::mnemonic_path()
                    .map_err(cli_string_err)?
                    .display()
            );
        }
    }
    Ok(())
}

fn run_cli() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Key { command } => run_key_command(command),
        Commands::Encode {
            input,
            format,
            outboard,
            encrypted,
            zstd_level,
            zstd_dict,
            master,
            output,
        } => {
            if input.is_file() {
                validate_format(format)?;
                let outdir = output.unwrap_or_else(|| PathBuf::from("."));
                fs::create_dir_all(&outdir)?;
                let policy = master_policy_for_format(format, true);
                let master_key = resolve_master_key(master, policy)?;
                reject_zero_encrypted_master(format, &master_key)?;
                let plaintext = fs::read(&input)?;
                let zstd = zstd_from_cli(format, zstd_level, zstd_dict)?;
                let written = encode_to_dir(
                    &master_key,
                    &plaintext,
                    format,
                    &outdir,
                    EncodeToDirOptions { outboard, zstd },
                )?;
                println!("encoded: {}", written.main_path.display());
                if written.adam_path != written.main_path {
                    println!("  + adamantine: {}", written.adam_path.display());
                }
            } else if input.is_dir() {
                if outboard {
                    return Err("--outboard is for single-file encode only".into());
                }
                let outdir = output.unwrap_or_else(|| default_directory_output(&input));
                fs::create_dir_all(&outdir)?;
                let dir_fmt = if encrypted {
                    DIRECTORY_ARCHIVE_FORMAT_ENCRYPTED
                } else {
                    carbonado::file::DIRECTORY_ARCHIVE_FORMAT
                };
                let policy = master_policy_for_format(dir_fmt, true);
                let master_key = resolve_master_key(master, policy)?;
                reject_zero_encrypted_master(dir_fmt, &master_key)?;
                let zstd = zstd_from_cli(dir_fmt, zstd_level, zstd_dict)?;
                let options = DirectoryEncodeOptions {
                    encrypted,
                    zstd,
                    ..DirectoryEncodeOptions::default()
                };
                let archive = encode_directory_with_options(&master_key, &input, &outdir, options)?;
                let root_hex = hex_encode_slice(&archive.catalog_bao_root);
                println!(
                    "directory archived: {} entries, catalog {}.adam.c{dir_fmt}",
                    archive.entry_count, root_hex
                );
            } else {
                return Err(format!(
                    "input not found or not a file or directory: {}",
                    input.display()
                )
                .into());
            }
            Ok(())
        }
        Commands::Decode {
            input,
            master,
            output,
            hash,
            format,
            padding,
        } => {
            let layout = detect_archive_layout(&input)?;

            match layout {
                ArchiveLayout::InboardAdam { catalog } => {
                    let out_base = output.unwrap_or_else(|| PathBuf::from("recovered_dir"));
                    let policy = if is_encrypted_adam_catalog(&catalog) {
                        MasterKeyPolicy::Decrypt
                    } else {
                        MasterKeyPolicy::Public
                    };
                    let master_key = resolve_master_key(master, policy)?;
                    fs::create_dir_all(&out_base)?;
                    decode_directory(&master_key, &catalog, &out_base)?;
                    println!("decoded directory to {}", out_base.display());
                }
                ArchiveLayout::InboardHeadered { path } => {
                    reject_bare_outboard_flags_on_headered(&format, &hash, padding)?;
                    let out_base = output.unwrap_or_else(|| PathBuf::from("recovered.bin"));
                    let mut header_bytes = [0u8; carbonado::file::Header::LEN];
                    let mut input_f = File::open(&path)?;
                    input_f.read_exact(&mut header_bytes)?;
                    let header = carbonado::file::Header::try_from(&header_bytes[..])?;
                    let fmt = header.format.bits();
                    let policy = master_policy_for_format(fmt, false);
                    let master_key = resolve_master_key(master, policy)?;
                    reject_zero_encrypted_master(fmt, &master_key)?;
                    input_f.rewind()?;
                    let mut out_f = File::create(&out_base)?;
                    let (_header, _n) = decode_stream(&master_key, &mut input_f, &mut out_f)?;
                    println!("decoded to {}", out_base.display());
                }
                ArchiveLayout::OutboardBare { main } => {
                    let out_base = output.unwrap_or_else(|| PathBuf::from("recovered.bin"));
                    let fmt = format.or_else(|| guess_format_from_filename(&main));
                    let policy = fmt
                        .map(|f| master_policy_for_format(f, false))
                        .unwrap_or(MasterKeyPolicy::Public);
                    let master_key = resolve_master_key(master, policy)?;
                    do_decode_outboard_streaming(
                        &main,
                        &master_key,
                        &out_base,
                        hash,
                        format,
                        padding,
                    )?;
                    println!("decoded to {}", out_base.display());
                }
            }
            Ok(())
        }
    }
}

fn do_decode_outboard_streaming(
    input: &Path,
    master: &[u8; 32],
    out_base: &Path,
    hash: Option<String>,
    format: Option<u8>,
    padding: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let main_path = if companion_main_for_adam_sidecar(input).is_some_and(|p| p.is_file())
        && input
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.contains(".adam."))
    {
        companion_main_for_adam_sidecar(input).expect("companion main")
    } else {
        input.to_path_buf()
    };
    let mut main_f = File::open(&main_path)?;
    let adam_path = adamantine_sidecar_for_main(&main_path)
        .filter(|p| p.is_file())
        .or_else(|| {
            if input
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.contains(".adam."))
            {
                Some(input.to_path_buf())
            } else {
                None
            }
        });

    let (bao_ob, fec_p, dict) = if let Some(adam) = adam_path {
        let bytes = fs::read(&adam)?;
        let (payload, _hdr, _n) = carbonado::adamantine::decode_adamantine_prefix(&bytes)?;
        let (rkyv, bundle) = carbonado::split_adamantine_payload(&payload)?;
        let manifest = carbonado::FilepackManifest::from_bytes(&rkyv)?;
        let seg = manifest
            .entries
            .first()
            .and_then(|e| e.segments.first())
            .ok_or("Adamantine sidecar has no segment")?;
        let bao = carbonado::verification_slice_from_bundle(
            &bundle,
            seg.verification_outboard_offset,
            seg.verification_outboard_len,
        )?
        .to_vec();
        let fec = if seg.fec_parity_len > 0 {
            Some(
                carbonado::fec_slice_from_bundle(
                    &bundle,
                    seg.fec_parity_offset,
                    seg.fec_parity_len,
                )?
                .to_vec(),
            )
        } else {
            None
        };
        let dict = if seg.dict_len > 0 {
            Some(
                carbonado::dict_slice_from_bundle(&bundle, seg.dict_offset, seg.dict_len)?.to_vec(),
            )
        } else {
            None
        };
        (Some(bao), fec, dict)
    } else {
        (None, None, None)
    };

    let fmt = match format {
        Some(f) => {
            validate_format(f)?;
            f
        }
        None => guess_format_from_filename(&main_path).ok_or(
            "could not guess Carbonado format level from filename; provide --format (0-15)",
        )?,
    };

    let bao_hash = if let Some(hs) = &hash {
        parse_hash_hex(hs)?
    } else {
        parse_bao_root_from_filename(&main_path)
            .ok_or("could not parse valid 64-hex bao root from bare filename; provide --hash")?
    };

    let pad = if padding != 0 {
        padding
    } else if fec_p.is_some() {
        let len = main_f.metadata()?.len() as usize;
        carbonado::utils::calc_padding_len(len).0
    } else {
        0
    };

    let mut out_f = File::create(out_base)?;
    stream_decode_outboard_with_dict(
        master,
        &bao_hash,
        &mut main_f,
        bao_ob.map(Cursor::new),
        fec_p.map(Cursor::new),
        pad,
        fmt,
        None,
        &mut out_f,
        dict.as_deref(),
    )?;
    Ok(())
}

fn parse_hash_hex(hs: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if hs.len() != 64 {
        return Err("hash must be 64 hex chars".into());
    }
    let mut hb = [0u8; 32];
    for (i, c) in hs.as_bytes().chunks(2).enumerate() {
        let byte_str = std::str::from_utf8(c).map_err(|_| "invalid utf8 in --hash")?;
        hb[i] = u8::from_str_radix(byte_str, 16).map_err(|_| "invalid hex digit in --hash")?;
    }
    Ok(hb)
}
