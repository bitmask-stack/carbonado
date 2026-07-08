//! Minimal directory archival example using Adamantine 1.0 + rkyv FilepackManifest v2.
//!
//! Encode a directory (inboard catalog + heterogeneous bare segment mains):
//! ```bash
//! cargo run --example dir_archival -- encode tests/samples /tmp/carbonado-out
//! ```
//!
//! Decode the catalog:
//! ```bash
//! cargo run --example dir_archival -- decode /tmp/carbonado-out/<catalog>.adam.c14 /tmp/restored
//! # Catalog suffix is decimal c14 (public) or c15 (encrypted).
//! ```
//!
//! Single-file encode/decode uses the same `carbonado` binary (hex suffix `c0e` for format 14):
//! ```bash
//! cargo run --bin carbonado -- encode tests/samples/content.png --outboard --format 14
//! cargo run --bin carbonado -- decode <hash>.c0e --output recovered.bin
//! ```
//! Directory archives use decimal `.c{N}` / `.adam.c{N}` naming; see AGENTS.md §7.1.

use carbonado::file::{decode_directory, encode_directory};
use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "encode".into());
    let input = PathBuf::from(args.next().unwrap_or_else(|| "tests/samples".into()));
    let output = PathBuf::from(
        args.next()
            .unwrap_or_else(|| "/tmp/carbonado-dir-out".into()),
    );

    // Public c14 directory archives use a zero master key.
    let master = [0u8; 32];

    match cmd.as_str() {
        "encode" => {
            let archive = encode_directory(&master, &input, &output)?;
            let root_hex: String = archive
                .catalog_bao_root
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            println!(
                "encoded {} files; catalog {root_hex}.adam.c14",
                archive.entry_count
            );
        }
        "decode" => {
            decode_directory(&master, &input, &output)?;
            println!("restored directory to {}", output.display());
        }
        other => {
            eprintln!("usage: dir_archival [encode|decode] <input> [output] (got {other})");
        }
    }
    Ok(())
}
