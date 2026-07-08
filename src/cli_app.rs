//! Clap command definitions for the `carbonado` binary.
//!
//! Kept in the library (behind the `cli` feature) so `gen-carbonado-man` and integration tests
//! share the same schema as the shipped binary. Implementation lives in `src/bin/carbonado/`.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Root CLI parser (`carbonado` binary).
#[derive(Parser)]
#[command(
    name = "carbonado",
    bin_name = "carbonado",
    version,
    about = "Apocalypse-resistant archival for files and directory trees",
    long_about = "Encode and decode Carbonado archives for single files or directory trees.\n\n\
                  KEY MATERIAL:\n  \
                  First encrypted encode auto-generates a BIP39 mnemonic (24 words), saved in \
                  plaintext at the path from `carbonado key path` (override: CARBONADO_MNEMONIC_PATH). \
                  Later encode/decode reuse it unless `--master` is given. Decode never auto-generates.\n\n\
                  ARTIFACTS:\n  \
                  Single-file default: inboard headered `{hash}.c{fmt:02x}` (format 14 → `.c0e`).\n  \
                  `--outboard`: bare main + optional `.out`/`.par` sidecars (single-file only).\n  \
                  Directory: inboard Adamantine 1.0 catalog `.adam.c14` (or `.adam.c15` with \
                  `--encrypted`) and heterogeneous bare segment mains (c4/c6 or c5/c7). Output \
                  defaults to `{input}-archive/`.\n\n\
                  See `carbonado <command> --help` for per-command options.",
    after_help = "EXAMPLES:\n  \
                  carbonado encode secret.bin --format 15\n  \
                  carbonado encode ./my-project --encrypted -o ./archive-out\n\n  \
                  carbonado encode myfile.bin --outboard --format 14\n  \
                  carbonado encode ./my-project -o ./archive-out\n  \
                  carbonado decode ./archive-out/<catalog>.adam.c14 -o ./restored\n  \
                  carbonado decode ./archive-out/<catalog>.adam.c15 -o ./restored\n\n  \
                  carbonado key path\n  \
                  carbonado key show"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

/// Top-level subcommands.
#[derive(Subcommand)]
pub enum Commands {
    /// Manage persisted BIP39 seed (plaintext; see `carbonado key path`)
    Key {
        #[command(subcommand)]
        command: KeyCommands,
    },
    /// Encode a file or directory into a Carbonado archive
    Encode {
        /// Input file or directory
        input: PathBuf,
        /// Format level 0–15 (default 14 = public verifiable; odd values = encrypted)
        #[arg(short, long, default_value_t = 14, value_name = "LEVEL")]
        format: u8,
        /// Single-file only: bare main + `.out`/`.par` sidecars (default single-file is inboard).
        #[arg(long)]
        outboard: bool,
        /// Directory only: encrypted catalog c15 and segment formats c5/c7 (auto-creates BIP39 seed if needed)
        #[arg(long)]
        encrypted: bool,
        /// 32-byte master key as 64 hex chars (overrides stored BIP39 seed)
        #[arg(long, value_name = "HEX")]
        master: Option<String>,
        /// Output directory [single-file default: . ; directory default: {input}-archive/]
        #[arg(short, long, value_name = "DIR")]
        output: Option<PathBuf>,
    },
    /// Decode a headered archive, bare outboard main, or Adamantine catalog
    Decode {
        /// Archive path: headered `.c{fmt:02x}`, bare outboard main, or `.adam.c{N}` directory catalog (decimal N)
        input: PathBuf,
        /// 32-byte master key as 64 hex chars (default: stored BIP39 seed from `carbonado key path`)
        #[arg(long, value_name = "HEX")]
        master: Option<String>,
        /// Output file or directory [default: recovered.bin or recovered_dir]
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Bare outboard only: Bao root as 64 hex chars (default: parsed from filename)
        #[arg(long, value_name = "HEX")]
        hash: Option<String>,
        /// Bare outboard only: format level 0–15 when not encoded in filename (rejected on headered inboard)
        #[arg(short, long, value_name = "LEVEL")]
        format: Option<u8>,
        /// Bare outboard only: FEC padding in bytes [default: 0, auto when `.par` sidecar present]
        #[arg(long, default_value = "0", value_name = "BYTES")]
        padding: u32,
        /// Bare outboard only: path to Bao `.out` sidecar [default: sibling of input]
        #[arg(long, value_name = "PATH")]
        bao_outboard: Option<PathBuf>,
        /// Bare outboard only: path to FEC `.par` sidecar [default: sibling of input]
        #[arg(long, value_name = "PATH")]
        fec_parity: Option<PathBuf>,
    },
}

/// `carbonado key` subcommands.
#[derive(Subcommand)]
pub enum KeyCommands {
    /// Generate a new English BIP39 mnemonic and save it (24 words by default)
    Init {
        /// Word count: 12, 15, 18, 21, or 24
        #[arg(long, default_value_t = 24)]
        words: usize,
        /// Overwrite existing mnemonic at `carbonado key path`
        #[arg(long)]
        force: bool,
    },
    /// Import an existing English BIP39 mnemonic (words as separate arguments)
    Import {
        /// Mnemonic words (e.g. `carbonado key import abandon abandon ... about`)
        #[arg(required = true)]
        words: Vec<String>,
        /// Overwrite existing mnemonic at `carbonado key path`
        #[arg(long)]
        force: bool,
    },
    /// Print the persisted mnemonic (sensitive — writes to stdout)
    Show,
    /// Print the path where the mnemonic is stored
    Path,
}
