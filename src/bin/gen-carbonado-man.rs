//! Generate roff man pages from the `carbonado` clap schema.
//!
//! Run via `just gen-man` or:
//! `cargo run --bin gen-carbonado-man --features cli,man-gen -- doc/man`

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use carbonado::cli_app::Cli;
use clap::CommandFactory;
use clap_mangen::Man;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("doc/man"));
    fs::create_dir_all(&out_dir)?;

    let root = Cli::command();
    let count = write_man_tree(&root, &out_dir, None)?;
    eprintln!("wrote {count} man page(s) to {}", out_dir.display());
    Ok(())
}

fn write_man_tree(
    cmd: &clap::Command,
    out_dir: &Path,
    prefix: Option<&str>,
) -> std::io::Result<usize> {
    let page_name = match prefix {
        None => cmd.get_name().to_string(),
        Some(p) => format!("{p}-{}", cmd.get_name()),
    };

    let page_name_static = leak_str(page_name);
    let mut page_cmd = cmd.clone();
    page_cmd = page_cmd.name(page_name_static);
    page_cmd = page_cmd.display_name(page_name_static);
    page_cmd = page_cmd.bin_name(page_name_static);

    let man = Man::new(page_cmd);
    let mut buffer = Vec::new();
    man.render(&mut buffer)?;
    while buffer.last() == Some(&0) {
        buffer.pop();
    }

    let path = out_dir.join(format!("{page_name_static}.1"));
    let mut file = fs::File::create(&path)?;
    file.write_all(&buffer)?;

    let mut count = 1;
    for sub in cmd.get_subcommands() {
        count += write_man_tree(sub, out_dir, Some(page_name_static))?;
    }
    Ok(count)
}

fn leak_str(value: String) -> &'static str {
    Box::leak(value.into_boxed_str())
}
