//! Link against Nix-built `libcarbonado` when `CARBONADO_LEAN_LIB` / `CARBONADO_LEAN_INCLUDE`
//! are set (or after `nix build .#libcarbonado` + env).
//!
//! ```bash
//! nix build .#libcarbonado -o result-libcarbonado
//! export CARBONADO_LEAN_LIB=$PWD/result-libcarbonado/lib
//! export CARBONADO_LEAN_INCLUDE=$PWD/result-libcarbonado/include
//! export LD_LIBRARY_PATH=$CARBONADO_LEAN_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
//! # Freeze allowlist (Phase 5 / G11): just test-lean-ci
//! cargo test -p carbonado --no-default-features --features "backend-lean,pqc,ots,cli"
//! ```
//!
//! Prefers the shared library (`libcarbonado.so`) produced by leanc (Lean runtime
//! already linked). Falls back to static `libcarbonado.a` when only the archive
//! is present (requires a full Lean link line — not the default path).
//!
//! With the `require-lib` feature (enabled by carbonado `backend-lean`), a missing
//! `CARBONADO_LEAN_LIB` or missing library file is a **hard build error** (fail-closed).

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=CARBONADO_LEAN_LIB");
    println!("cargo:rerun-if-env-changed=CARBONADO_LEAN_INCLUDE");

    let require_lib = env::var_os("CARGO_FEATURE_REQUIRE_LIB").is_some();
    let lib = env::var_os("CARBONADO_LEAN_LIB").map(PathBuf::from);
    let include = env::var_os("CARBONADO_LEAN_INCLUDE").map(PathBuf::from);

    if let Some(inc) = include {
        println!("cargo:include={}", inc.display());
    }

    if let Some(lib_dir) = lib {
        let so = lib_dir.join("libcarbonado.so");
        let dylib = lib_dir.join("libcarbonado.dylib");
        let archive = lib_dir.join("libcarbonado.a");
        if !so.exists() && !dylib.exists() && !archive.exists() {
            let msg = format!(
                "CARBONADO_LEAN_LIB={} has no libcarbonado.so/.dylib/.a — run: nix build .#libcarbonado -o result-libcarbonado",
                lib_dir.display()
            );
            if require_lib {
                panic!("{msg}");
            }
            println!("cargo:warning={msg}");
            return;
        }

        println!("cargo:rustc-link-search=native={}", lib_dir.display());

        if so.exists() || dylib.exists() {
            println!("cargo:rustc-link-lib=dylib=carbonado");
            // Runtime resolution for tests without installing into system paths.
            println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_dir.display());
        } else {
            println!("cargo:rustc-link-lib=static=carbonado");
            println!(
                "cargo:warning=libcarbonado shared object missing; linking static (may need Lean runtime libs)"
            );
        }
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=m");
        println!("cargo:rustc-link-lib=dl");
    } else if require_lib {
        panic!(
            "CARBONADO_LEAN_LIB unset while carbonado-sys/require-lib is enabled (backend-lean). \
             Build: nix build .#libcarbonado -o result-libcarbonado && \
             export CARBONADO_LEAN_LIB=$PWD/result-libcarbonado/lib \
             CARBONADO_LEAN_INCLUDE=$PWD/result-libcarbonado/include"
        );
    } else {
        // Allow standalone carbonado-sys docs/check without the AOT lib.
        println!(
            "cargo:warning=CARBONADO_LEAN_LIB unset; carbonado-sys will not link libcarbonado"
        );
    }
}
