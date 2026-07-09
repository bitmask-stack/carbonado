//! Link against Nix-built `libcarbonado` when `CARBONADO_LEAN_LIB` / `CARBONADO_LEAN_INCLUDE`
//! are set (or `OUT_DIR` sibling after `nix build .#libcarbonado` + env).
//!
//! ```bash
//! nix build .#libcarbonado
//! export CARBONADO_LEAN_LIB=$PWD/result/lib
//! export CARBONADO_LEAN_INCLUDE=$PWD/result/include
//! cargo test -p carbonado --features backend-lean
//! ```

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=CARBONADO_LEAN_LIB");
    println!("cargo:rerun-if-env-changed=CARBONADO_LEAN_INCLUDE");

    let lib = env::var_os("CARBONADO_LEAN_LIB").map(PathBuf::from);
    let include = env::var_os("CARBONADO_LEAN_INCLUDE").map(PathBuf::from);

    if let Some(inc) = include {
        println!("cargo:include={}", inc.display());
    }

    if let Some(lib_dir) = lib {
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
        println!("cargo:rustc-link-lib=static=carbonado");
        // Lean/zstd static archive may need system libs when full Lean objects are linked later.
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=m");
        println!("cargo:rustc-link-lib=dl");
    } else {
        // Allow crate to compile docs/check without the AOT lib; link fails at use if missing.
        println!("cargo:warning=CARBONADO_LEAN_LIB unset; carbonado-sys will not link libcarbonado");
    }
}
