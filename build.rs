//! Propagate libcarbonado rpath onto final binaries/tests (backend-lean).
//!
//! `carbonado-sys` sets `rustc-link-search` / `rustc-link-lib`, but `rustc-link-arg`
//! rpath from a dependency build script is not applied to dependents' final links.

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=CARBONADO_LEAN_LIB");
    println!("cargo:rerun-if-cfg=feature=\"backend-lean\"");

    let lean = env::var("CARGO_FEATURE_BACKEND_LEAN").is_ok();
    if !lean {
        return;
    }
    if let Ok(lib) = env::var("CARBONADO_LEAN_LIB") {
        let lib_dir = PathBuf::from(lib);
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_dir.display());
    }
}
