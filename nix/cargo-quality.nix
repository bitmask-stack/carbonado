# Crane fmt / clippy / nextest for Carbonado.
#
# Never pass cargo --all-features. There is no Cargo Lean backend.
#
# Feature sets (must stay in sync with justfile comments and CI):
#   rust clippy/nextest extras: async,async-tokio,man-gen
#     (on top of default backend-rust,pqc,ots,cli,parallel)
#   rust serial FEC: --no-default-features --features backend-rust,pqc,ots,cli
{
  lib,
  pkgs,
  craneLib,
  rustToolchain,
  src,
  secp256k1Src,
  remote ? false,
}: let
  rustExtraFeatures = "async,async-tokio,man-gen";
  rustSerialFeatures = "backend-rust,pqc,ots,cli";

  remoteSystemFeatures = [
    "big-parallel"
    "surmount-remote"
  ];

  remoteAttrs = lib.optionalAttrs remote {
    preferLocalBuild = false;
    requiredSystemFeatures = remoteSystemFeatures;
  };

  pnameSuffix =
    if remote
    then "-quality"
    else "";

  # bitcoinpqc's CMake FetchContent clones bitcoin-core/secp256k1. The Nix
  # sandbox has no network, so point FetchContent at a pinned source.
  cmakeWithSecp = pkgs.writeShellScriptBin "cmake" ''
    case "''${1:-}" in
      --build|--install|--help|-E|--version)
        exec ${pkgs.cmake}/bin/cmake "$@"
        ;;
    esac
    exec ${pkgs.cmake}/bin/cmake \
      -DFETCHCONTENT_SOURCE_DIR_SECP256K1=${secp256k1Src} \
      -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
      "$@"
  '';

  # zstd-sys 2.0.16 build.rs uses pkg-config when the *presence* of
  # ZSTD_SYS_USE_PKG_CONFIG is Some (including the string "0") or when the
  # crate feature `pkg-config` is on. Host cargo leaves the var unset and
  # compiles bundled zstd 1.5.7. Do not put nixpkgs zstd or pkg-config on
  # this compile PATH (that is how zstd-sys would pick system libzstd).
  # buildDepsOnly must see the same hook so it does not cache a pkg-config
  # libzstd.a into cargoArtifacts.
  forceBundledZstdHook = pkgs.makeSetupHook {name = "carbonado-force-bundled-zstd";} (
    pkgs.writeText "carbonado-force-bundled-zstd.sh" ''
      unset ZSTD_SYS_USE_PKG_CONFIG
      unset PKG_CONFIG PKG_CONFIG_PATH PKG_CONFIG_LIBDIR PKG_CONFIG_SYSROOT_DIR
    ''
  );

  nativeBuildInputs = [
    cmakeWithSecp
    pkgs.rustPlatform.bindgenHook
    forceBundledZstdHook
  ];

  cargoJobsFromCores = ''
    cargoJobs="''${NIX_BUILD_CORES:-32}"
    case "$cargoJobs" in
      "" | *[!0-9]*) cargoJobs=32 ;;
    esac
    if [ "$cargoJobs" -gt 32 ]; then
      cargoJobs=32
    fi
    if [ "$cargoJobs" -lt 2 ]; then
      cargoJobs=32
    fi
    export CARGO_BUILD_JOBS="$cargoJobs"
    unset MAKEFLAGS MFLAGS CARGO_MAKEFLAGS
    unset ZSTD_SYS_USE_PKG_CONFIG
    unset PKG_CONFIG PKG_CONFIG_PATH PKG_CONFIG_LIBDIR PKG_CONFIG_SYSROOT_DIR
    echo "carbonado cargo jobs=$CARGO_BUILD_JOBS NIX_BUILD_CORES=''${NIX_BUILD_CORES:-unset}"
  '';

  commonArgs = {
    inherit src nativeBuildInputs;
    pname = "carbonado";
    version = (craneLib.crateNameFromCargoToml {cargoToml = src + "/Cargo.toml";}).version;
    strictDeps = true;
    enableParallelBuilding = true;
    CARGO_BUILD_JOBS = "32";
    CARGO_PROFILE = "dev";
    hardeningDisable = ["all"];
    # Host `.cargo/config.toml` points crates-io at index.crates.io so this
    # laptop is not stuck on menhera-cooldown. Crane already vendors crates.io;
    # that replace-with would override the vendor directory in the sandbox.
    postPatch = ''
      if [ -f .cargo/config.toml ]; then
        awk '
          /^\[source\.crates-io\]/ { skip=1; next }
          /^\[registries\.crates-io-official\]/ { skip=1; next }
          /^\[/ { skip=0 }
          skip { next }
          { print }
        ' .cargo/config.toml > .cargo/config.toml.vendor
        mv .cargo/config.toml.vendor .cargo/config.toml
      fi
    '';
    # Presence of ZSTD_SYS_USE_PKG_CONFIG (even =0) makes zstd-sys probe
    # nixpkgs libzstd. Unset on the deps layer and the test layer.
    preConfigure = ''
      unset ZSTD_SYS_USE_PKG_CONFIG
      unset PKG_CONFIG PKG_CONFIG_PATH PKG_CONFIG_LIBDIR PKG_CONFIG_SYSROOT_DIR
      echo "carbonado zstd-sys: bundled (ZSTD_SYS_USE_PKG_CONFIG unset; pkg-config not on compile PATH)"
    '';
  };

  # Do not put --all-targets here: crane buildDepsOnly already adds it.
  rustCargoExtraArgs = "--features ${rustExtraFeatures} --locked";

  rustArtifacts = craneLib.buildDepsOnly (commonArgs
    // remoteAttrs
    // {
      pname = "carbonado-clippy-rust${pnameSuffix}";
      cargoExtraArgs = rustCargoExtraArgs;
      doCheck = false;
    });

  applyRemote = drv: drv.overrideAttrs (_: remoteAttrs);

  fmt = applyRemote (craneLib.cargoFmt {
    inherit src;
    pname = "carbonado-fmt${pnameSuffix}";
    cargoExtraArgs = "--all";
  });

  clippy-rust = applyRemote (craneLib.cargoClippy (commonArgs
    // {
      cargoArtifacts = rustArtifacts;
      pname = "carbonado-clippy-rust${pnameSuffix}";
      cargoExtraArgs = "--locked";
      cargoClippyExtraArgs = "--all-targets --features ${rustExtraFeatures} -- -D warnings";
      doInstallCargoArtifacts = false;
    }));

  nextest-rust = applyRemote (craneLib.mkCargoDerivation (commonArgs
    // {
      cargoArtifacts = rustArtifacts;
      pname = "carbonado-nextest-rust${pnameSuffix}";
      pnameSuffix = "";
      doCheck = false;
      doInstallCargoArtifacts = false;
      nativeBuildInputs = nativeBuildInputs ++ [pkgs.cargo-nextest];
      buildPhaseCargoCommand = ''
        ${cargoJobsFromCores}
        echo "carbonado nextest (backend-rust + ${rustExtraFeatures})"
        cargo nextest run --locked --features ${rustExtraFeatures}
        echo "carbonado nextest serial FEC (--no-default-features --features ${rustSerialFeatures})"
        cargo nextest run --locked --no-default-features --features ${rustSerialFeatures} --test serial_fec_path
        echo "carbonado doctests (backend-rust + ${rustExtraFeatures})"
        cargo test --locked --doc --features ${rustExtraFeatures} --profile "$CARGO_PROFILE" --jobs "$CARGO_BUILD_JOBS"
      '';
    }));

  # grok-build cargo-on-builder style: rust-overlay cargo/nextest in this
  # derivation. Not crane mkCargoDerivation (that always adds nixpkgs zstd
  # for artifact compression, which can put libzstd headers on CPATH).
  # zstd-sys compiles its bundled C here (no buildDepsOnly cache).
  nextest-rust-cargo-on-builder = applyRemote (
    pkgs.stdenv.mkDerivation {
      pname = "carbonado-nextest-rust-cargo-on-builder${pnameSuffix}";
      inherit (commonArgs) version src;
      strictDeps = true;
      enableParallelBuilding = true;
      CARGO_BUILD_JOBS = "32";
      CARGO_PROFILE = "dev";
      hardeningDisable = ["all"];
      cargoVendorDir = craneLib.vendorCargoDeps {inherit src;};
      nativeBuildInputs = [
        rustToolchain
        pkgs.cargo-nextest
        cmakeWithSecp
        pkgs.rustPlatform.bindgenHook
        forceBundledZstdHook
        craneLib.configureCargoCommonVarsHook
        craneLib.configureCargoVendoredDepsHook
      ];
      preConfigure = commonArgs.preConfigure;
      buildPhase = ''
        runHook preBuild
        ${cargoJobsFromCores}
        echo "carbonado cargo-on-builder: rust-overlay cargo/nextest, no crane zstd package"
        rustc --version
        cargo --version
        echo "CC=''${CC:-unset}"
        if command -v pkg-config >/dev/null 2>&1; then
          echo "pkg-config=$(command -v pkg-config)"
        else
          echo "pkg-config=absent"
        fi
        set +e
        cargo nextest run --locked --features ${rustExtraFeatures} -- directory_cross_engine_live_roots_residual golden_directory_interop_checksums_and_manifest_wire directory_encode_independent_of_readdir_order
        nextest_status=$?
        set -e
        find target -name 'libzstd.a' -print -exec sha256sum {} \; -exec wc -c {} \; || true
        if [ "$nextest_status" -ne 0 ]; then
          exit "$nextest_status"
        fi
        runHook postBuild
      '';
      installPhase = ''
        runHook preInstall
        mkdir -p "$out"
        echo ok > "$out/result"
        runHook postInstall
      '';
    }
  );

in {
  inherit
    fmt
    clippy-rust
    nextest-rust
    nextest-rust-cargo-on-builder
    rustExtraFeatures
    rustSerialFeatures
    ;
}
