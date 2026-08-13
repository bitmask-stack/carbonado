{
  description = "carbonado — apocalypse-resistant archival format (Lean 4 AOT + Nix)";

  inputs = {
    nixpkgs.follows = "lean4-nix/nixpkgs";
    flake-parts.url = "github:hercules-ci/flake-parts";
    lean4-nix.url = "github:lenianiva/lean4-nix";
  };

  outputs = inputs @ {
    nixpkgs,
    flake-parts,
    lean4-nix,
    ...
  }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-darwin"
        "x86_64-linux"
      ];

      perSystem = {
        system,
        pkgs,
        ...
      }: let
        # Product source: Lean modules + flake metadata. ref/ and Rust legacy stay out
        # of the Lean package src filter where possible.
        # Note: Lean test tree is `CarbonadoTest/` (not `Tests/`) to avoid colliding
        # with Rust `tests/` on case-insensitive filesystems (Darwin).
        productSrc = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type: let
            base = baseNameOf path;
          in
            !(base == "ref" && type == "directory")
            && !(base == "target" && type == "directory")
            && !(base == "src" && type == "directory")
            && !(base == "tests" && type == "directory")
            && !(base == "benches" && type == "directory")
            && !(base == "examples" && type == "directory")
            && !(base == ".git" && type == "directory")
            && !(base == "result" || pkgs.lib.hasPrefix "result-" base)
            && pkgs.lib.cleanSourceFilter path type;
        };

        # Match proof holes: `sorry` and its Lean alias `admit`.
        holePattern = ''(^|[^a-zA-Z_])(sorry|admit)([^a-zA-Z_]|$)'';

        # Program F: static zstd from the **same pin as ref/zstd** (v1.5.7 /
        # f8745da6…) + FFI glue → libcarbonado_native.a. Fetched by fixed rev/hash
        # so flake purity does not require the submodule worktree to be git-tracked
        # in the parent tree; SHA must stay in lockstep with docs/PARITY.md.
        zstdPinned = pkgs.fetchFromGitHub {
          owner = "facebook";
          repo = "zstd";
          rev = "f8745da6ff1ad1e7bab384bd1f9d742439278e99";
          hash = "sha256-tNFWIT9ydfozB8dWcmTMuZLCQmQudTFJIkSr0aG7S44=";
        };
        # R9 / G10: libbitcoinpqc pin matching ref/bitcoinpqc submodule
        # (b309f444… / branch 27-slh-dsa-sha-2-128s). SLH-DSA-SHA2-128s only
        # (no secp/ML-DSA) is compiled into libcarbonado_native.a.
        bitcoinpqcPinned = pkgs.fetchFromGitHub {
          owner = "cryptoquick";
          repo = "libbitcoinpqc";
          rev = "b309f444e383f0e8726c8697128641c7599524f1";
          hash = "sha256-dSGYo3qmq2wSltKjRgcRyrYFZO6YGoIsIG7scEWnQqE=";
        };
        carbonadoNative = import ./nix/native {
          inherit pkgs;
          leanAll = pkgs.lean.lean-all;
          zstdSrc = zstdPinned;
          bitcoinpqcSrc = bitcoinpqcPinned;
          carbonadoInclude = ./include;
        };

        leanPkg = pkgs.lean.buildLeanPackage {
          name = "carbonado";
          # Separate roots so CarbonadoTest compiles without product → test imports.
          # lean4-nix only discovers modules under the root name of each entry.
          # Carbonado.Ffi is a root so `@[export] l_carbonado_*` AOT objects land in
          # staticLib even when Main does not import Ffi.
          roots = [
            "Carbonado.Main"
            "Carbonado.Ffi"
            "Carbonado.RkyvFilepack"
            "CarbonadoTest.Scaffold"
            "CarbonadoTest.EtM"
            "CarbonadoTest.Fec"
            "CarbonadoTest.Bao"
            "CarbonadoTest.Pipeline"
            "CarbonadoTest.Compress"
            "CarbonadoTest.Slh"
            "CarbonadoTest.Directory"
          ];
          src = productSrc;
          debug = false;
          leancFlags = ["-O3" "-DNDEBUG"];
          # Static zstd + C ABI glue (no shared libzstd — avoids lld shlib-undefined/pthread).
          staticLibDeps = [carbonadoNative];
          linkFlags = [];
        };

        # Dual-backend product archive: Lean AOT objects + native zstd/ABI glue,
        # packaged as a shared library (leanc links Lean runtime) plus a static
        # archive for `nm` / partial static consumers.
        libcarbonado =
          pkgs.runCommand "libcarbonado" {
            nativeBuildInputs = [pkgs.binutils pkgs.stdenv.cc pkgs.lean.leanc];
          } ''
            set -euo pipefail
            mkdir -p $out/lib $out/include

            LEAN_A="${leanPkg.staticLib}/libcarbonado.a"
            NATIVE_A="${carbonadoNative}/libcarbonado_native.a"
            test -f "$LEAN_A"
            test -f "$NATIVE_A"

            # Shared library via leanc + Lean shared stdlib (Init/runtime).
            # lean4-nix staticLib is a *thin* archive; leanc/ld accept it with whole-archive.
            # --whole-archive keeps @[export] + C ABI symbols from being GC'd.
            # Pass libleanshared the same way buildLeanPackage.executable does (withSharedStdlib).
            ${pkgs.lean.leanc}/bin/leanc -shared -fPIC \
              -Wl,--whole-archive "$LEAN_A" "$NATIVE_A" -Wl,--no-whole-archive \
              ${pkgs.lean.leanshared}/* \
              -o $out/lib/libcarbonado.so

            # Regular static archive for `nm` / consumers: thin member paths + native objects.
            WORK=$(mktemp -d)
            cd "$WORK"
            mapfile -t LEAN_OBJS < <(${pkgs.binutils}/bin/ar t "$LEAN_A")
            ${pkgs.binutils}/bin/ar x "$NATIVE_A"
            ${pkgs.binutils}/bin/ar rcs $out/lib/libcarbonado.a "''${LEAN_OBJS[@]}" ./*.o

            cp ${./include}/carbonado.h $out/include/
            echo "libcarbonado: packaged static + shared" >&2
          '';

        leanAbiCheck =
          pkgs.runCommand "carbonado-lean-abi" {
            nativeBuildInputs = [pkgs.binutils];
          } ''
            set -euo pipefail
            test -f ${libcarbonado}/include/carbonado.h
            test -f ${libcarbonado}/lib/libcarbonado.a
            test -f ${libcarbonado}/lib/libcarbonado.so
            nm ${libcarbonado}/lib/libcarbonado.a | grep -q carbonado_abi_version
            nm ${libcarbonado}/lib/libcarbonado.a | grep -q carbonado_free
            nm ${libcarbonado}/lib/libcarbonado.a | grep -q carbonado_encode
            nm ${libcarbonado}/lib/libcarbonado.a | grep -q carbonado_decode
            nm ${libcarbonado}/lib/libcarbonado.a | grep -q carbonado_encode_headered
            nm ${libcarbonado}/lib/libcarbonado.a | grep -q carbonado_decode_headered
            nm ${libcarbonado}/lib/libcarbonado.a | grep -q carbonado_verification_key
            nm ${libcarbonado}/lib/libcarbonado.a | grep -q l_carbonado_encode_headered
            nm ${libcarbonado}/lib/libcarbonado.a | grep -q l_carbonado_verification_key
            # R9 / G10 SLH + seekable outboard slice
            nm ${libcarbonado}/lib/libcarbonado.a | grep -q carbonado_slh_keygen
            nm ${libcarbonado}/lib/libcarbonado.a | grep -q carbonado_slh_sign
            nm ${libcarbonado}/lib/libcarbonado.a | grep -q carbonado_slh_verify
            nm ${libcarbonado}/lib/libcarbonado.a | grep -q carbonado_verify_slice_outboard
            nm ${libcarbonado}/lib/libcarbonado.a | grep -q l_carbonado_verify_slice_outboard
            echo ok > $out
          '';

        noSorry =
          pkgs.runCommand "carbonado-no-sorry" {
            src = productSrc;
          } ''
            set -euo pipefail
            # Fail-closed: product Lean trees must exist in productSrc.
            for dir in Carbonado CarbonadoTest; do
              if [ ! -d "$src/$dir" ]; then
                echo "carbonado: missing required directory $dir/ in product source" >&2
                exit 1
              fi
              lean_count=$(find "$src/$dir" -type f -name '*.lean' | wc -l)
              if [ "$lean_count" -lt 1 ]; then
                echo "carbonado: $dir/ has no .lean files" >&2
                exit 1
              fi
              if grep -R --include='*.lean' -nE '${holePattern}' "$src/$dir"; then
                echo "carbonado: proof hole (sorry/admit) found in $dir Lean sources" >&2
                exit 1
              fi
            done
            for f in Carbonado.lean CarbonadoTest.lean; do
              if [ ! -f "$src/$f" ]; then
                echo "carbonado: missing root module $f" >&2
                exit 1
              fi
              if grep -nE '${holePattern}' "$src/$f"; then
                echo "carbonado: proof hole (sorry/admit) found in $f" >&2
                exit 1
              fi
            done
            mkdir -p $out
            echo ok > $out/result
          '';

        toolingPurity = import ./nix/tooling-purity.nix {
          inherit pkgs;
          src = productSrc;
        };

        # Run AOT binary as a check (constants + EtM + FEC + Bao + pipeline + Program F).
        demo =
          pkgs.runCommand "carbonado-demo" {
            nativeBuildInputs = [leanPkg.executable];
          } ''
            set -euo pipefail
            ${leanPkg.executable}/bin/carbonado | tee $out
            grep -q "scaffold constants ok" $out
            grep -q "headerLen = 177" $out
            grep -q "sliceLen = 4096" $out
            grep -q "leafBytes = 4096" $out
            grep -q "verificationContext = carbonado-v2/verification" $out
            grep -q "sample public c14 format byte = 14" $out
            grep -q "sample encrypted c15 format byte = 15" $out
            grep -q "fecK = 4 fecM = 8 stripeUnit = 16384" $out
            grep -q "sha512 goldens ok" $out
            grep -q "hmac goldens ok" $out
            grep -q "aes-ctr nist golden ok" $out
            grep -q "subkey goldens ok" $out
            grep -q "etm header-path goldens + roundtrip ok" $out
            grep -q "etm low-level layout ok" $out
            grep -q "tampered tag → authenticationFailed ok" $out
            grep -q "wrong key → authenticationFailed ok" $out
            grep -q "short ciphertext → invalidCiphertextLength ok" $out
            grep -q "short master → invalidKeyLength ok" $out
            grep -q "bad nonce → invalidNonceLength ok" $out
            grep -q "ct body tamper → authenticationFailed ok" $out
            grep -q "header mac goldens ok" $out
            grep -q "header mac verify false path ok" $out
            grep -q "etm stack ok" $out
            grep -q "gf goldens ok" $out
            grep -q "padding geometry ok" $out
            grep -q "rs encode/reconstruct goldens ok" $out
            grep -q "inboard hello roundtrip + knockout ok" $out
            grep -q "inboard pattern roundtrip ok" $out
            grep -q "unevenShards ok" $out
            grep -q "tooFewShards ok" $out
            grep -q "emptyShard ok" $out
            grep -q "incorrectShardSize ok" $out
            grep -q "badGeometry ok" $out
            grep -q "paddingTooLarge ok" $out
            grep -q "singularMatrix ok" $out
            grep -q "encode/new guards ok" $out
            grep -q "verify good/bad ok" $out
            grep -q "knockout oob badGeometry ok" $out
            grep -q "fec stack ok" $out
            grep -q "blake3 goldens ok" $out
            grep -q "verification key goldens ok" $out
            grep -q "keyed root goldens ok" $out
            grep -q "inboard encode/decode ok" $out
            grep -q "outboard encode/verify ok" $out
            grep -q "slice encode/stream-decode ok" $out
            grep -q "three-leaf tree ok" $out
            grep -q "wrong format key → authenticationFailed ok" $out
            grep -q "slice wrong key → authenticationFailed ok" $out
            grep -q "truncated response → truncatedResponse ok" $out
            grep -q "truncated slice → truncatedResponse ok" $out
            grep -q "trailing data → trailingData ok" $out
            grep -q "slice trailing data → trailingData ok" $out
            grep -q "short prefix → invalidPrefix ok" $out
            grep -q "bad root length → invalidRootLength ok" $out
            grep -q "bad slice index → invalidSliceIndex ok" $out
            grep -q "slice count 0 → invalidSliceCount ok" $out
            grep -q "tampered body → authenticationFailed ok" $out
            grep -q "tampered slice → authenticationFailed ok" $out
            grep -q "bao stack ok" $out
            grep -q "header wire + verify ok" $out
            grep -q "badMagic → HeaderError/PipelineError.badMagic ok" $out
            grep -q "short header → invalidHeaderLength ok" $out
            grep -q "invalidFieldLength ok" $out
            grep -q "format matrix c0–c15 roundtrip ok" $out
            grep -q "headered + c12/c15 roundtrip ok" $out
            grep -q "encoded_len truncatedBody + trailer ignore ok" $out
            grep -q "payload tamper → payloadAuthenticationFailed ok" $out
            grep -q "composition invalidCiphertextLength + paddingTooLarge + bao trunc ok" $out
            grep -q "pipeline invalidNonceLength + invalidKeyLength ok" $out
            grep -q "wrong bao root → baoAuthenticationFailed ok" $out
            grep -q "fecDecodeStep uneven → unevenShards ok" $out
            grep -q "PipelineError taxonomy maps ok" $out
            grep -q "stream stripe bounds ok" $out
            grep -q "scrubRequiresVerification ok" $out
            grep -q "unnecessaryScrub ok" $out
            grep -q "scrub knockout recovery + invalidScrubbedHash ok" $out
            grep -q "shard roundtrip + sequence errors ok" $out
            grep -q "encrypted formats odd ok" $out
            grep -q "pipeline stack ok" $out
            # Program F
            grep -q "zstd status mapping ok" $out
            grep -q "PipelineError zstd maps ok" $out
            grep -q "zstd goldens + roundtrip + error paths ok" $out
            grep -q "pipeline compression formats c2/c6 + headered c3/c7 ok" $out
            grep -q "SLH1 wire framing ok" $out
            grep -q "SLH live sign/verify ok" $out
            grep -q "program F stack ok" $out
            grep -q "outboard slice verify ok" $out
            # Program G
            grep -q "adamantine wire ok" $out
            grep -q "filepack path rules ok" $out
            grep -q "rkyv FilepackManifestWire encode/decode goldens ok" $out
            # multi-entry + OTS + trunc covered in same Main block
            grep -q "outboard segment roundtrip ok" $out
            grep -q "directory pure encode/decode ok" $out
            grep -q "directory exact failure modes ok" $out
            grep -q "directory error taxonomy ok" $out
            grep -q "program G stack ok" $out
            grep -q "version = lean-program-g-0" $out
          '';

        # Strip only with GNU strip (Linux). Darwin strip rejects --strip-unneeded.
        carbonadoRelease =
          if pkgs.stdenv.isLinux
          then
            pkgs.runCommand "carbonado-release" {
              nativeBuildInputs = [pkgs.binutils];
            } ''
              set -euo pipefail
              mkdir -p $out/bin
              cp ${leanPkg.executable}/bin/carbonado $out/bin/carbonado
              chmod u+w $out/bin/carbonado
              strip --strip-unneeded $out/bin/carbonado
            ''
          else
            pkgs.runCommand "carbonado-release" {} ''
              set -euo pipefail
              mkdir -p $out/bin
              cp ${leanPkg.executable}/bin/carbonado $out/bin/carbonado
              # Darwin/BSD strip does not use GNU long options; ship unstripped release.
              echo "carbonado-release: non-Linux host; leaving binary unstripped" >&2
            '';
      in {
        _module.args.pkgs = import nixpkgs {
          inherit system;
          overlays = [(lean4-nix.readToolchainFile ./lean-toolchain)];
        };

        packages = {
          default = leanPkg.executable;
          carbonado = leanPkg.executable;
          carbonado-release = carbonadoRelease;
          libcarbonado = libcarbonado;
        };

        apps.default = {
          type = "app";
          program = "${leanPkg.executable}/bin/carbonado";
          meta.description = "Carbonado Lean 4 AOT product binary (Programs A–G: Adamantine dirs + CLI)";
        };

        checks = {
          no-sorry = noSorry;
          tooling-purity = toolingPurity;
          demo = demo;
          # Building the package is itself a check of Lean compile (includes CarbonadoTest roots).
          carbonado = leanPkg.executable;
          lean-abi = leanAbiCheck;
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            cacert
            git
            gnupg
            ripgrep
            scc
            # Host elan/lake may be used; lean4-nix provides leanc via package builds.
          ];
          shellHook = ''
            export SSL_CERT_FILE="${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
            export GIT_SSL_CAINFO="$SSL_CERT_FILE"
            if [ -f lean-toolchain ]; then
              echo "carbonado Lean 4 + Nix dev shell"
              echo "Lean toolchain pin: $(cat lean-toolchain)"
              echo "Build: nix build .#carbonado"
              echo "Lib:   nix build .#libcarbonado"
              echo "Check: nix flake check"
              echo "Run:   nix run"
              echo "Lean backend tests:"
              echo "  nix build .#libcarbonado -o result-libcarbonado"
              echo "  export CARBONADO_LEAN_LIB=\$PWD/result-libcarbonado/lib CARBONADO_LEAN_INCLUDE=\$PWD/result-libcarbonado/include"
              echo "  export LD_LIBRARY_PATH=\$CARBONADO_LEAN_LIB"
              echo "  cargo test --no-default-features --features \"backend-lean,pqc,ots\" --test lean_backend_smoke"
            fi
          '';
        };
      };
    };
}
