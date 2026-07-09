# Static FFI glue for Carbonado AOT (zstd wrappers + libzstd objects).
# Output: $out/libcarbonado_native.a (linked via buildLeanPackage.staticLibDeps).
#
# Embeds single-threaded libzstd from the **pinned** `ref/zstd` tree (v1.5.7)
# so product frames track the git submodule SSOT — not a floating nixpkgs.src.
# Static archive only (no shared -lzstd / pthread shlib issues under lld).
{
  pkgs,
  leanAll, # pkgs.lean.lean-all — provides lean/lean.h
  zstdSrc, # flake: ./ref/zstd (must be checked-out submodule pin)
  carbonadoInclude ? ../.. + "/include", # repo include/carbonado.h (ABI)
}:
pkgs.stdenv.mkDerivation {
  pname = "carbonado-native";
  version = "0.1.0";
  src = ./.;

  nativeBuildInputs = [pkgs.binutils];

  # Fail-closed: every .c compile must succeed (no `|| true` / silent stderr).
  buildPhase = ''
    runHook preBuild
    set -euo pipefail

    ZSTD_LIB="${zstdSrc}/lib"
    ABI_INC="${carbonadoInclude}"
    if [ ! -f "$ABI_INC/carbonado.h" ]; then
      echo "carbonado-native: missing $ABI_INC/carbonado.h" >&2
      exit 1
    fi
    if [ ! -d "$ZSTD_LIB" ]; then
      echo "carbonado-native: missing zstd lib dir at $ZSTD_LIB (init ref/zstd submodule)" >&2
      exit 1
    fi
    if [ ! -f "$ZSTD_LIB/zstd.h" ]; then
      echo "carbonado-native: missing $ZSTD_LIB/zstd.h" >&2
      exit 1
    fi

    # Portable single-thread objects (no assembly). Explicit loops — fail on first error.
    compile_dir() {
      local dir="$1"
      local f base
      for f in "$dir"/*.c; do
        [ -f "$f" ] || continue
        base=$(basename "$f" .c)
        echo "  CC $base.c"
        $CC -c -O2 -fPIC -DZSTD_DISABLE_ASM \
          -I"$ZSTD_LIB" -I"$ZSTD_LIB/common" \
          "$f" -o "$base.o"
      done
    }

    echo "carbonado-native: compiling libzstd (common/compress/decompress) from ref pin"
    compile_dir "$ZSTD_LIB/common"
    compile_dir "$ZSTD_LIB/compress"
    compile_dir "$ZSTD_LIB/decompress"
    # dictBuilder not required for ZSTD_compress / ZSTD_decompress buffer API.

    echo "carbonado-native: compiling carbonado_zstd.c"
    $CC -c -O2 -fPIC \
      -I${leanAll}/include \
      -I"$ZSTD_LIB" \
      carbonado_zstd.c \
      -o carbonado_zstd.o

    echo "carbonado-native: compiling carbonado_abi.c (C ABI v0 stubs)"
    $CC -c -O2 -fPIC \
      -I"$ABI_INC" \
      carbonado_abi.c \
      -o carbonado_abi.o

    # Fail-closed: must have more than just the FFI object.
    ocount=$(ls -1 ./*.o 2>/dev/null | wc -l)
    if [ "$ocount" -lt 10 ]; then
      echo "carbonado-native: expected many zstd objects, found $ocount" >&2
      ls -la ./*.o >&2 || true
      exit 1
    fi

    ar rcs libcarbonado_native.a ./*.o
    echo "carbonado-native: archived $ocount objects → libcarbonado_native.a"
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    # lean4-nix staticLibDeps expects $out/libcarbonado_native.a (archive root).
    mkdir -p $out/lib $out/include
    cp libcarbonado_native.a $out/
    cp libcarbonado_native.a $out/lib/
    ln -sf libcarbonado_native.a $out/lib/libcarbonado.a
    cp "${carbonadoInclude}/carbonado.h" $out/include/
    runHook postInstall
  '';

  meta = {
    description = "Carbonado Lean AOT native glue (static zstd + C ABI stubs)";
  };
}
