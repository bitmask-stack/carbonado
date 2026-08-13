# Static FFI glue for Carbonado AOT (zstd + SLH-DSA + C ABI).
# Output: $out/libcarbonado_native.a (linked via buildLeanPackage.staticLibDeps).
#
# Embeds:
#   * single-threaded libzstd from the **pinned** `ref/zstd` tree (v1.5.7)
#   * SLH-DSA-SHA2-128s from pinned libbitcoinpqc (sphincsplus + slh_dsa only)
# so product frames track git submodule SSOTs — not floating nixpkgs.src.
# Static archive only (no shared -lzstd / pthread shlib issues under lld).
{
  pkgs,
  leanAll, # pkgs.lean.lean-all — provides lean/lean.h
  zstdSrc, # flake: pinned zstd fetch
  bitcoinpqcSrc, # flake: pinned libbitcoinpqc fetch (R9 / G10)
  carbonadoInclude ? ../.. + "/include", # repo include/carbonado.h (ABI)
}:
pkgs.stdenv.mkDerivation {
  pname = "carbonado-native";
  version = "0.1.0";
  src = ./.;

  # Static .a only; strip of archives trips nixpkgs strip.sh under `set -u` on some hosts.
  dontStrip = true;

  nativeBuildInputs = [pkgs.binutils];

  # Fail-closed: every .c compile must succeed (no `|| true` / silent stderr).
  buildPhase = ''
    runHook preBuild
    set -euo pipefail

    ZSTD_LIB="${zstdSrc}/lib"
    PQC="${bitcoinpqcSrc}"
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
    if [ ! -f "$PQC/include/libbitcoinpqc/slh_dsa.h" ]; then
      echo "carbonado-native: missing libbitcoinpqc at $PQC" >&2
      exit 1
    fi

    # Portable single-thread objects (no assembly). Explicit loops — fail on first error.
    compile_dir() {
      local dir="$1"
      local f base
      for f in "$dir"/*.c; do
        [ -f "$f" ] || continue
        base=$(basename "$f" .c)
        echo "  CC zstd/$base.c"
        $CC -c -O2 -fPIC -DZSTD_DISABLE_ASM \
          -I"$ZSTD_LIB" -I"$ZSTD_LIB/common" \
          "$f" -o "zstd_$base.o"
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

    # SLH-DSA-SHA2-128s only (no secp / ML-DSA). Unique object basenames avoid
    # clobbering sphincsplus/ref/utils.o vs src/slh_dsa/utils.o.
    PQC_CFLAGS="-O2 -fPIC -DPARAMS=sphincs-sha2-128s -DCUSTOM_RANDOMBYTES=1"
    PQC_INCLUDES="-I$PQC/include -I$PQC/src -I$PQC/sphincsplus/ref"
    compile_pqc() {
      local src="$1"
      local base="$2"
      echo "  CC slh/$base.c"
      $CC -c $PQC_CFLAGS $PQC_INCLUDES "$src" -o "slh_$base.o"
    }
    echo "carbonado-native: compiling libbitcoinpqc SLH-DSA (pinned)"
    compile_pqc "$PQC/sphincsplus/ref/address.c"            spx_address
    compile_pqc "$PQC/sphincsplus/ref/fors.c"               spx_fors
    compile_pqc "$PQC/sphincsplus/ref/hash_sha2.c"          spx_hash_sha2
    compile_pqc "$PQC/sphincsplus/ref/merkle.c"             spx_merkle
    compile_pqc "$PQC/sphincsplus/ref/sign.c"               spx_sign
    compile_pqc "$PQC/sphincsplus/ref/thash_sha2_simple.c"  spx_thash_sha2_simple
    compile_pqc "$PQC/sphincsplus/ref/utils.c"              spx_utils
    compile_pqc "$PQC/sphincsplus/ref/utilsx1.c"            spx_utilsx1
    compile_pqc "$PQC/sphincsplus/ref/wots.c"               spx_wots
    compile_pqc "$PQC/sphincsplus/ref/wotsx1.c"             spx_wotsx1
    compile_pqc "$PQC/sphincsplus/ref/sha2.c"               spx_sha2
    compile_pqc "$PQC/src/randombytes_custom.c"             pqc_randombytes
    compile_pqc "$PQC/src/slh_dsa/utils.c"                  slh_utils
    compile_pqc "$PQC/src/slh_dsa/keygen.c"                 slh_keygen
    compile_pqc "$PQC/src/slh_dsa/sign.c"                   slh_sign
    compile_pqc "$PQC/src/slh_dsa/verify.c"                 slh_verify

    echo "carbonado-native: compiling carbonado_slh.c (Lean extern + C ABI)"
    $CC -c -O2 -fPIC \
      -I${leanAll}/include \
      -I"$ABI_INC" \
      -I"$PQC/include" \
      carbonado_slh.c \
      -o carbonado_slh.o

    echo "carbonado-native: compiling carbonado_abi.c (C ABI v1 + Lean glue)"
    $CC -c -O2 -fPIC \
      -I${leanAll}/include \
      -I"$ABI_INC" \
      carbonado_abi.c \
      -o carbonado_abi.o

    # Fail-closed: must have more than just the FFI object.
    ocount=$(ls -1 ./*.o 2>/dev/null | wc -l)
    if [ "$ocount" -lt 20 ]; then
      echo "carbonado-native: expected many zstd+slh objects, found $ocount" >&2
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
    description = "Carbonado Lean AOT native glue (static zstd + SLH-DSA + C ABI Lean bridge)";
  };
}
