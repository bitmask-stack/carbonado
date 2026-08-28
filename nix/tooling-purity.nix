# checks.tooling-purity — product tree purity constraints.
# SSOT: Rust under src/, tests/, benches/, examples/ is the production engine.
# Lean under Carbonado/ + CarbonadoTest/ is proofs + AOT demo. ref/ is third-party
# oracles only. There is no carbonado-sys crate and no product C ABI.
# This check:
#   * requires product Lean roots to exist and be Lean-only
#   * bans product shell/python glue outside nix/ and ref/
#   * allowlists known top-level roots (both engines + docs/tooling expected permanently)
{ pkgs, src }:
pkgs.runCommand "carbonado-tooling-purity" {
  inherit src;
  nativeBuildInputs = [pkgs.findutils pkgs.gnugrep pkgs.coreutils];
} ''
  set -euo pipefail
  cd "$src"

  # Fail-closed: product Lean trees must be present in productSrc.
  for dir in Carbonado CarbonadoTest; do
    if [ ! -d "$dir" ]; then
      echo "carbonado tooling-purity: missing required directory $dir/" >&2
      exit 1
    fi
    lean_count=$(find "$dir" -type f -name '*.lean' | wc -l)
    if [ "$lean_count" -lt 1 ]; then
      echo "carbonado tooling-purity: $dir/ has no .lean files" >&2
      exit 1
    fi
    bad=$(find "$dir" -type f ! -name '*.lean' 2>/dev/null || true)
    if [ -n "''${bad}" ]; then
      echo "carbonado tooling-purity: non-Lean files under $dir/:" >&2
      echo "$bad" >&2
      exit 1
    fi
  done

  for f in Carbonado.lean CarbonadoTest.lean; do
    if [ ! -f "$f" ]; then
      echo "carbonado tooling-purity: missing root module $f" >&2
      exit 1
    fi
  done

  # Forbidden product glue paths (use Nix or ref/).
  if [ -d scripts ] || [ -d tools ]; then
    echo "carbonado tooling-purity: scripts/ and tools/ are forbidden product roots" >&2
    exit 1
  fi
  for f in Makefile; do
    if [ -e "$f" ]; then
      echo "carbonado tooling-purity: forbidden product path $f (use Nix or ref/)" >&2
      exit 1
    fi
  done
  # Root-level shell/python product glue (ref/ and nix/ may have their own).
  sh_py=$(find . -maxdepth 1 -type f \( -name '*.sh' -o -name '*.py' \) 2>/dev/null || true)
  if [ -n "''${sh_py}" ]; then
    echo "carbonado tooling-purity: forbidden root shell/python product glue:" >&2
    echo "$sh_py" >&2
    exit 1
  fi

  # Positive allowlist for top-level names.
  # Permanent dual product roots: src/, tests/, benches/, examples/, Cargo.* (Rust)
  # plus Carbonado/, CarbonadoTest/ (Lean). productSrc may exclude Rust; allowlist
  # still names them for full-tree runs (expected, not temporary).
  is_allowed() {
    local base="$1"
    case "$base" in
      .|..) return 0 ;;
      .git|.cargo|.github|.vscode|.gitignore|.gitmodules) return 0 ;;
      Carbonado|CarbonadoTest|nix|docs|doc|ref|src|tests|benches|examples|target) return 0 ;;
      Carbonado.lean|CarbonadoTest.lean) return 0 ;;
      flake.nix|flake.lock|lean-toolchain|rust-toolchain.toml|justfile|build.rs) return 0 ;;
      # Optional Lake manifest for local Lean IDE/`lake build` (Nix remains SSOT package).
      lakefile.toml|lakefile.lean|lake-manifest.json) return 0 ;;
      AGENTS.md|README.md|LICENSE|CHANGELOG.md|Cargo.toml|Cargo.lock) return 0 ;;
      result|result-*) return 0 ;;
      *.md) return 0 ;;  # project notes / reviews at root
    esac
    # Dotfiles are tooling metadata, not product glue.
    case "$base" in
      .*) return 0 ;;
    esac
    return 1
  }

  for entry in * .[!.]* ..?*; do
    [ -e "$entry" ] || continue
    base=$(basename "$entry")
    if ! is_allowed "$base"; then
      echo "carbonado tooling-purity: unexpected top-level product path: $base" >&2
      echo "  (allowlist is intentional; move glue to nix/ or ref/, or update allowlist)" >&2
      exit 1
    fi
  done

  mkdir -p $out
  echo ok > $out/result
''
