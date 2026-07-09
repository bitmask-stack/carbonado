# Carbonado development tasks. Run `just` to list recipes.
# Before a release: `just all`

set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

# Clone the keyed bao-tree sibling (../bao-tree, branch 76-keyed-bao).
setup-bao-tree:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -f ../bao-tree/Cargo.toml ]]; then
      echo "../bao-tree already present"
    else
      git clone -b 76-keyed-bao https://github.com/SurmountSystems/bao-tree.git ../bao-tree
    fi
    rg -q 'keyed_hash_subtree|KeyedHash|create_keyed' ../bao-tree/src
    echo "bao-tree OK (keyed fork)"

# Optional: verify sibling bao-tree when using `.cargo/config.toml` path patch.
require-bao-tree:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ ! -f ../bao-tree/Cargo.toml ]]; then
      echo "Missing ../bao-tree. Run: just setup-bao-tree (optional path patch for faster local builds)"
      exit 1
    fi
    if ! rg -q 'keyed_hash_subtree|KeyedHash|create_keyed' ../bao-tree/src 2>/dev/null; then
      echo "Wrong bao-tree at ../bao-tree — need SurmountSystems branch 76-keyed-bao"
      exit 1
    fi

# Enable ../bao-tree path patch (copy .cargo/config.toml.example → .cargo/config.toml).
dev-local-bao:
    #!/usr/bin/env bash
    set -euo pipefail
    just setup-bao-tree
    mkdir -p .cargo
    cp -f .cargo/config.toml.example .cargo/config.toml
    echo "Local bao-tree path patch enabled (.cargo/config.toml)"

fmt:
    cargo fmt --check

fmt-fix:
    cargo fmt

# Clippy + project-specific source checks (things clippy does not know about).
lint: _clippy _lint-source

[private]
_clippy:
    cargo clippy --all-targets --all-features -- -D warnings

[private]
_lint-source:
    #!/usr/bin/env bash
    set -euo pipefail
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    NC='\033[0m'
    if ! command -v rg >/dev/null 2>&1; then
      echo -e "${RED}ERROR${NC}: ripgrep (rg) is required. Install: pacman/apt/brew install ripgrep"
      exit 1
    fi
    failures=0
    pass() { echo -e "${GREEN}PASS${NC}: $1"; }
    fail() { echo -e "${RED}FAIL${NC}: $1"; failures=$((failures + 1)); }
    scan_non_test_src() {
      local mode="$1"
      find src -name '*.rs' -print0 | while IFS= read -r -d '' f; do
        awk -v mode="$mode" '
          /#\[cfg\(test\)\]/ { in_test = 1 }
          /^[[:space:]]*mod tests[[:space:]]*\{/ && !in_test { in_test = 1; depth = 1; next }
          in_test {
            nopen = gsub(/\{/, "{")
            nclose = gsub(/\}/, "}")
            depth += nopen - nclose
            if (depth <= 0) in_test = 0
            next
          }
          {
            hit = 0
            if (mode == "unwrap" && ($0 ~ /\.unwrap\(\)/ || $0 ~ /\.expect\(/)) hit = 1
            if (mode == "stub" && ($0 ~ /todo!\(/ || $0 ~ /unimplemented!\(/)) hit = 1
            if (hit && $0 !~ /^[[:space:]]*\/\// && $0 !~ /^[[:space:]]*\/\*/) {
              print FILENAME ":" NR ":" $0
            }
          }
        ' "$f"
      done
    }
    echo "=== Source checks (part of lint) ==="
    echo ""
    echo "--- 1. No v1 ECIES decode paths ---"
    ecies_hits=$(rg -n 'ecies|CARBONADO01' \
      --glob '!AGENTS.md' --glob '!CHANGELOG.md' --glob '!README.md' \
      --glob '!review-round-1-merged.md' \
      src/ Cargo.toml tests/ examples/ benches/ 2>/dev/null || true)
    if [[ -z "$ecies_hits" ]]; then
      pass "No ecies/CARBONADO01 in src/, tests/, Cargo.toml deps (docs excluded)"
    else
      bad=$(echo "$ecies_hits" | rg -v '^\S+:\d+:(//|#)' || true)
      if [[ -z "$bad" ]]; then
        pass "ecies/CARBONADO01 only in comments (clean break upheld)"
        echo "  Evidence (comments only):"
        echo "$ecies_hits" | sed 's/^/    /'
      else
        fail "ecies/CARBONADO01 found outside comments/docs"
        echo "$bad" | sed 's/^/    /'
      fi
    fi
    if rg -q '^ecies\s*=' Cargo.toml 2>/dev/null; then
      fail "ecies crate listed as dependency in Cargo.toml"
    else
      pass "No ecies crate dependency in Cargo.toml"
    fi
    echo ""
    echo "--- 2. No .unwrap()/.expect() in production src/ ---"
    unwrap_violations=$(scan_non_test_src unwrap)
    if [[ -z "$unwrap_violations" ]]; then
      pass "No .unwrap()/.expect() in production src/ (test modules excluded)"
    else
      fail ".unwrap()/.expect() found in production src/"
      echo "$unwrap_violations" | sed 's/^/    /'
    fi
    echo ""
    echo "--- 3. MAGIC constant ---"
    if rg -q 'CARBONADO20\\n' src/constants.rs && \
       rg -q 'pub const MAGICNO: &\[u8; 12\] = b"CARBONADO20\\n";' src/constants.rs; then
      pass 'MAGICNO is b"CARBONADO20\n" in src/constants.rs'
    else
      fail 'MAGICNO not set to b"CARBONADO20\n" in src/constants.rs'
      rg -n 'MAGICNO' src/constants.rs 2>/dev/null | sed 's/^/    /' || true
    fi
    echo ""
    echo "--- 4. NotImplemented not on crypto paths ---"
    notimpl_returns=$(rg -n 'CarbonadoError::NotImplemented|Err\([^)]*NotImplemented' src/ 2>/dev/null || true)
    if [[ -z "$notimpl_returns" ]]; then
      pass "No NotImplemented returns in src/ (enum variant may exist for future use)"
    else
      fail "NotImplemented returned in src/"
      echo "$notimpl_returns" | sed 's/^/    /'
    fi
    echo ""
    echo "--- 5. No todo!/unimplemented! in production src/ ---"
    stub_violations=$(scan_non_test_src stub)
    if [[ -z "$stub_violations" ]]; then
      pass "No todo!/unimplemented! in production src/ (test modules excluded)"
    else
      fail "todo!/unimplemented! found in production src/"
      echo "$stub_violations" | sed 's/^/    /'
    fi
    echo ""
    echo "--- 6. Seekable verify_slice / scrub extraction contract ---"
    preorder_hits=$(rg -n 'ranges_pre_order_chunks_iter_ref' src/decoding.rs 2>/dev/null || true)
    if [[ -z "$preorder_hits" ]]; then
      pass "decoding.rs has no ranges_pre_order_chunks_iter_ref (verify_slice delegates to stream)"
    else
      fail "ranges_pre_order_chunks_iter_ref still present in src/decoding.rs"
      echo "$preorder_hits" | sed 's/^/    /'
    fi
    slice_preorder=$(rg -n 'ranges_pre_order_chunks_iter_ref' src/stream/slice.rs 2>/dev/null || true)
    if [[ -n "$slice_preorder" ]]; then
      if rg -q 'P1-SCRUB: pre-order walk' src/stream/slice.rs 2>/dev/null; then
        pass "stream/slice.rs pre-order iter is confined to documented scrub extraction path"
      else
        fail "stream/slice.rs uses ranges_pre_order_chunks_iter_ref without P1-SCRUB contract comment"
        echo "$slice_preorder" | sed 's/^/    /'
      fi
      if rg -q 'content\.extend' src/stream/slice.rs 2>/dev/null; then
        fail "stream/slice.rs must not full-materialize logical content (content.extend found)"
      else
        pass "stream/slice.rs has no O(N) logical content.extend materialization"
      fi
    else
      pass "stream/slice.rs has no ranges_pre_order_chunks_iter_ref (fully seekable)"
    fi
    if rg -q 'ranges_pre_order_chunks_iter_ref' src/stream/slice.rs 2>/dev/null && \
       rg -A2 'pub fn verify_slice_inboard_seekable' src/stream/slice.rs 2>/dev/null | rg -q 'ranges_pre_order_chunks_iter_ref'; then
      fail "verify_slice_inboard_seekable must not use ranges_pre_order_chunks_iter_ref"
    else
      pass "verify_slice_inboard_seekable does not use pre-order full materialization loop"
    fi
    echo ""
    if [[ $failures -eq 0 ]]; then
      echo -e "=== Source checks: ${GREEN}ALL PASS${NC} ==="
    else
      echo -e "=== Source checks: ${RED}$failures FAILED${NC} ==="
      exit 1
    fi

lint-wasm:
    cargo clippy --target wasm32-unknown-unknown --no-default-features --features "" -- -D warnings

# Default features (includes `parallel`), serial FEC regression, then full feature matrix.
test:
    cargo test
    cargo test --no-default-features --features "pqc,ots,cli" --test serial_fec_path
    cargo test --all-features

test-serial:
    cargo test --no-default-features --features "pqc,ots,cli" --test serial_fec_path

test-parallel:
    cargo test --test parallel_determinism

# Focused smoke: slices, streaming, sharding, bao-tree contract (also in `just test`).
test-smoke:
    cargo test --test streaming --test seekable_slices --test sharding --test bao_keyed_contract

build:
    cargo build --bin carbonado --release

# Install `carbonado` into ~/.cargo/bin from this checkout.
install:
    cargo install --path . --bin carbonado --locked --force

# Regenerate roff man pages from the clap schema → doc/man/*.1
gen-man:
    cargo run --quiet --bin gen-carbonado-man --features man-gen -- doc/man

# Install man pages (default: ~/.local/share/man/man1). Override: MANPREFIX=/usr/local
install-man:
    #!/usr/bin/env bash
    set -euo pipefail
    just gen-man
    dest="${MANPREFIX:-$HOME/.local}/share/man/man1"
    mkdir -p "$dest"
    cp -f doc/man/carbonado*.1 "$dest/"
    echo "Installed carbonado man pages to $dest"
    if command -v mandb >/dev/null 2>&1; then
      mandb "$dest" 2>/dev/null || mandb 2>/dev/null || true
    fi

# CLI tests using the release binary (run after `just build`).
test-cli:
    cargo test --release --test bin_smoke --test bin_heuristics --test bin_cli

examples:
    cargo test --examples --no-run

# Everything — run this before a release tag.
# Regenerate man pages and fail if doc/man/*.1 drift from clap schema.
check-man:
    #!/usr/bin/env bash
    set -euo pipefail
    just gen-man
    if ! git diff --exit-code -- doc/man/*.1 >/dev/null 2>&1; then
      echo "doc/man/*.1 out of date — commit regenerated man pages (just gen-man)"
      git diff --stat -- doc/man/*.1
      exit 1
    fi

all: fmt lint test test-smoke build test-cli gen-man check-man examples