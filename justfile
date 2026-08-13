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

# rustfmt has no `-W`; `--check` is the fail-if-unformatted equivalent of `cargo fmt --all -W`.
# Never `--all-features` on clippy: that enables both `backend-rust` and `backend-lean`
# and hits `compile_error!`. This is the rust-compatible stand-in (same as `just lint` / CI).
# Rust-only gate: fmt --check, clippy (rust features), nextest. Stops on first failure.
check:
    cargo fmt --all -- --check
    cargo clippy --all-targets --features "async,async-tokio,man-gen" -- -D warnings
    cargo nextest run

# Clippy + project-specific source checks (things clippy does not know about).
lint: _clippy _lint-source

# Never use `--all-features` here: that enables both `backend-rust` and `backend-lean` → compile_error!.
# Cover optional features mutually compatible with default `backend-rust`.
[private]
_clippy:
    cargo clippy --all-targets --features "async,async-tokio,man-gen" -- -D warnings

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
    # Skip #[cfg(test)] modules (any name) and bare `mod tests { ... }` blocks.
    # Important: do not clear in_test on the cfg line itself (depth starts at 0).
    scan_non_test_src() {
      local mode="$1"
      find src -name '*.rs' -print0 | while IFS= read -r -d '' f; do
        awk -v mode="$mode" '
          /#\[cfg\(test\)\]/ { in_test = 1; entered = 0; depth = 0; next }
          /^[[:space:]]*(pub[[:space:]]+)?mod[[:space:]]+tests[[:space:]]*\{/ && !in_test {
            in_test = 1; entered = 0; depth = 0
          }
          in_test {
            line = $0
            nopen = gsub(/\{/, "{", line)
            nclose = gsub(/\}/, "}", line)
            depth += nopen - nclose
            if (nopen > 0) entered = 1
            if (entered && depth <= 0) { in_test = 0; entered = 0; depth = 0 }
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
    echo "--- 4. NotImplemented only on intentional residual / map sites ---"
    # Allowed (documented dual-backend / platform residuals — not silent crypto stubs):
    # - error.rs enum variant definition
    # - backend lean ABI code → CarbonadoError map arm
    # - stream_decode_async on wasm32 (documented NotImplemented residual)
    # - doc comments mentioning the variant
    # (R2: file::encode metadata/SLH are plumbed — no longer NotImplemented)
    notimpl_hits=$(rg -n 'CarbonadoError::NotImplemented|Err\([^)]*NotImplemented' src/ 2>/dev/null || true)
    notimpl_bad=""
    if [[ -n "$notimpl_hits" ]]; then
      notimpl_bad=$(echo "$notimpl_hits" | while IFS= read -r line; do
        # comments / docs
        if echo "$line" | rg -q '^\S+:\d+:[[:space:]]*(//|///|\*)'; then continue; fi
        # enum variant
        if echo "$line" | rg -q 'src/error\.rs:'; then continue; fi
        # match-arm mapping from C ABI
        if echo "$line" | rg -q '=>[[:space:]]*CarbonadoError::NotImplemented'; then continue; fi
        # intentional wasm async residual
        if echo "$line" | rg -q 'src/stream/decode_async\.rs:'; then continue; fi
        echo "$line"
      done || true)
    fi
    if [[ -z "$notimpl_bad" ]]; then
      pass "NotImplemented only at allowlisted residual/map sites (dual-backend + wasm async)"
      if [[ -n "$notimpl_hits" ]]; then
        echo "  Allowlisted evidence:"
        echo "$notimpl_hits" | sed 's/^/    /'
      fi
    else
      fail "Unexpected NotImplemented returns in src/ (not on allowlist)"
      echo "$notimpl_bad" | sed 's/^/    /'
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

# wasm32: always name backend-rust under --no-default-features (mutual exclusion).
lint-wasm:
    cargo clippy --target wasm32-unknown-unknown --no-default-features --features "backend-rust" -- -D warnings

# Default features (includes `parallel`), serial FEC, then backend-rust + optional features.
# Never `--all-features` (enables both backends → compile_error!).
test:
    cargo test
    cargo test --no-default-features --features "backend-rust,pqc,ots,cli" --test serial_fec_path
    cargo test --features "async,async-tokio,man-gen"

test-serial:
    cargo test --no-default-features --features "backend-rust,pqc,ots,cli" --test serial_fec_path

test-parallel:
    cargo test --test parallel_determinism

# Focused smoke: slices, streaming, sharding, bao-tree contract (also in `just test`).
test-smoke:
    cargo test --test streaming --test seekable_slices --test sharding --test bao_keyed_contract

# Shared lean env: build libcarbonado if CARBONADO_LEAN_LIB unset; fail-closed if .so/.dylib missing.
# stdout: only `export …` lines (safe for `eval "$(just _lean-env)"`); diagnostics on stderr.
[private]
_lean-env:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -z "${CARBONADO_LEAN_LIB:-}" ]]; then
      # Dedicated symlink so other `nix build` targets do not clobber `result/`.
      nix build .#libcarbonado -o result-libcarbonado
      export CARBONADO_LEAN_LIB="$PWD/result-libcarbonado/lib"
      export CARBONADO_LEAN_INCLUDE="$PWD/result-libcarbonado/include"
    fi
    if [[ ! -f "${CARBONADO_LEAN_LIB}/libcarbonado.so" && ! -f "${CARBONADO_LEAN_LIB}/libcarbonado.dylib" ]]; then
      echo "FATAL: libcarbonado shared library missing under CARBONADO_LEAN_LIB=${CARBONADO_LEAN_LIB}" >&2
      echo "  Build: nix build .#libcarbonado -o result-libcarbonado" >&2
      echo "  Then:  export CARBONADO_LEAN_LIB=\$PWD/result-libcarbonado/lib" >&2
      echo "         export CARBONADO_LEAN_INCLUDE=\$PWD/result-libcarbonado/include" >&2
      exit 1
    fi
    if [[ -z "${CARBONADO_LEAN_INCLUDE:-}" ]]; then
      if [[ -d "$(dirname "${CARBONADO_LEAN_LIB}")/include" ]]; then
        export CARBONADO_LEAN_INCLUDE="$(dirname "${CARBONADO_LEAN_LIB}")/include"
      else
        echo "FATAL: CARBONADO_LEAN_INCLUDE unset and cannot infer from CARBONADO_LEAN_LIB" >&2
        exit 1
      fi
    fi
    export LD_LIBRARY_PATH="${CARBONADO_LEAN_LIB}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    echo "CARBONADO_LEAN_LIB=$CARBONADO_LEAN_LIB" >&2
    echo "CARBONADO_LEAN_INCLUDE=$CARBONADO_LEAN_INCLUDE" >&2
    printf 'export CARBONADO_LEAN_LIB=%q\n' "$CARBONADO_LEAN_LIB"
    printf 'export CARBONADO_LEAN_INCLUDE=%q\n' "$CARBONADO_LEAN_INCLUDE"
    printf 'export LD_LIBRARY_PATH=%q\n' "$LD_LIBRARY_PATH"

# Dual-backend Phase 1: build libcarbonado and run lean allowlist smoke.
test-lean-smoke:
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(just _lean-env)"
    cargo test --no-default-features --features "backend-lean,pqc,ots" --test lean_backend_smoke

# Dual-backend Phase 2: outboard/scrub/slice + G9 buffer seeds (+ Phase 1 smoke).
test-lean-phase2:
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(just _lean-env)"
    cargo test --no-default-features --features "backend-lean,pqc,ots" \
      --test lean_backend_smoke --test lean_backend_phase2

# Dual-backend Phase 3: directory composition (rkyv catalog + Lean segment/catalog crypto).
test-lean-phase3:
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(just _lean-env)"
    cargo test --no-default-features --features "backend-lean,pqc,ots" \
      --test lean_backend_smoke --test lean_backend_phase2 --test lean_backend_phase3 \
      --test format_policy

# Dual-backend Phase 4: SLH composition (G10-A) + CLI dual path + directory OTS.
# `cli` enables lean-linked binary: directory subprocess = dual-engine; single-file stream = link smoke.
test-lean-phase4:
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(just _lean-env)"
    cargo test --no-default-features --features "backend-lean,pqc,ots,cli" \
      --test lean_backend_smoke --test lean_backend_phase2 --test lean_backend_phase3 \
      --test format_policy --test slh_outboard --test lean_backend_phase4

# Dual-backend Phase 5 / G11 + R7 G8 full close: shared CI + human gate.
# Freeze = full dual suite under lean features (G8 closed 2026-07 R7). See docs/GAPS.md.
# Permanent feature-gated exclusions under this feature set (0 tests, not dual residual):
#   streaming_async needs `async` (R10 closed: freeze never requires async; lean+async dual-aware);
#   parallel_determinism needs `parallel` (Lean RS serial).
# Post-G8 residuals (not dual-suite failures): stream E2, file::decode_stream pure-Rust,
# pure Lean rkyv encode residual — composition paths remain SSOT for those layers.
test-lean-ci:
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(just _lean-env)"
    # Full dual suite (lib units + all integration tests, including bin_*). Never add async.
    cargo test --no-default-features --features "backend-lean,pqc,ots,cli"

# G9 / R8: cross-backend matrix both directions (lean fixtures → rust; rust fixtures → lean).
test-g9:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo test --test g9_cross_backend
    eval "$(just _lean-env)"
    cargo test --no-default-features --features "backend-lean,pqc,ots" --test g9_cross_backend

# Regenerate G9 goldens under tests/fixtures/g9/{rust,lean}/ (requires libcarbonado for lean).
g9-gen-fixtures:
    #!/usr/bin/env bash
    set -euo pipefail
    G9_WRITE_FIXTURES=1 cargo test --test g9_cross_backend write_fixtures -- --ignored --nocapture
    eval "$(just _lean-env)"
    G9_WRITE_FIXTURES=1 cargo test --no-default-features --features "backend-lean,pqc,ots" \
      --test g9_cross_backend write_fixtures -- --ignored --nocapture

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