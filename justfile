# Carbonado development tasks. Run `just` to list recipes.
# Before a release: `just all`
#
# Full quality gate (fmt, clippy, nextest, then Lean proof/demo checks) on
# the Nix remote builder: `just check` / `just check-remote`. Sequential.
# There is no Cargo Lean backend. GitHub Actions must not call check-remote;
# GHA keeps `just fmt` / `just lint` / `just test` / Lean nix checks.
# Force-remote nix: caller max-jobs 0, --store ssh-ng (machines file),
# --eval-store auto, --cores 64. rustc requires surmount-remote.

set shell := ["bash", "-euo", "pipefail", "-c"]

# Host system for flake check attributes. Prefer CI_SYSTEM. Do not call nix
# at just parse time.
system := env_var_or_default("CI_SYSTEM", `case "$(uname -s)-$(uname -m)" in Linux-x86_64) echo x86_64-linux;; Linux-aarch64|Linux-arm64) echo aarch64-linux;; Darwin-x86_64) echo x86_64-darwin;; Darwin-arm64) echo aarch64-darwin;; *) echo "unsupported $(uname -s)-$(uname -m); set CI_SYSTEM=..." >&2; exit 1;; esac`)

default:
    @just --list

# Clone n0-computer/bao-tree at the PR 78 merge SHA (optional sibling path patch).
bao_tree_rev := "dbc952e32cbda8ffd14c106b770e72987b01618e"

setup-bao-tree:
    #!/usr/bin/env bash
    set -euo pipefail
    PIN="{{bao_tree_rev}}"
    if [[ -f ../bao-tree/Cargo.toml ]]; then
      echo "../bao-tree already present"
    else
      git clone https://github.com/n0-computer/bao-tree.git ../bao-tree
    fi
    git -C ../bao-tree fetch --all --tags
    git -C ../bao-tree checkout "$PIN"
    rg -q 'create_keyed|keyed_outboard_post_order' ../bao-tree/src
    echo "bao-tree OK (n0-computer $PIN)"

# Optional: verify sibling bao-tree when using `.cargo/config.toml` path patch.
require-bao-tree:
    #!/usr/bin/env bash
    set -euo pipefail
    PIN="{{bao_tree_rev}}"
    if [[ ! -f ../bao-tree/Cargo.toml ]]; then
      echo "Missing ../bao-tree. Run: just setup-bao-tree (optional path patch for faster local builds)"
      exit 1
    fi
    if ! rg -q 'create_keyed|keyed_outboard_post_order' ../bao-tree/src 2>/dev/null; then
      echo "Wrong bao-tree at ../bao-tree — need n0-computer PR 78 merge ($PIN)"
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

# Host cargo fmt (CI `lint` job). Check gate uses --all -- --check, not a write.
fmt:
    cargo fmt --all -- --check

fmt-fix:
    cargo fmt --all

# Fail loud before force-remote nix. Reuses the trusted-user machines file
# (default $HOME/.config/nix/machines). Does not bake a host address. Does
# not fall back to local Nix store builds. Override: GROK_NIX_BUILDERS_FILE.
[private]
require_remote_builder:
    #!/usr/bin/env bash
    set -euo pipefail
    file="${GROK_NIX_BUILDERS_FILE:-$HOME/.config/nix/machines}"
    known_hosts="${GROK_NIX_KNOWN_HOSTS:-$HOME/.ssh/known_hosts}"
    extra_ssh="-o UserKnownHostsFile=${known_hosts} -o StrictHostKeyChecking=yes"
    if [[ -n "${NIX_SSHOPTS:-}" ]]; then
      export NIX_SSHOPTS="${NIX_SSHOPTS} ${extra_ssh}"
    else
      export NIX_SSHOPTS="${extra_ssh}"
    fi
    if [[ ! -s "${file}" ]]; then
      echo "The Nix builders file is missing or empty: ${file}." >&2
      echo "just check-remote reuses the trusted-user machines file already named in the user Nix config (override with GROK_NIX_BUILDERS_FILE)." >&2
      echo "Host cargo recipes (just fmt, just lint, just test) do not need this file." >&2
      exit 2
    fi
    if ! grep -q 'ssh-ng://' "${file}"; then
      echo "The Nix builders file ${file} has no ssh-ng:// builder line." >&2
      echo "just check-remote will not fall back to local Nix store builds." >&2
      exit 2
    fi
    ssh_ng_host() {
      local u="${1#ssh-ng://}"
      u="${u%%\?*}"
      u="${u#*@}"
      u="${u%%/*}"
      if [[ "${u}" == \[* ]]; then
        u="${u#\[}"
        u="${u%%]*}"
      else
        u="${u%%:*}"
      fi
      printf '%s' "${u}"
    }
    host_key_present() {
      local host="$1"
      [[ -s "${known_hosts}" ]] || return 1
      ssh-keygen -F "${host}" -f "${known_hosts}" 2>/dev/null | awk '!/^#/ && $2 ~ /^ssh-/ { found=1; exit } END { exit !found }'
    }
    while IFS= read -r line || [[ -n "${line}" ]]; do
      [[ "${line}" == ssh-ng://* ]] || continue
      set -- ${line}
      host="$(ssh_ng_host "${1}")"
      if [[ -z "${host}" ]] || ! host_key_present "${host}"; then
        echo "This account's known_hosts has no host key for the machines-file builder." >&2
        echo "User ssh to Host surmount-1 is not the nix build SSH path (nix-daemon opens ssh-ng)." >&2
        echo "just check-remote sets NIX_SSHOPTS to this account's known_hosts and will not fall back to a local rustc." >&2
        exit 2
      fi
    done < "${file}"
    inject_feats="${GROK_NIX_REMOTE_SYSTEM_FEATURES-}"
    if [[ -z "${inject_feats}" ]]; then
      if ! ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=yes surmount-1 true; then
        echo "SSH BatchMode to Host surmount-1 failed." >&2
        echo "just check-remote requires that existing remote builder and will not fall back to local Nix store builds." >&2
        exit 2
      fi
    fi
    remote_feats=""
    if [[ -n "${inject_feats}" ]]; then
      remote_feats="${inject_feats}"
    else
      set +e
      feats_out="$(ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=yes surmount-1 'nix config show' 2>/dev/null)"
      feats_status=$?
      set -e
      if [[ "${feats_status}" -ne 0 ]]; then
        echo "Could not read the remote builder nix-daemon system-features over SSH BatchMode." >&2
        echo "just check-remote will not start the long quality build until that query works." >&2
        exit 2
      fi
      remote_feats="$(awk -F' = ' '/^system-features / { print $2; exit }' <<<"${feats_out}")"
      if [[ -z "${remote_feats}" ]]; then
        echo "The remote builder SSH reply had no system-features line." >&2
        echo "just check-remote will not start the long quality build until the remote nix-daemon reports its feature list." >&2
        exit 2
      fi
    fi
    if ! grep -Eq '(^|[[:space:],{])surmount-remote($|[[:space:],}])' <<<"${remote_feats}"; then
      echo "The remote nix-daemon does not list surmount-remote in its system-features." >&2
      echo "The client machines file advertises that feature, so Nix will schedule rustc on the remote, then the daemon will refuse: missing system features." >&2
      echo "Add surmount-remote to the builder daemon (NixOS extra-system-features / nix.conf) and restart or switch. just check-remote will not start the long quality build until that feature is present." >&2
      exit 2
    fi
    echo "==> just check-remote: using builders file ${file}"
    echo "==> just check-remote: NIX_SSHOPTS uses this account's known_hosts (host-key checks stay on)"
    echo "==> just check-remote: rustc, clippy, and nextest require the remote builder surmount-remote feature (fallback=false). This laptop does not advertise that feature, so local nixbld cannot take the rustc job."
    echo "==> just check-remote: force-remote nix sets max-jobs 0. This laptop must not build. Fixed-output derivations and toolchain downloads go to the remote builder."
    echo "==> just check-remote: force-remote nix uses --store ssh-ng (same machines-file builder) and --eval-store auto. -L logs still stream. nix build --no-link skips a local result symlink."
    echo "==> just check-remote: force-remote nix uses --cores 64. Host machines max-jobs should advertise that many jobs on the builder."

# Retry a nix command. When GROK_NIX_FORCE_REMOTE=1, append force-remote
# flags (max-jobs 0, ssh-ng --store, --eval-store auto). Hard SSH /
# missing-system-features / rustfmt Diff-in / clippy could-not-compile /
# nextest fail exit on attempt 1.
[private]
[positional-arguments]
nix_retry +cmd:
    #!/usr/bin/env bash
    set -euo pipefail
    raw_attempts="${NIX_RETRY_ATTEMPTS:-4}"
    if [[ ! "${raw_attempts}" =~ ^[1-9][0-9]*$ ]]; then
      echo "==> nix_retry: NIX_RETRY_ATTEMPTS must be a positive integer, got: ${raw_attempts}" >&2
      exit 2
    fi
    attempts="${raw_attempts}"
    backoff=5
    n=1
    attempt_log="$(mktemp)"
    enriched_builders=""
    cleanup_nix_retry_log() { rm -f "${attempt_log}" "${enriched_builders}"; }
    trap cleanup_nix_retry_log EXIT
    force_remote_opts=()
    if [[ "${GROK_NIX_FORCE_REMOTE:-}" == "1" ]]; then
      builders_file="${GROK_NIX_BUILDERS_FILE:-$HOME/.config/nix/machines}"
      known_hosts="${GROK_NIX_KNOWN_HOSTS:-$HOME/.ssh/known_hosts}"
      extra_ssh="-o UserKnownHostsFile=${known_hosts} -o StrictHostKeyChecking=yes"
      if [[ -n "${NIX_SSHOPTS:-}" ]]; then
        export NIX_SSHOPTS="${NIX_SSHOPTS} ${extra_ssh}"
      else
        export NIX_SSHOPTS="${extra_ssh}"
      fi
      ssh_ng_host() {
        local u="${1#ssh-ng://}"
        u="${u%%\?*}"
        u="${u#*@}"
        u="${u%%/*}"
        if [[ "${u}" == \[* ]]; then
          u="${u#\[}"
          u="${u%%]*}"
        else
          u="${u%%:*}"
        fi
        printf '%s' "${u}"
      }
      host_key_b64() {
        local host="$1"
        local line typ key
        [[ -s "${known_hosts}" ]] || return 1
        line="$(ssh-keygen -F "${host}" -f "${known_hosts}" 2>/dev/null | awk '!/^#/ && $2=="ssh-ed25519" {print; exit}')"
        if [[ -z "${line}" ]]; then
          line="$(ssh-keygen -F "${host}" -f "${known_hosts}" 2>/dev/null | awk '!/^#/ && $2 ~ /^ssh-/ {print; exit}')"
        fi
        [[ -n "${line}" ]] || return 1
        typ="$(awk '{print $2}' <<<"${line}")"
        key="$(awk '{print $3}' <<<"${line}")"
        printf '%s' "${typ} ${key}" | base64 -w0
      }
      max_conn="${GROK_NIX_SSH_NG_MAX_CONNECTIONS:-8}"
      if [[ ! "${max_conn}" =~ ^[1-9][0-9]*$ ]]; then
        echo "==> nix_retry: GROK_NIX_SSH_NG_MAX_CONNECTIONS must be a positive integer, got: ${max_conn}" >&2
        exit 2
      fi
      enriched_builders="$(mktemp)"
      chmod 600 "${enriched_builders}"
      while IFS= read -r line || [[ -n "${line}" ]]; do
        if [[ "${line}" != ssh-ng://* ]]; then
          printf '%s\n' "${line}" >>"${enriched_builders}"
          continue
        fi
        uri="" systems="" ssh_key="" max_jobs="" speed="" supported="" mandatory="" host_key=""
        read -r uri systems ssh_key max_jobs speed supported mandatory host_key _rest <<<"${line}" || true
        if [[ "${uri}" != *"max-connections="* ]]; then
          if [[ "${uri}" == *\?* ]]; then
            uri="${uri}&max-connections=${max_conn}"
          else
            uri="${uri}?max-connections=${max_conn}"
          fi
        fi
        if [[ -n "${host_key:-}" && "${host_key}" != "-" ]]; then
          printf '%s %s %s %s %s %s %s %s\n' \
            "${uri}" "${systems:--}" "${ssh_key:--}" "${max_jobs:--}" "${speed:--}" "${supported:--}" "${mandatory:--}" "${host_key}" >>"${enriched_builders}"
          continue
        fi
        host="$(ssh_ng_host "${uri}")"
        if ! b64="$(host_key_b64 "${host}")"; then
          echo "==> nix_retry: this account's known_hosts has no host key for the machines-file builder. User ssh to Host surmount-1 is not the nix build SSH path." >&2
          exit 2
        fi
        printf '%s %s %s %s %s %s %s %s\n' \
          "${uri}" "${systems:--}" "${ssh_key:--}" "${max_jobs:--}" "${speed:--}" "${supported:--}" "${mandatory:--}" "${b64}" >>"${enriched_builders}"
      done < "${builders_file}"
      builders_file="${enriched_builders}"
      store_uri=""
      while IFS= read -r bline || [[ -n "${bline}" ]]; do
        if [[ "${bline}" == ssh-ng://* ]]; then
          read -r store_uri _ <<<"${bline}" || true
          break
        fi
      done < "${builders_file}"
      if [[ -z "${store_uri}" || "${store_uri}" != ssh-ng://* ]]; then
        echo "==> nix_retry: GROK_NIX_FORCE_REMOTE needs an ssh-ng:// builder URI in the machines file so nix can use --store on that builder. This laptop must not realize the graph into the local store." >&2
        exit 2
      fi
      force_remote_opts=(
        --option builders "@${builders_file}"
        --option builders-use-substitutes true
        --option fallback false
        --option system-features "kvm nixos-test uid-range"
        --option max-jobs 0
        --cores 64
        --store "${store_uri}"
        --eval-store auto
      )
      if [[ "${2:-}" == "build" ]]; then
        force_remote_opts+=(--no-link)
      fi
    fi
    if [[ "${1:-}" == ssh-ng://* ]]; then
      echo "==> nix_retry: the first argument is a machines-file line, not the nix command. Pass --option builders @file after the command; do not put the machines line in \"\$@\"." >&2
      exit 2
    fi
    while true; do
      if ((${#force_remote_opts[@]})); then
        banner_opts=()
        skip_store_uri=0
        for opt in "${force_remote_opts[@]}"; do
          if [[ "${skip_store_uri}" -eq 1 ]]; then
            banner_opts+=("<builder>")
            skip_store_uri=0
            continue
          fi
          if [[ "${opt}" == "--store" ]]; then
            banner_opts+=(--store)
            skip_store_uri=1
            continue
          fi
          banner_opts+=("${opt}")
        done
        echo "==> nix attempt ${n}/${attempts}: $* ${banner_opts[*]}"
      else
        echo "==> nix attempt ${n}/${attempts}: $*"
      fi
      set +e
      set +o pipefail
      "$@" "${force_remote_opts[@]}" 2>&1 | tee "${attempt_log}"
      status="${PIPESTATUS[0]}"
      set -o pipefail
      set -e
      if [[ "${status}" -eq 0 ]]; then
        exit 0
      fi
      if grep -qE 'failed to start SSH connection|Failed to find a machine for remote build' "${attempt_log}"; then
        echo "==> nix_retry: the builder is listed, but SSH did not start. rustc was not run locally. Not retrying this hard remote miss." >&2
        exit "${status}"
      fi
      if grep -qE 'missing system features' "${attempt_log}"; then
        echo "==> nix_retry: the remote builder refused this derivation: missing system features. Add surmount-remote to the builder daemon and retry. Not retrying this hard remote miss." >&2
        exit "${status}"
      fi
      if grep -qE 'Diff in ' "${attempt_log}"; then
        echo "==> nix_retry: cargo fmt / rustfmt check failed (Diff in). Format the listed files and retry. Not retrying this hard quality miss." >&2
        exit "${status}"
      fi
      if grep -qE 'error: could not compile|clippy::' "${attempt_log}"; then
        echo "==> nix_retry: cargo clippy / rustc quality failed (could not compile). Fix the listed errors and retry. Not retrying this hard quality miss." >&2
        exit "${status}"
      fi
      if grep -qE 'cannot update the lock file|--locked was passed' "${attempt_log}"; then
        echo "==> nix_retry: cargo lockfile / --locked mismatch. Not retrying this hard quality miss." >&2
        exit "${status}"
      fi
      if grep -qE 'hash mismatch in fixed-output derivation' "${attempt_log}"; then
        echo "==> nix_retry: nix fixed-output hash mismatch. Update the listed sha256 and retry. Not retrying this hard quality miss." >&2
        exit "${status}"
      fi
      if grep -qE 'error: test run failed|test run failed' "${attempt_log}"; then
        echo "==> nix_retry: cargo nextest / test run failed. Fix the listed tests and retry. Not retrying this hard quality miss." >&2
        exit "${status}"
      fi
      if [[ "${status}" -eq 127 ]] && grep -qE 'ssh-ng://.*No such file or directory' "${attempt_log}"; then
        echo "==> nix_retry: the command was a machines-file line (exit 127). Force-remote builders belong in --option builders @file after nix. Not retrying this hard recipe miss." >&2
        exit "${status}"
      fi
      if [[ "${n}" -ge "${attempts}" ]]; then
        echo "==> nix FAILED after ${n} attempt(s) (exit ${status}): $*" >&2
        exit "${status}"
      fi
      echo "==> nix attempt ${n} failed (exit ${status}); retrying in ${backoff}s..." >&2
      sleep "${backoff}"
      backoff=$((backoff * 3))
      n=$((n + 1))
    done

# Sequential host-Nix flake checks (fmt, clippy, nextest, then Lean proofs).
# Does not force the remote builder; this laptop may rustc.
check-local:
    #!/usr/bin/env bash
    set -euo pipefail
    sys="{{ system }}"
    echo "==> just check-local: fmt"
    nix build --impure -L --print-out-paths "path:.#checks.${sys}.fmt"
    echo "==> just check-local: clippy (backend-rust + async,async-tokio,man-gen)"
    nix build --impure -L --print-out-paths "path:.#checks.${sys}.clippy-rust"
    echo "==> just check-local: nextest (backend-rust)"
    nix build --impure -L --print-out-paths "path:.#checks.${sys}.nextest-rust"
    echo "==> just check-local: Lean gates"
    nix build --impure -L --print-out-paths "path:.#checks.${sys}.no-sorry"
    nix build --impure -L --print-out-paths "path:.#checks.${sys}.tooling-purity"
    nix build --impure -L --print-out-paths "path:.#checks.${sys}.carbonado"
    nix build --impure -L --print-out-paths "path:.#checks.${sys}.demo"
    nix build --impure -L --print-out-paths "path:.#checks.${sys}.rustc-1_98"

# Sequential force-remote gate. rustc requires surmount-remote. Quote
# .#attr; unquoted # is a bash comment.
check-remote: require_remote_builder
    #!/usr/bin/env bash
    set -euo pipefail
    export GROK_NIX_FORCE_REMOTE=1
    export GROK_NIX_BUILDERS_FILE="${GROK_NIX_BUILDERS_FILE:-$HOME/.config/nix/machines}"
    known_hosts="${GROK_NIX_KNOWN_HOSTS:-$HOME/.ssh/known_hosts}"
    extra_ssh="-o UserKnownHostsFile=${known_hosts} -o StrictHostKeyChecking=yes"
    if [[ -n "${NIX_SSHOPTS:-}" ]]; then
      export NIX_SSHOPTS="${NIX_SSHOPTS} ${extra_ssh}"
    else
      export NIX_SSHOPTS="${extra_ssh}"
    fi
    sys="{{ system }}"
    echo "==> just check-remote: fmt"
    just nix_retry nix build --impure -L --print-out-paths "path:.#fmt-quality"
    echo "==> just check-remote: clippy (backend-rust + async,async-tokio,man-gen)"
    just nix_retry nix build --impure -L --print-out-paths "path:.#clippy-rust-quality"
    echo "==> just check-remote: nextest (backend-rust)"
    just nix_retry nix build --impure -L --print-out-paths "path:.#nextest-rust-quality"
    echo "==> just check-remote: Lean gates"
    just nix_retry nix build --impure -L --print-out-paths "path:.#checks.${sys}.no-sorry"
    just nix_retry nix build --impure -L --print-out-paths "path:.#checks.${sys}.tooling-purity"
    just nix_retry nix build --impure -L --print-out-paths "path:.#checks.${sys}.carbonado"
    just nix_retry nix build --impure -L --print-out-paths "path:.#checks.${sys}.demo"
    just nix_retry nix build --impure -L --print-out-paths "path:.#checks.${sys}.rustc-1_98"

# Full gate on the remote builder (Surmount split: check-remote is the
# builder path; check is the name operators type).
check: check-remote

# Clippy + project-specific source checks (things clippy does not know about).
lint: _clippy _lint-source

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
    # Allowed (documented residuals — not silent crypto stubs):
    # - error.rs enum variant definition
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
        # match-arm mapping to the variant
        if echo "$line" | rg -q '=>[[:space:]]*CarbonadoError::NotImplemented'; then continue; fi
        # intentional wasm async residual
        if echo "$line" | rg -q 'src/stream/decode_async\.rs:'; then continue; fi
        echo "$line"
      done || true)
    fi
    if [[ -z "$notimpl_bad" ]]; then
      pass "NotImplemented only at allowlisted residual/map sites (wasm async)"
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

# wasm32: name backend-rust under --no-default-features (empty marker + lib).
lint-wasm:
    cargo clippy --target wasm32-unknown-unknown --no-default-features --features "backend-rust" -- -D warnings

# Default features (includes `parallel`), serial FEC, then optional features.
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

# Lean proof + AOT demo gates (no Rust -sys / libcarbonado).
test-lean-ci:
    #!/usr/bin/env bash
    set -euo pipefail
    sys="{{ system }}"
    nix build --impure -L --print-out-paths "path:.#checks.${sys}.no-sorry"
    nix build --impure -L --print-out-paths "path:.#checks.${sys}.tooling-purity"
    nix build --impure -L --print-out-paths "path:.#checks.${sys}.carbonado"
    nix build --impure -L --print-out-paths "path:.#checks.${sys}.demo"

# Rust decode of committed Lean AOT goldens under tests/fixtures/g9/lean/.
test-g9:
    cargo test --test g9_cross_backend

# Regenerate rust goldens under tests/fixtures/g9/rust/.
g9-gen-fixtures:
    G9_WRITE_FIXTURES=1 cargo test --test g9_cross_backend write_fixtures -- --ignored --nocapture

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