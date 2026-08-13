# PR 32 CI: restore bao-tree checkout on a legal path

**Date:** 2026-08-13  
**Workspace:** `/home/hunter/Projects/surmount/carbonado`  
**HEAD (committed YAML still had the illegal sibling checkout):** `b8c070ae64da98a9a2743dfdb48e8f75322b4f93`

## What changed

The previous working-tree change deleted all six `actions/checkout` steps that fetch bao-tree. That is reversed.

Every job that had **Checkout bao-tree keyed fork (sibling for path dep)** now has the step again. The path is inside `GITHUB_WORKSPACE`. Cargo is pointed at that tree before any cargo/just step.

`git diff HEAD -- .github/workflows/rust.yaml` is a restore-and-rewire (repo/ref/path + a patch step), not a net deletion of the checkout feature.

## In-workspace path

| Field | Old (illegal) | New |
|-------|---------------|-----|
| `repository` | `SurmountSystems/bao-tree` | `n0-computer/bao-tree` |
| `ref` | `76-keyed-bao` | `keyed-bao` |
| `path` | `../bao-tree` | `bao-tree` |

`path: bao-tree` is `${GITHUB_WORKSPACE}/bao-tree`, i.e. `/home/runner/work/carbonado/carbonado/bao-tree`. `actions/checkout@v4` accepts that.

Product `Cargo.toml` already uses `git = "https://github.com/n0-computer/bao-tree.git"`, `branch = "keyed-bao"`. The checkout matches that source, not the SurmountSystems `76-keyed-bao` sibling used only by local `just setup-bao-tree`.

Local optional path is unchanged: `just setup-bao-tree` / `.cargo/config.toml.example` still talk about `../bao-tree`.

`/bao-tree` is gitignored so an in-workspace clone is not committed.

## How cargo is patched (CI-only)

Committed `.cargo/config.toml` still only has the bitcoinpqc `[patch.crates-io]` block. That file is not overwritten.

Each job, after the bao-tree checkout, runs the composite
`.github/actions/ci-patch-bao-tree`. That step:

1. Fail-closes unless `${GITHUB_WORKSPACE}/bao-tree/Cargo.toml` exists.
2. **Appends** (does not replace) this table to `.cargo/config.toml`:

```toml
[patch."https://github.com/n0-computer/bao-tree.git"]
bao-tree = { path = "${GITHUB_WORKSPACE}/bao-tree" }
```

The path is absolute so it does not depend on whether cargo resolves patch paths relative to `.cargo/` or the workspace root. The git URL matches `Cargo.toml` exactly. The bitcoinpqc patch stays in place.

This append is job-local. It is not committed. Developers without a sibling or in-workspace tree keep using the public git dep.

## Jobs covered

Same six jobs as `git show HEAD:.github/workflows/rust.yaml`:

| Job | Checkout restored | Patch before cargo |
|-----|-------------------|--------------------|
| `lint` | yes | yes (before `just fmt` / `just lint`) |
| `lint-wasm` | yes | yes (before `just lint-wasm`) |
| `desktop` | yes | yes (before `cargo test` / just) |
| `test-matrix` | yes | yes (before `cargo check`) |
| `web-check` | yes | yes (before `cargo check`) |
| `dual-backend-lean` | yes | yes (before nix + `just test-lean-ci`) |

No `--all-features`. Tests were not weakened. No commit or push.

## Process note

This L2 session could not launch a workflow (host: workflows only from a top-level session). Inventory used `git show HEAD:.github/workflows/rust.yaml`, `Cargo.toml`, `.cargo/config.toml`, `.cargo/config.toml.example`, and `justfile`.
