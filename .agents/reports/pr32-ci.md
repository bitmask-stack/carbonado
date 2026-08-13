# PR 32 CI diagnosis

**PR:** https://github.com/bitmask-stack/carbonado/pull/32  
**Branch:** `lean` → `main` (draft, title “proven”)  
**HEAD:** `b8c070ae64da98a9a2743dfdb48e8f75322b4f93`  
**Date observed:** 2026-08-13

## What ran

Workflows are not skipped, pending forever, or missing. One workflow exists (`Rust` / `.github/workflows/rust.yaml`). Both the `push` run ([101](https://github.com/bitmask-stack/carbonado/actions/runs/31745640857)) and the `pull_request` run ([102](https://github.com/bitmask-stack/carbonado/actions/runs/31745690786)) completed in about ten seconds as **failure**. Combined commit status is `pending` with **zero** commit statuses. That is normal: this repo uses Actions check runs, not the old status API.

| Check name | Conclusion | Why |
|------------|------------|-----|
| `lint` | **failure** | Illegal sibling checkout (below) |
| `lint-wasm` | **failure** | Same |
| `desktop` | skipped | `needs: lint` |
| `test-matrix` | skipped | `needs: lint` |
| `dual-backend-lean` | skipped | `needs: lint` |
| `web-check` | skipped | `needs: lint-wasm` |

Job names match `docs/TEST_CONTRACT.md` (`desktop`, `dual-backend-lean`, plus lint/matrix). This is not a branch-protection name mismatch. There are no PR comments about CI. Rustc, clippy, and tests never started.

## Root cause

Every job checked out `SurmountSystems/bao-tree` at `76-keyed-bao` with `path: ../bao-tree`. `actions/checkout@v4` refuses any path outside `GITHUB_WORKSPACE`.

Quoted from `lint` / `lint-wasm` on run 102:

```
Repository path '/home/runner/work/carbonado/bao-tree' is not under '/home/runner/work/carbonado/carbonado'
```

Failed step: **Checkout bao-tree keyed fork (sibling for path dep)**.

That step is leftover from an optional local path patch (`just dev-local-bao` / `.cargo/config.toml.example`). CI does not copy that example. Product `Cargo.toml` already uses a public git dep:

`git+https://github.com/n0-computer/bao-tree.git?branch=keyed-bao` (lock pin `e82e744…`; branch is public).

Committed `.cargo/config.toml` only patches `bitcoinpqc` to a public git rev. It does **not** force `../bao-tree`. So CI does not need a sibling checkout.

Local `just check` looks fine because it never runs `actions/checkout`. Same illegal step already fails `main` the same way (run 99, 2026-07-09).

Not the cause: YAML syntax, path filters, permissions, n0-computer fetch (never reached), dual-backend `--all-features` (PR already avoids that).

## Fix applied (not committed, not pushed)

Removed all six sibling `actions/checkout` steps from [`.github/workflows/rust.yaml`](../../.github/workflows/rust.yaml) and left a short comment. Cargo on CI will fetch `n0-computer/bao-tree` `keyed-bao` as `Cargo.toml` already says.

After this file is on `lean`, re-run the PR workflow. Later jobs may still fail on real compile/test; this change only unblocks the first step.

## Residual (not this outage)

- `keyed-bao` is a moving branch; `/Cargo.lock` is gitignored, so CI is not pinned to a lockfile.
- `just setup-bao-tree` still clones `SurmountSystems` `76-keyed-bao`. Local optional path patch vs product git source can drift. Separate from this CI break.
