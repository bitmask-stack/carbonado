# `ref/crates` — crates.io-only vendors

Some Cargo.lock pins are not git monorepo tags (or left the monorepo). Vendor exact
crates.io sources here when a Lean parity program needs them.

| Crate | Version | Checksum (Cargo.lock) | Status |
|-------|---------|----------------------|--------|
| `ctr` | 0.9.2 | `0369ee1ad6718345…` | **vendored** (`ref/crates/ctr-0.9.2`, Program B) |

Do not use crates.io at build time for product gates; pin trees under this directory
(or a submodule) so builds are hermetic.
