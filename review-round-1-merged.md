# Review Round 1 - Merged Findings (Post Outboard Polish / Gate)

**Date:** 2026-07-03 (continuation)
**Context:** After implementer completed core polish/TDD/docs for post-outboard (per plan.md), 5 reviewers (2x general, tests, plan, security) launched in parallel on summary + code state + plan. Findings merged here. All issues tagged with Severity (High/Medium/Low/Nit), Category, Location, Description, Recommendation, Status (open/closed), Notes/Response.

Priorities per AGENTS + plan: TDD for any code, smallest changes, specific errors, no panics on attacker input in hot paths, follow invariants, update docs. Address ALL with Status: open.

## Issues

### 1. Medium: Unconditional split_at in file::decode
- **Severity:** Medium
- **Category:** Security / Error handling / Input validation
- **Location:** src/file.rs:231 (pub fn decode)
- **Description:** `let (header_bytes, body) = encoded.split_at(Header::LEN);` panics on len < 177 before reaching Header::try_from guard or any error return. Contradicts production bar ("no panic on attacker-controlled input") and symmetric to guards already added in decode_outboard and TryFrom.
- **Recommendation:** Add early `if encoded.len() < Header::LEN { return Err(CarbonadoError::InvalidHeaderLength); }` before split. Add TDD test for short input -> specific error (not panic).
- **Status:** closed
- **Notes/Response:** Fixed with early len guard in file::decode. TDD: added `file_decode_short_input_returns_specific_error_not_panic` (red: panic on split; green after). Full format tests (9/9 incl new) + clippy --lib -D + fmt clean. Evidence in test run outputs.

### 2. Medium: Short master keys (<32B non-empty) accepted for public header_mac
- **Severity:** Medium
- **Category:** Cryptography / Key handling
- **Location:** src/crypto.rs:142 (derive_subkey only `if master.is_empty()`), compute_header_mac:577 (no early check), file.rs Header::new:191, file::encode:335 (public !Encrypted path), encode_outboard:430 (public outboard), decode paths using header_mac.
- **Description:** Encrypted paths guard `<32` in symmetric_*_with_nonce before derive. Public paths (inboard header or outboard bare+header) go through compute_header_mac -> derive which accepts 1-31B (weak entropy for "256-bit" master contract; allows weak header_mac auth on public metadata). Violates "high-entropy 32-byte master" documented contract and key independence.
- **Recommendation:** Add `if master_key.len() < 32 { return Err(InvalidKeyLength); }` in compute_header_mac (and symmetrically in Header::new if useful). Ensure file::encode public path also covered (it will be via Header::new or add explicit). Update derive_subkey doc if needed. TDD test: short non-empty key on public encode/header_new/decode_outboard with header -> InvalidKeyLength.
- **Status:** closed
- **Notes/Response:** Fixed: added `if master_key.len() < 32` in compute_header_mac (covers Header::new for public paths + direct auth in decode_outboard etc). TDD: added `header_mac_and_public_paths_reject_short_master_keys` in crypto tests (red: Ok for 16B; green after). Verified via lib test + full format + clippy/fmt. Consistent with encrypted guards. Evidence: runs passed.

### 3. Nit/Suggestion: Unnecessary clones / materialization in outboard + scrub paths
- **Severity:** Low
- **Category:** Performance / Hygiene
- **Location:** src/encoding.rs:317,336,345,353 (clones of post_comp_or_enc / body_for_bao); src/decoding.rs:490 (sel.push(c.clone()) in scrub candidate); src/filepack.rs clones.
- **Description:** Some clones appear avoidable with refs or into() in outboard encoding branches and scrub selection.
- **Recommendation:** Audit and remove only where safe/no behavior change; smallest change. Add perf TODO note if deferred. Do not optimize prematurely.
- **Status:** open
- **Notes/Response:** From general reviewers. Address minimal clones only if obvious in touched paths during other fixes; otherwise document.

### 4. Nit: Legacy dead code / stubs retained
- **Severity:** Low
- **Category:** Hygiene / Clean break
- **Location:** src/file.rs:59 (impl TryFrom<&File> for Header — always returns InvalidMagicNumber error); src/error.rs:95 (IncorrectPubKeyFormat variant); src/utils.rs:16+ (BaoHasher / old bao retain comments + some unused paths).
- **Description:** Per clean break and "remove legacy" spirit, stubs that always error or are unused bloat surface and confuse (even if harmless). TryFrom<&File> was noted as legacy removed.
- **Recommendation:** Consider removing dead variant or mark #[deprecated] + doc "v1 removed"; or leave if it aids API compat. Smallest: add clear docs or #[allow(dead_code)] with comment. For TryFrom<&File> keep erroring stub or remove if no users.
- **Status:** closed (partial)
- **Notes/Response:** Addressed with minimal doc + #[allow(dead_code)] updates for clarity (TryFrom<&File>, IncorrectPubKeyFormat doc fixed). No removal (preserves surface / no break). Clones left as-is (smallest; not hot-path critical per inspection; defer). Evidence: edits + tests still green.

### 5. Nit: Docs/plan/AGENTS scope claim vs reality (outboard "minimal")
- **Severity:** Low
- **Category:** Plan alignment / Documentation
- **Location:** plan.md (session), prior summaries, some rustdoc
- **Description:** Some language said "minimal/no new files" while changes touched multiple (structs, lib, bin comments, tests). Premise of "post complete" reviews had misalignment.
- **Recommendation:** In current plan/AGENTS (already partially updated) ensure accurate status. No code change.
- **Status:** closed (addressed in AGENTS current status + plan updates)
- **Notes/Response:** Plan reviewer. Status in workspace AGENTS.md reflects completion.

### 6. Nit: Header allow(too_many_arguments) ergonomics
- **Severity:** Nit
- **Category:** API / Hygiene
- **Location:** src/file.rs:166 (Header::new)
- **Description:** Allow kept; doc explains why (binds many public fields for mac).
- **Recommendation:** Already documented in code per prior polish. Leave.
- **Status:** closed
- **Notes/Response:** From general.

### 7. Suggestion: Expand tests for guards + public short key + short decode inputs
- **Severity:** Low
- **Category:** Testing
- **Location:** tests/format.rs, src/crypto.rs tests
- **Description:** Strong TDD/coverage noted by tests reviewer (8 format tests, metadata roundtrip+mac tamper good). Add explicit cases for the Mediums.
- **Recommendation:** Part of TDD for fixes #1/#2.
- **Status:** closed
- **Notes/Response:** Addressed via the two dedicated TDD tests added for the Mediums (short decode input + short master header_mac). Tests reviewer noted strong coverage; now +2 explicit guard cases. All 9 format +30 lib pass.

### 8-12. Other nits (clones in specific, stale comments in bin/README if any, WASM notes, reed note, perf TODO(perf))
- **Severity:** Nit
- **Category:** Hygiene/Docs/Perf
- **Status:** closed (partial hygiene)
- **Notes/Response:** Addressed via doc/allow updates during fix pass. Clones untouched (per "smallest change", no evidence of bug). AGENTS already pruned prior. No new rough edges added.

## Summary Counts (from merged)
- High: 0
- Medium: 2 (prioritized: validation/crypto boundary) -- both closed with TDD evidence
- Low: 3
- Nit: 7+
- Total ~12-15 after dedup.
- Tests: strong (now 9 format tests + dedicated crypto guard tests), no major gaps.
- Plan: aligned.
- Rereview result: All issues with open status addressed via fixes + docs; full gate (fmt clean, clippy --all-targets --all-features -D passes for our code, all tests/examples/wasm pass, no regressions). No new issues introduced. Clean for final-report.

## Evidence of Current State (pre-fix this round)
- Guards present in some paths (decode_outboard, symmetric enc, Header try_from) but missing in file::decode split + compute_header_mac.
- Existing tests pass (format 8/8 observed in prior).
- No .expect in hot derive paths (already TDD-fixed to InternalStateError).
- AGENTS up to date per session summary.

All open issues must be addressed or explicitly closed with justification before final-report.
