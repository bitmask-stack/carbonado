# R9/W3 rkyv FilepackManifestWire goldens

Pinned Rust `rkyv` 0.8.16 + `unaligned` wire for pure Lean encode **and** decode
(`Carbonado/RkyvFilepack.lean`).

| File | Description |
|------|-------------|
| `empty_manifest.bin` | version=2, format_level=c14, 0 entries (13 B) |
| `single_entry.bin` | one entry `a.txt`, one SegmentRef, no OTS (131 B) |
| `multi_entry_ots.bin` | two entries (`a.txt` + ool long path) + OTS Some on second (275 B) |
| `path_inline_8.bin` | exactly 8-byte path (inline boundary) |
| `path_ool_9.bin` | exactly 9-byte path (out-of-line boundary) |
| `two_segments.bin` | one entry, two SegmentRefs |
| `ots_first_only.bin` | OTS Some on first entry only; second None |
| `rkyv_cfp2_prefix.bin` | rkyv body starting with ASCII `CFP2` (dual-decode sniffer regression) |

Regenerate:

```bash
cargo run --example dump_rkyv_r9 --features backend-rust
# Also update Carbonado/RkyvFilepack.lean golden*Hex constants (must stay bit-identical).
# CI lock: tests/rkyv_golden_lock.rs asserts fixture bins == Lean hex constants.
```

**W3 acceptance:** Lean `encodeRkyvManifest` must bit-match these fixtures (encode twice → same bytes).
AOT demo greps: `rkyv FilepackManifestWire encode/decode goldens ok`.

Rust directory encode uses this rkyv wire. Pure Lean `encodeRkyvManifest` must bit-match
these fixtures. There is no Cargo Lean directory encoder.
