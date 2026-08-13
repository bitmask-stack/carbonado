G9 directory seed: rust-encoded Adamantine 1.0 archive (backend-rust / CLI).
Used by tests/lean_backend_phase3.rs for rust-encode → lean-decode extract.

**Decode-only SSOT** for dual-suite interop. Catalog root is **not** a live
re-encode golden: current backend-rust re-encode of the same tree yields a
different catalog root (see LIVE_RUST_DIR_CATALOG_ROOT in
tests/determinism_roundtrip.rs) while segment mains may still match. Cross-engine
encode residual is live-rust vs live-lean (W2b), not lean-vs-this-seed.

Source tree (public c14 catalog, zero master):
  a.txt       = "phase3 g9 hello"
  sub/b.bin   = "nested data"

Segment formats follow auto policy (both small texts → c14).
Catalog seed: 16e2369f4f4465014e5e92740e3f76403f681cd60c01f7605ee11acd5423024f.adam.c14

Regenerate (only when intentionally refreshing the decode seed; update
lean_backend_phase3 hard-coded path + this README):
  printf 'phase3 g9 hello' > /tmp/src/a.txt
  mkdir -p /tmp/src/sub && printf 'nested data' > /tmp/src/sub/b.bin
  cargo run --features cli --bin carbonado -- encode /tmp/src -o tests/fixtures/phase3_g9_directory
