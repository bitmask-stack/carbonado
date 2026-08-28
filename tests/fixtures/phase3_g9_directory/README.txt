Phase 3 G9 directory seed (public c14).

Live rust encode of `a.txt` = "phase3 g9 hello" and `sub/b.bin` = "nested data"
with zstd level 20. Catalog Bao root is FilepackManifest v3 (dict offset fields).

Regenerate with:
  carbonado encode <src> --zstd-level 20 --output tests/fixtures/phase3_g9_directory
and update LIVE_RUST_DIR_CATALOG_ROOT / PHASE3_SEED_DIR_CATALOG_ROOT in
tests/determinism_roundtrip.rs.
