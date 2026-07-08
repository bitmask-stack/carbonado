//! Compile-time checks that one-release deprecation aliases resolve.
#![allow(deprecated)]

use carbonado::{
    pack_index, PackEntry, PackIndex, PackSegmentRef, MAX_PACK_ENTRIES, PACK_INDEX_FORMAT_LEVEL,
    PACK_INDEX_FORMAT_LEVEL_ENCRYPTED, PACK_INDEX_FORMAT_LEVEL_PUBLIC, PACK_INDEX_VERSION,
};

#[test]
fn deprecated_crate_root_type_aliases_compile() {
    fn _uses_pack_index(_: PackIndex) {}
    fn _uses_pack_entry(_: PackEntry) {}
    fn _uses_segment_ref(_: PackSegmentRef) {}
    let _ = PACK_INDEX_VERSION;
    let _ = PACK_INDEX_FORMAT_LEVEL;
    let _ = PACK_INDEX_FORMAT_LEVEL_PUBLIC;
    let _ = PACK_INDEX_FORMAT_LEVEL_ENCRYPTED;
    let _ = MAX_PACK_ENTRIES;
}

#[test]
fn deprecated_pack_index_submodule_aliases_compile() {
    fn _uses_submodule_index(_: pack_index::PackIndex) {}
    fn _uses_submodule_entry(_: pack_index::PackEntry) {}
    fn _uses_submodule_segment(_: pack_index::PackSegmentRef) {}
    let _ = pack_index::PACK_INDEX_VERSION;
    let _ = pack_index::PACK_INDEX_FORMAT_LEVEL;
    let _ = pack_index::PACK_INDEX_FORMAT_LEVEL_PUBLIC;
    let _ = pack_index::PACK_INDEX_FORMAT_LEVEL_ENCRYPTED;
    let _ = pack_index::MAX_PACK_ENTRIES;
}
