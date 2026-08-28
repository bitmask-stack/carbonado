//! Directory archive helpers (format policy, layout invariants).

pub mod format_policy;

pub use format_policy::{
    SEGMENT_FORMAT_ENCRYPTED_COMPRESSED, SEGMENT_FORMAT_ENCRYPTED_RAW,
    SEGMENT_FORMAT_PUBLIC_COMPRESSED, SEGMENT_FORMAT_PUBLIC_RAW, SegmentFormatPolicy,
    resolve_catalog_format,
};
