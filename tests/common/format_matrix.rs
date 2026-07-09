//! Helpers for exhaustive format-combination integration tests (c0–c15).

use carbonado::constants::Format;

/// Human-readable label for a format level (e.g. `c14`).
pub fn format_label(level: u8) -> String {
    format!("c{level}")
}

/// All 16 pipeline combinations.
pub const ALL_FORMAT_LEVELS: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

/// Formats with FEC (bit 3).
pub fn fec_levels() -> impl Iterator<Item = u8> {
    ALL_FORMAT_LEVELS.into_iter().filter(|l| l & 8 != 0)
}

/// Formats with Bao verifiability (bit 2) — required for `scrub`.
pub fn verification_levels() -> impl Iterator<Item = u8> {
    ALL_FORMAT_LEVELS.into_iter().filter(|l| l & 4 != 0)
}

/// Verification + Fec (scrub-capable inboard).
pub fn verification_fec_levels() -> impl Iterator<Item = u8> {
    ALL_FORMAT_LEVELS.into_iter().filter(|l| l & 12 == 12)
}

/// Non-encrypted Fec (deterministic re-encode).
pub fn public_fec_levels() -> impl Iterator<Item = u8> {
    fec_levels().filter(|l| l & 1 == 0)
}

/// Primary production / directory-related levels (directory segments: c12–c15).
pub const PRODUCTION_LEVELS: [u8; 4] = [12, 13, 14, 15];

/// Parse `Format` bitmask for assertions.
pub fn format_bits(level: u8) -> Format {
    Format::from(level)
}

/// Scenario name for matrix parametrized tests.
pub fn scenario_name(level: u8, encrypted: bool, payload_kind: &str) -> String {
    format!(
        "{}-{}-{}",
        format_label(level),
        if encrypted { "enc" } else { "pub" },
        payload_kind
    )
}
