//! Helpers for exhaustive format-combination integration tests (c0–c15).

use carbonado::constants::Format;

/// Human-readable label for a format level (e.g. `c14`).
pub fn format_label(level: u8) -> String {
    format!("c{level}")
}

/// All 16 pipeline combinations.
pub const ALL_FORMAT_LEVELS: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

/// Formats with Reed-Solomon FEC (bit 3).
pub fn zfec_levels() -> impl Iterator<Item = u8> {
    ALL_FORMAT_LEVELS.into_iter().filter(|l| l & 8 != 0)
}

/// Formats with Bao verifiability (bit 2) — required for `scrub`.
pub fn bao_levels() -> impl Iterator<Item = u8> {
    ALL_FORMAT_LEVELS.into_iter().filter(|l| l & 4 != 0)
}

/// Bao + Zfec (scrub-capable inboard).
pub fn bao_zfec_levels() -> impl Iterator<Item = u8> {
    ALL_FORMAT_LEVELS.into_iter().filter(|l| l & 12 == 12)
}

/// Non-encrypted Zfec (deterministic re-encode).
pub fn public_zfec_levels() -> impl Iterator<Item = u8> {
    zfec_levels().filter(|l| l & 1 == 0)
}

/// Primary production / directory-related levels.
pub const PRODUCTION_LEVELS: [u8; 6] = [4, 5, 6, 7, 12, 14];

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
