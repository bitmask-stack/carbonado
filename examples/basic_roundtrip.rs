//! Basic secure roundtrip using Carbonado v2 symmetric API.
//!
//! This demonstrates the recommended way to encrypt and decrypt data
//! with the new symmetric design (AES-256-CTR + HMAC-SHA512 EtM).
//!
//! Security notes:
//! - Master key must have at least 256 bits of entropy.
//! - Never reuse a master key across unrelated datasets without rotation.
//! - See AGENTS.md §2 for full invariants, nonce rules, and recommendations.

use carbonado::{decode, encode};
use getrandom::getrandom;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a fresh 32-byte master key.
    // In real applications this would come from a secure source (e.g. key derivation,
    // hardware wallet, or properly managed secret).
    let mut master_key = [0u8; 32];
    getrandom(&mut master_key)?;

    let plaintext = b"Hello, this is a test of the Carbonado v2 symmetric format. \
                     This data will be compressed, encrypted, FEC-protected, and verifiable.";

    println!("Original size: {} bytes", plaintext.len());

    // Level 15 = full features: Encrypted (symmetric AES-256-CTR + HMAC) + Zstd(level 20) + Bao + Zfec (RS)
    let level = 15u8;

    // Using the low-level encode/decode API here for the demo.
    // Most production code will prefer the high-level carbonado::file API.
    let encoded = encode(&master_key, plaintext, level)?;

    println!("Encoded size: {} bytes", encoded.0.len());
    println!(
        "Amplification factor: {:.2}x",
        encoded.2.amplification_factor
    );

    // Decode
    let recovered = decode(
        &master_key,
        encoded.1.as_bytes(),
        &encoded.0,
        encoded.2.padding_len,
        level,
    )?;

    assert_eq!(recovered, plaintext);
    println!("Roundtrip successful!");
    println!("Recovered {} bytes", recovered.len());

    Ok(())
}
