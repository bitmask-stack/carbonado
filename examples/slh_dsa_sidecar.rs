//! Example: Create a Carbonado archive and produce a SLH-DSA (post-quantum)
//! sidecar signature over its Bao hash.
//!
//! This is the intended use of SLH-DSA in Carbonado: signing manifests,
//! catalogs, or important checkpoints as *separate* sidecar files, never
//! inside the per-segment .cXX containers.
//!
//! See AGENTS.md §2.3 for the exact sidecar format and security model.

use carbonado::crypto::{slh_dsa_generate_keypair, slh_dsa_sign, slh_dsa_verify};
use carbonado::file::{encode, Header};
use getrandom::getrandom;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // === 1. Create some data and encode it ===
    let master_key = {
        let mut k = [0u8; 32];
        getrandom(&mut k)?;
        k
    };

    let important_data = b"This could be a manifest, a checkpoint, or a critical archive.";

    let (encoded, _info) = encode(&master_key, important_data, 15, None)?;

    // The high-level encode includes a Header. Parse it to get the authoritative Bao hash
    // that represents this archive (this is the value we sign for a sidecar).
    let header = Header::try_from(&encoded[..Header::LEN])?;
    let bao_hash = header.hash;

    println!(
        "Created Carbonado archive with Bao hash: {}",
        carbonado::utils::encode_bao_hash(&bao_hash)
    );

    // === 2. Generate a SLH-DSA keypair (post-quantum) ===
    let mut entropy = [0u8; 128];
    getrandom(&mut entropy)?;

    let keypair = slh_dsa_generate_keypair(&entropy)?;
    println!("Generated SLH-DSA keypair (pk = 32 bytes, sk = 64 bytes)");

    // === 3. Sign the Bao hash (or a higher-level structure containing it) ===
    // The Bao hash (and thus the signature) corresponds to the specific Format combination
    // used for this segment. With 16 possible combinations, the hash is multi-dimensional:
    // it names a particular (data + processing pipeline) result. See AGENTS.md §2.3.
    // For a real sidecar you would typically sign a canonical manifest that
    // includes the hash, timestamp, description, etc.
    let message_to_sign = bao_hash.as_bytes();

    let signature = slh_dsa_sign(&keypair.secret_key, message_to_sign)?;
    println!(
        "Produced SLH-DSA signature ({} bytes)",
        signature.bytes.len()
    );

    // === 4. (Optional but recommended) Persist the sidecar ===
    // A real implementation would write something like:
    //   <bao-hash>.c15.slh
    // containing: b"SLH1" (4 bytes) + signature (7856 bytes).
    //
    // The 32-byte SLH-DSA public key now lives in the Carbonado Header
    // (header.slh_public_key) of the referenced archive. The sidecar only
    // carries the signature (over the Bao hash or a higher-level manifest).
    //
    // For this example we just keep everything in memory.

    // === 5. Verification (done by anyone who has the public key) ===
    let valid = slh_dsa_verify(&keypair.public_key, message_to_sign, &signature)?;
    println!("Signature verification result: {}", valid);

    assert!(valid);

    // Tamper test
    let mut tampered = message_to_sign.to_vec();
    tampered[0] ^= 0x01;
    let still_valid = slh_dsa_verify(&keypair.public_key, &tampered, &signature)?;
    println!("Tampered message verification result: {}", still_valid);
    assert!(!still_valid);

    println!("\nSLH-DSA sidecar signing example completed successfully.");
    println!("Remember: SLH-DSA public key is stored in the Carbonado Header; only the signature is handled in the sidecar. Never embed signatures inside the container.");

    Ok(())
}
