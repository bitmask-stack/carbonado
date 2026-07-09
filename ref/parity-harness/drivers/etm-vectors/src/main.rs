//! Golden vectors for Carbonado v2 EtM (matches src/crypto.rs semantics).
use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes256;
use ctr::Ctr128BE;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha512};

type HmacSha512 = Hmac<Sha512>;

fn derive_subkey(master: &[u8], label: &str) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(master).unwrap();
    mac.update(b"carbonado-v2/");
    mac.update(label.as_bytes());
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

fn aes_ctr(key: &[u8; 32], nonce: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut cipher = Ctr128BE::<Aes256>::new(key.into(), nonce.into());
    let mut out = data.to_vec();
    cipher.apply_keystream(&mut out);
    out
}

fn etm_encrypt(master: &[u8], nonce: [u8; 16], pt: &[u8]) -> Vec<u8> {
    let enc = derive_subkey(master, "aes-ctr");
    let mac_key = derive_subkey(master, "etm-hmac");
    let aes_key: [u8; 32] = enc[..32].try_into().unwrap();
    let ct = aes_ctr(&aes_key, &nonce, pt);
    let mut mac = HmacSha512::new_from_slice(&mac_key).unwrap();
    mac.update(b"carbonado-v2-etm");
    mac.update(&nonce);
    mac.update(&ct);
    let tag = mac.finalize().into_bytes();
    let mut out = Vec::with_capacity(64 + ct.len());
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ct);
    out
}

fn header_mac(master: &[u8], auth_data: &[u8]) -> [u8; 64] {
    let key = derive_subkey(master, "header-auth");
    let mut mac = HmacSha512::new_from_slice(&key).unwrap();
    mac.update(auth_data);
    let r = mac.finalize().into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&r);
    out
}

fn hex(b: &[u8]) -> String {
    hex::encode(b)
}

fn main() {
    println!("=== SHA-512 ===");
    for msg in [&b""[..], &b"abc"[..], &b"The quick brown fox jumps over the lazy dog"[..]] {
        let d = Sha512::digest(msg);
        println!("sha512 len={} = {}", msg.len(), hex(&d));
    }

    println!("\n=== HMAC-SHA512 RFC4231-1 ===");
    let key = [0x0bu8; 20];
    let data = b"Hi There";
    let mut mac = HmacSha512::new_from_slice(&key).unwrap();
    mac.update(data);
    println!("hmac = {}", hex(&mac.finalize().into_bytes()));

    println!("\n=== AES-256-CTR NIST ===");
    let key: [u8; 32] = [
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
    ];
    let counter: [u8; 16] = [
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
    ];
    let pt: [u8; 64] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    ];
    let ct = aes_ctr(&key, &counter, &pt);
    println!("nist_ct = {}", hex(&ct));

    let master = [0x42u8; 32];
    let nonce = [0x11u8; 16];
    println!("\n=== Carbonado subkeys ===");
    for label in ["aes-ctr", "etm-hmac", "header-auth"] {
        let sk = derive_subkey(&master, label);
        println!("subkey({}) = {}", label, hex(&sk));
    }

    println!("\n=== Carbonado EtM header-path [tag|ct] ===");
    for (name, pt) in [
        ("empty", &b""[..]),
        ("hello", &b"hello"[..]),
        ("block16", &[0u8; 16][..]),
        ("block32", &[0xABu8; 32][..]),
        ("multi", &b"The quick brown fox jumps over the lazy dog"[..]),
        ("block64", &[0x5Au8; 64][..]),
    ] {
        let out = etm_encrypt(&master, nonce, pt);
        println!("{} pt_len={} blob={}", name, pt.len(), hex(&out));
    }

    let out = etm_encrypt(&master, nonce, b"hello");
    let mut low = Vec::new();
    low.extend_from_slice(&nonce);
    low.extend_from_slice(&out);
    println!("\nlow_level_hello = {}", hex(&low));

    let magic = b"CARBONADO20\n";
    let hm = header_mac(&master, magic);
    println!("\nheader_mac(MAGIC) = {}", hex(&hm));

    let mut auth = Vec::new();
    auth.extend_from_slice(magic);
    auth.extend_from_slice(&nonce);
    auth.extend_from_slice(&[0xCDu8; 32]);
    auth.extend_from_slice(&[0x00u8; 32]);
    auth.push(0x05);
    auth.extend_from_slice(&0u32.to_le_bytes());
    auth.extend_from_slice(&100u32.to_le_bytes());
    auth.extend_from_slice(&0u32.to_le_bytes());
    auth.extend_from_slice(&[0u8; 8]);
    assert_eq!(auth.len(), 12 + 16 + 32 + 32 + 1 + 4 + 4 + 4 + 8);
    let hm2 = header_mac(&master, &auth);
    println!("header_mac(sample_auth) len={} = {}", auth.len(), hex(&hm2));
}
