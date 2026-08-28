//! Golden vectors for Carbonado RS 4/8 (matches stream/fec + reed-solomon-erasure 5.0.3).
use reed_solomon_erasure::galois_8::{self, Field};
use reed_solomon_erasure::ReedSolomon;

fn hex(b: &[u8]) -> String {
    hex::encode(b)
}

fn calc_padding_len(input_len: usize) -> (u32, u32) {
    if input_len == 0 {
        return (0, 0);
    }
    let stripe = 4096usize * 4;
    let target = input_len.div_ceil(stripe) * stripe;
    let padding_len = (target - input_len) as u32;
    let chunk_size = (target / 4) as u32;
    (padding_len, chunk_size)
}

fn encode_inboard(input: &[u8]) -> (Vec<u8>, u32, u32) {
    if input.is_empty() {
        return (vec![], 0, 0);
    }
    let (pad, chunk) = calc_padding_len(input.len());
    let chunk = chunk as usize;
    let mut data = input.to_vec();
    data.resize(input.len() + pad as usize, 0);
    let r = ReedSolomon::<Field>::new(4, 4).unwrap();
    let mut shards: Vec<Vec<u8>> = (0..4)
        .map(|i| data[i * chunk..(i + 1) * chunk].to_vec())
        .collect();
    for _ in 0..4 {
        shards.push(vec![0u8; chunk]);
    }
    r.encode(&mut shards).unwrap();
    let mut out = Vec::with_capacity(8 * chunk);
    for s in &shards {
        out.extend_from_slice(s);
    }
    (out, pad, chunk as u32)
}

fn main() {
    println!("=== GF(2^8) samples ===");
    for (a, b) in [(0x53u8, 0xcau8), (2, 3), (7, 11), (0xff, 1)] {
        println!("mul({:02x},{:02x}) = {:02x}", a, b, galois_8::mul(a, b));
        if b != 0 {
            println!("div({:02x},{:02x}) = {:02x}", a, b, galois_8::div(a, b));
        }
        println!("exp({:02x},3) = {:02x}", a, galois_8::exp(a, 3));
    }

    println!("\n=== padding geometry ===");
    for n in [0usize, 1, 100, 4096, 16384, 16385] {
        let (p, c) = calc_padding_len(n);
        println!("pad({}) = ({}, {})", n, p, c);
    }

    let r = ReedSolomon::<Field>::new(4, 4).unwrap();
    println!("\n=== RS 4/8 len1 ===");
    let mut s = vec![
        vec![1u8],
        vec![2],
        vec![3],
        vec![4],
        vec![0],
        vec![0],
        vec![0],
        vec![0],
    ];
    r.encode(&mut s).unwrap();
    println!(
        "parity = {:02x}{:02x}{:02x}{:02x}",
        s[4][0], s[5][0], s[6][0], s[7][0]
    );

    println!("\n=== RS 4/8 seq8 ===");
    let mut s8: Vec<Vec<u8>> = (0..4)
        .map(|i| (0..8).map(|j| (i * 8 + j) as u8).collect())
        .collect();
    for _ in 0..4 {
        s8.push(vec![0u8; 8]);
    }
    r.encode(&mut s8).unwrap();
    for (i, sh) in s8.iter().enumerate() {
        println!("s{} = {}", i, hex(sh));
    }

    println!("\n=== Carbonado inboard hello ===");
    let (body, pad, chunk) = encode_inboard(b"hello");
    println!("pad={} chunk={} len={}", pad, chunk, body.len());
    println!("head = {}", hex(&body[..16]));

    println!("\n=== Carbonado inboard pat100 ===");
    let pat: Vec<u8> = (0..100).map(|i| (i % 251) as u8).collect();
    let (body, pad, chunk) = encode_inboard(&pat);
    println!("pad={} chunk={} len={}", pad, chunk, body.len());
    let shard_len = body.len() / 8;
    println!("parity0_head8 = {}", hex(&body[4 * shard_len..4 * shard_len + 8]));
}
