//! Golden vectors for Carbonado keyed Bao (bao-tree 76-keyed-bao, 4 KiB groups).
use std::io::Cursor;

use bao_tree::{
    blake3,
    io::{
        outboard::{EmptyOutboard, PostOrderMemOutboard},
        sync::{keyed_decode_ranges, keyed_encode_ranges_validated, keyed_outboard_post_order},
    },
    BaoTree, BlockSize, ChunkNum, ChunkRanges,
};

const BAO_BLOCK_SIZE: BlockSize = BlockSize::from_chunk_log(2);
const CTX: &str = "carbonado-v2/verification";

fn hex(b: &[u8]) -> String {
    hex::encode(b)
}

fn verification_key(format: u8) -> [u8; 32] {
    blake3::derive_key(CTX, &[format])
}

fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn inboard_encode(data: &[u8], format: u8) -> (Vec<u8>, [u8; 32]) {
    let key = verification_key(format);
    let content_len = data.len() as u64;
    let tree = BaoTree::new(content_len, BAO_BLOCK_SIZE);
    let mut sidecar = Vec::new();
    let root = keyed_outboard_post_order(Cursor::new(data), tree, &mut sidecar, &key).unwrap();
    let ob = PostOrderMemOutboard {
        root,
        tree,
        data: sidecar,
    };
    let mut out = Vec::new();
    out.extend_from_slice(&content_len.to_le_bytes());
    keyed_encode_ranges_validated(data, &ob, &ChunkRanges::all(), &mut out, &key).unwrap();
    (out, *root.as_bytes())
}

fn outboard_encode(data: &[u8], format: u8) -> (Vec<u8>, [u8; 32]) {
    let key = verification_key(format);
    let ob = PostOrderMemOutboard::create_keyed(data, BAO_BLOCK_SIZE, &key);
    (ob.data, *ob.root.as_bytes())
}

fn main() {
    println!("=== verification keys ===");
    for f in [0u8, 4, 6, 12, 14, 15] {
        println!("key_c{:02x} = {}", f, hex(&verification_key(f)));
    }

    println!("\n=== blake3 goldens ===");
    println!("hash(empty) = {}", hex(blake3::hash(b"").as_bytes()));
    println!("hash(abc) = {}", hex(blake3::hash(b"abc").as_bytes()));
    let k0 = verification_key(4);
    println!("keyed_hash(c4, empty) = {}", hex(blake3::keyed_hash(&k0, b"").as_bytes()));
    println!("keyed_hash(c4, hello) = {}", hex(blake3::keyed_hash(&k0, b"hello").as_bytes()));
    let pat100 = patterned(100);
    println!("keyed_hash(c4, pat100) = {}", hex(blake3::keyed_hash(&k0, &pat100).as_bytes()));
    let pat4096 = patterned(4096);
    println!("keyed_hash(c4, pat4096) = {}", hex(blake3::keyed_hash(&k0, &pat4096).as_bytes()));
    let pat5000 = patterned(5000);
    println!("keyed_hash(c4, pat5000) = {}", hex(blake3::keyed_hash(&k0, &pat5000).as_bytes()));

    println!("\n=== keyed roots (create_keyed == keyed_hash) ===");
    for &len in &[0usize, 1, 100, 1024, 4095, 4096, 4097, 8192] {
        let data = patterned(len);
        let key = verification_key(4);
        let root = PostOrderMemOutboard::create_keyed(&data, BAO_BLOCK_SIZE, &key).root;
        let direct = blake3::keyed_hash(&key, &data);
        assert_eq!(root, direct);
        println!("root_c4_len{} = {}", len, hex(root.as_bytes()));
    }
    // format domain separation same data
    let data = patterned(100);
    for f in [4u8, 6, 14] {
        let key = verification_key(f);
        let root = PostOrderMemOutboard::create_keyed(&data, BAO_BLOCK_SIZE, &key).root;
        println!("root_c{:02x}_len100 = {}", f, hex(root.as_bytes()));
    }

    println!("\n=== outboard sidecars ===");
    for &len in &[0usize, 1, 100, 4096, 5000] {
        let data = patterned(len);
        let (ob, root) = outboard_encode(&data, 4);
        println!("out_c4_len{} root={} len={} hex={}", len, hex(&root), ob.len(), hex(&ob));
    }

    println!("\n=== inboard (prefix+response) ===");
    for &len in &[0usize, 1, 5, 100, 4096, 5000] {
        let data = if len == 5 {
            b"hello".to_vec()
        } else {
            patterned(len)
        };
        let (ib, root) = inboard_encode(&data, 4);
        println!(
            "in_c4_len{} root={} total={} head32={}",
            if len == 5 { 5 } else { len },
            hex(&root),
            ib.len(),
            hex(&ib[..ib.len().min(32)])
        );
        if ib.len() <= 200 {
            println!("  full = {}", hex(&ib));
        } else {
            println!("  tail16 = {}", hex(&ib[ib.len() - 16..]));
        }
    }

    // wrong format fails decode
    println!("\n=== wrong key fails ===");
    let data = patterned(100);
    let (ib, root) = inboard_encode(&data, 4);
    let key_wrong = verification_key(6);
    let content_len = u64::from_le_bytes(ib[0..8].try_into().unwrap());
    let tree = BaoTree::new(content_len, BAO_BLOCK_SIZE);
    let mut ob = EmptyOutboard {
        tree,
        root: blake3::Hash::from(root),
    };
    let mut out = vec![0u8; content_len as usize];
    let res = keyed_decode_ranges(
        Cursor::new(&ib[8..]),
        &ChunkRanges::all(),
        &mut out[..],
        &mut ob,
        &key_wrong,
    );
    println!("decode_wrong_key_err = {:?}", res.err().map(|e| format!("{e}")));

    // slice range: first 4 KiB of 5000-byte file
    println!("\n=== slice first group (5000 bytes, chunks 0..4) ===");
    let data = patterned(5000);
    let key = verification_key(4);
    let tree = BaoTree::new(5000, BAO_BLOCK_SIZE);
    let mut sidecar = Vec::new();
    let root = keyed_outboard_post_order(Cursor::new(&data), tree, &mut sidecar, &key).unwrap();
    let ob = PostOrderMemOutboard {
        root,
        tree,
        data: sidecar,
    };
    // chunk group = 4 chunks of 1024 = 4096 bytes → ChunkNum 0..4
    let ranges = ChunkRanges::from(ChunkNum(0)..ChunkNum(4));
    let mut slice_enc = Vec::new();
    keyed_encode_ranges_validated(&data[..], &ob, &ranges, &mut slice_enc, &key).unwrap();
    println!("slice_c4_5000_0_4 root={} enc_len={} head48={}", hex(root.as_bytes()), slice_enc.len(), hex(&slice_enc[..slice_enc.len().min(48)]));
    if slice_enc.len() <= 256 {
        println!("  full = {}", hex(&slice_enc));
    }

    // Three-leaf tree (12288 B) + middle slice stream decode
    println!("\n=== three-leaf 12288 ===");
    let data = patterned(12288);
    let (ib, root) = inboard_encode(&data, 4);
    let (ob, root2) = outboard_encode(&data, 4);
    assert_eq!(root, root2);
    println!(
        "in_c4_len12288 root={} total={} outboard_len={}",
        hex(&root),
        ib.len(),
        ob.len()
    );
    let key = verification_key(4);
    let tree = BaoTree::new(12288, BAO_BLOCK_SIZE);
    let mut sidecar = Vec::new();
    let root_h = keyed_outboard_post_order(Cursor::new(&data), tree, &mut sidecar, &key).unwrap();
    let pom = PostOrderMemOutboard {
        root: root_h,
        tree,
        data: sidecar,
    };
    // second leaf group: blake3 chunks 4..8
    let ranges = ChunkRanges::from(ChunkNum(4)..ChunkNum(8));
    let mut mid = Vec::new();
    keyed_encode_ranges_validated(&data[..], &pom, &ranges, &mut mid, &key).unwrap();
    println!(
        "slice_c4_12288_leaf1 enc_len={} head48={}",
        mid.len(),
        hex(&mid[..mid.len().min(48)])
    );
    // stream decode without trusting full plaintext buffer contents beforehand
    let mut decoded = vec![0u8; 12288];
    let mut eob = EmptyOutboard {
        tree,
        root: root_h,
    };
    keyed_decode_ranges(Cursor::new(&mid), &ranges, &mut decoded[..], &mut eob, &key).unwrap();
    assert_eq!(&decoded[4096..8192], &data[4096..8192]);
    println!("slice_c4_12288_leaf1 stream_decode ok");

    println!("\nok");
}
