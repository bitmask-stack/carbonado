# Streaming Memory & Parallelism

Carbonado 2.x is **streaming-first in API shape** but not yet **streaming-complete in memory**. This document records current behavior, parallelization opportunities, hard limits, and the path to minimal-memory encode/decode for JBOD, UDP, and P2P workloads.

## Current pipeline (per segment)

```text
Read (64 KiB chunks)
  → stream_preprocess (compress / encrypt) → seekable Vec staging
  → stream_encode_inboard_body (FEC + Bao) → often full-body read
  → Header + write

Decode:
  → read full body Vec
  → Bao verify / slice extract
  → zfec (RS reconstruct)
  → decrypt / decompress stream to output
```

## Memory model today

| Stage | Streaming read? | Peak memory |
|-------|-----------------|-------------|
| `stream_preprocess` | Yes (64 KiB buf) | O(segment plaintext) staged in `Vec` |
| `FecInboardEncoder::feed` | Yes (4 KiB buf) | O(stripe) = O(16 KiB × 8 shards) per stripe |
| `stream_encode_inboard_body` | Partial | **O(bare_len)** — `read_seek_to_vec` before FEC |
| `encode_stream` / `encode_shard_stream` | Partial | O(segment budget) staging |
| `stream_decode_buffer` | No | **O(encoded body)** full buffer |
| `scrub` | Seekable slices | O(N) Bao pre-check + combinatorial shard search |

**Bottom line:** segment budget caps plaintext staging, but FEC+Bao inboard paths still materialize the full pre-FEC body per segment. Decode always buffers the full encoded body.

Tests documenting this: `tests/streaming_limits.rs`.

## Target: minimal-memory streaming

### Design principles

1. **Stripe-bounded FEC** — never hold more than one RS stripe (16 KiB logical → 8 shards) in memory.
2. **Incremental Bao** — feed 4 KiB leaves into keyed tree; defer root until stripe/file end.
3. **Decode pull model** — `Read` impl over decrypt → FEC → Bao verify without full `Vec`.
4. **Scrub without full `bao()`** — slice extract only; skip O(N) pre-decode when hash known bad.

### Proposed phases

| Phase | Work | Memory impact |
|-------|------|---------------|
| **S1** | Wire `stream_decode_inboard` / `stream_decode_outboard` or remove dead code | Clarify API |
| **S2** | `stream_encode_inboard_body` FEC from `Read` without `read_seek_to_vec` | O(stripe) encode |
| **S3** | Streaming Bao encode (leaf-at-a-time keyed root) | O(leaf) tree state |
| **S4** | Streaming decode pipeline | O(stripe) decode |
| **S5** | Scrub: skip full `bao()` oracle when Bao verify already failed at slice | Reduce scrub RAM |

**Aspirational test:** `streaming_limits::stream_decode_should_not_materialize_full_body` (currently `#[ignore]`). Un-ignore when S4 lands.

## Parallelization

### What parallelizes well today

| Work | Parallelism | Notes |
|------|-------------|-------|
| AES-256-CTR | Block-independent | VAES/AES-NI; CTR counters per block |
| HMAC-SHA512 EtM | Chunked input | SHA extensions on x86 |
| RS parity generation | Per stripe | 4 data shards → 4 parity; stripes independent |
| Bao leaf hashing | Per 4 KiB leaf | BLAKE3 keyed leaves embarrassingly parallel |
| Multi-file directory encode | Per-file segments | Independent bare mains + bundle append |
| Multi-shard decode | Per shard (after fetch) | `decode_shards_stream` sequential today; could parallelize per shard decode |

### Hard serial bottlenecks

| Bottleneck | Why | Test / evidence |
|------------|-----|-----------------|
| **Keyed Bao root** | Root commits to full leaf set; tree level reduction is sequential | `streaming_limits::bao_zfec_encode_root_depends_on_full_staged_body` |
| **Scrub shard search** | Must try C(n,4) subsets with Bao hash oracle | Combinatorial; worst case exponential in extracted shards |
| **Encrypted nonce scope** | One `payload_nonce` per header-path archive | CTR stream is sequential per (key, nonce) |
| **Deterministic FEC re-encode** | Scrub compares Bao root after re-encode | Must complete stripe before hash compare |
| **Centralized directory Bao bundle** | Bundle built sequentially during encode | Offsets assigned in manifest order |

### Parallelism limits — reasoning

1. **Bao root dependency:** Merkle roots require all leaf hashes. You can parallelize leaf hashing, but the root aggregation tree has O(log N) sequential levels. For a single segment, leaf parallelization helps; root finalize waits for all leaves.

2. **Scrub is inherently search-heavy:** When >4 shards are damaged, RS cannot recover. When ≤4 are damaged but unknown which, scrub brute-forces 4-subsets. Parallelizing subset trials is possible (rayon over combinations) but each trial still needs Bao verify — dominated by hash work.

3. **CTR counter discipline:** Parallel CTR encryption must partition the counter space (e.g. per-stripe base counter) to avoid keystream reuse. Current API uses one nonce per archive — parallel encrypt of one archive needs counter partitioning (not implemented).

4. **Outboard sidecar ordering:** `.out` and `.par` are derived from the same logical body; parallel write is fine after body is known.

### Future parallel work

- Rayon over FEC stripes on encode (multi-stripe files)
- Parallel scrub subset evaluation (careful with Bao oracle cost)
- Per-shard `decode_stream` in `decode_shards_stream`
- UDP ingress: shard index → direct RS slot write (no full body)

## FEC ↔ UDP datagram mapping (sketch)

```text
Datagram header: [segment_id | stripe_id | shard_index | chunk_offset]
Payload: up to chunk_len bytes (one RS shard fragment)

Receiver:
  - Buffer 8 shards per stripe (any 4 sufficient)
  - On stripe complete → RS reconstruct → feed Bao leaf verifier
  - Bao ordering independent of datagram arrival order
```

50% packet loss ≈ 50% shard loss if each datagram maps 1:1 to a shard — within RS 4/8 if losses are spread (not concentrated on >4 shards). Tests in `fec_chaos.rs` model this at the byte/stream level; a future `tests/udp_fec_sim.rs` could simulate datagram drops.

## JBOD / RAID replacement

| RAID/JBOD concept | Carbonado equivalent |
|-------------------|-------------------|
| Disk stripe | RS shard (8 per stripe) |
| Disk failure | Shard erasure (`erase_shards`) |
| Degraded read | `zfec` / `zfec_with_parity` with 4 good shards |
| Scrub/rebuild | `scrub` / `scrub_outboard` + deterministic re-encode |
| Content verify | Keyed Bao root + slice verify |

Tests: `fec_chaos.rs` (distributed knockout), `shard_fec_scrub.rs` (per-segment heal).

## References

- `AGENTS.md` §2 — RS 4/8 rationale
- `src/stream/fec.rs` — `FecInboardEncoder`
- `src/decoding.rs` — `scrub`, `zfec_chunks`
- `tests/streaming_limits.rs` — bottleneck documentation tests
- `doc/TEST_STRATEGY.md` — full test matrix plan