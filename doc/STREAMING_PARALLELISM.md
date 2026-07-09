# Streaming Memory & Parallelism

Carbonado is **streaming-first in API shape** and **partially streaming-complete in pipeline memory**. This document records current behavior, the three axes (memory / concurrency / parallelism), hard limits, and the **active hard-break** path to eliminate residual O(logical) staging for JBOD, UDP, and P2P workloads.

**Naming:** *Memory-efficient streaming* = bounded working set during encode/decode **pipeline** stages. It is **not** Bao cryptographic slice/stream verification (`verify_slice_*`), which is already O(slice) in retained memory.

## Current pipeline (per segment)

```text
Read (64 KiB chunks)
  → stream_preprocess_spool (compress / encrypt) → SeekableSpool temp file (O(chunk) RAM)
  → stream_encode_inboard_body (FEC incremental + Bao) → O(stripe) FEC + O(leaf) Bao tree state
  → Header + write

Decode:
  → incremental Read (bounded by encoded_len when known)
  → Bao verify via WriteAt sink
  → FEC RS reconstruct (one stripe); verification formats may retain O(logical) at this tier
  → SeekableSpool staging → streaming EtM MAC-then-decrypt → decompress to output
```

## Memory model today

| Stage | Streaming read? | Peak memory |
|-------|-----------------|-------------|
| `stream_preprocess_spool` | Yes (64 KiB buf) | **O(chunk)** — disk-backed `SeekableSpool` (0600 on Unix) |
| `FecInboardEncoder::feed` | Yes (4 KiB buf) | O(8 × chunk_len) encoder state per stripe (`chunk_len` scales with segment) |
| `stream_encode_inboard_body` (FEC) | Yes (4 KiB feed) | **O(8 × chunk_len)** — S2 eliminates pre-FEC `bare_len` staging |
| `stream_encode_inboard_body` (Bao verify) | Yes (leaf-at-a-time) | **O(leaf + outboard)** — S3: `FecStripeReadAt` / `SeekReadAt`, no body staging `Vec` |
| `encode_stream` / `encode_shard_stream` | Yes | O(chunk) preprocess spool + O(stripe) FEC |
| `decode_stream` / `file::decode` | Yes (bounded `encoded_len`) | O(chunk) spool staging + streaming EtM on header path |
| `stream_decode` (Verification c6) | Yes (incremental Read) | **(A)** Bao → `SeekWriteAt` on post-preprocess spool (**O(chunk)** RAM); **(B)** streaming EtM/decompress |
| `stream_decode` (Verification+FEC c12/c14/c15) | Yes (incremental Read) | **(A)** Bao → `FecInboardWriteAt` O(FEC body) shards (segment-wide stripe); `finish_into` streams logical without second full `Vec`; **(B)** O(chunk) spool + EtM |
| `stream_decode` (c4/c8) | Bounded when `encoded_body_len` set | O(stripe) FEC or O(compressed); rejects trailing bytes |
| `stream_decode_outboard` | Incremental main/parity copy | Bao verify via `PostOrderOutboard` + `ReadAt` (O(hash pair) per node; spool or slice); main via spool |
| `scrub` | Seekable slices | O(1) Bao verify sink + combinatorial shard search (S5); `scrub_outboard` verify retains O(sidecar) |

**Bottom line:** Phase 1 fused encode/decode uses `SeekableSpool` for preprocess and post-Bao/FEC staging with streaming MAC-then-decrypt. **M1:** c6 `SeekWriteAt` O(chunk); FEC verify O(FEC body) shards + `finish_into`. **M2:** outboard verify uses `PostOrderOutboard` + `ReadAt` (no full sidecar `Vec` copy). Residual: FEC O(segment body) under single segment-wide RS stripe; async encoded-body spool. Scrub uses discard `WriteAt` (S5).

Tests documenting this: `tests/streaming_limits.rs`.

## Active hard-break: residual pipeline staging

**Hard break:** no dual “compat” buffer sinks. On-disk format unchanged; internal pipeline shapes may be deleted and replaced.

| Priority | Work | Memory impact |
|----------|------|---------------|
| **M1** | ~~Non-FEC c6 → `SeekWriteAt`~~ **Shipped**; FEC `finish_into` **Shipped**. Further FEC O(segment) needs multi-stripe geometry (format-level) or accept segment-bounded residual | c6 O(chunk); c12–c15 O(FEC body) shards |
| **M2** | ~~Outboard `PostOrderOutboard` + `ReadAt`~~ **Shipped** (slice or spool; O(hash pair) per node) | Dropped O(sidecar) mem copy |
| **M3** | Async: wire `bao_tree::io::fsm` (or equivalent); drop full encoded-body spool | Remove ~2× encoded disk I/O on async path |

### Design principles

1. **Stripe-bounded FEC** — never hold more than one RS stripe (8 shards × `chunk_len`; `chunk_len` from `calc_padding_len`) in memory.
2. **Incremental Bao** — feed 4 KiB leaves into keyed tree; defer root until stripe/file end.
3. **Decode pull model** — `Read` / `WriteAt` over decrypt → FEC → Bao verify without full logical `Vec`.
4. **MAC-before-decrypt** — streaming EtM may spool ciphertext; never emit plaintext before full tag success.
5. **Scrub verify oracle without O(decoded) body staging** — discard `WriteAt` sink on scrub entry; combinatorial recovery still uses slice extract + re-encode Bao hash oracle.
6. **`streaming_limits` is the bar** — each eliminated tier updates tests the same change.

### Shipped phases (S2–S5)

| Phase | Work | Memory impact |
|-------|------|---------------|
| **S2** | `stream_encode_inboard_body` FEC from `Read` without full body staging | O(stripe) FEC encode |
| **S3** | Streaming Bao encode (leaf-at-a-time keyed root) | O(leaf) tree state + outboard sidecar |
| **S4** | Streaming decode pipeline (incremental Read; residual O(logical) on verification sinks) | O(chunk) spool + streaming EtM; **O(logical) residual on c6/c12/c14/c15** |
| **S5** | Scrub entry: `verify_inboard_keyed` discard sink | O(1) retained decode RAM on scrub pre-check |

**S4 contract test:** `streaming_limits::stream_decode_bounded_read_matches_buffer_path` — bounded-read `stream_decode` matches buffer path (**read-chunk parity**, not peak-RSS proof of O(stripe) until M1 lands).

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
| **Keyed Bao root** | Root commits to full leaf set; tree level reduction is sequential | `streaming_limits::verification_keyed_root_is_deterministic_over_complete_body` |
| **Scrub shard search** | Must try C(n,4) subsets with Bao hash oracle | Combinatorial; worst case exponential in extracted shards |
| **Encrypted nonce scope** | One `payload_nonce` per header-path archive | CTR stream is sequential per (key, nonce) |
| **Deterministic FEC re-encode** | Scrub compares Bao root after re-encode | Must complete stripe before hash compare |
| **Centralized directory Bao bundle** | Bundle built sequentially during encode | Offsets assigned in manifest order |

### Parallelism limits — reasoning

1. **Bao root dependency:** Merkle roots require all leaf hashes. You can parallelize leaf hashing, but the root aggregation tree has O(log N) sequential levels. For a single segment, leaf parallelization helps; root finalize waits for all leaves.

2. **Scrub is inherently search-heavy:** When >4 shards are damaged, RS cannot recover. When ≤4 are damaged but unknown which, scrub brute-forces 4-subsets. Parallelizing subset trials is possible (rayon over combinations) but each trial still needs Bao verify — dominated by hash work.

3. **CTR counter discipline:** Parallel CTR encryption must partition the counter space (e.g. per-stripe base counter) to avoid keystream reuse. Current API uses one nonce per archive — parallel encrypt of one archive needs counter partitioning (not implemented).

4. **Outboard sidecar ordering:** `.out` and `.par` are derived from the same logical body; parallel write is fine after body is known.

### Deferred parallel work (after memory M1–M3)

Pipeline **memory** elimination outranks these:

- Fork-join keyed BLAKE3 4 KiB leaves within a stripe
- Parallel scrub subset evaluation (careful with Bao oracle cost)
- Per-shard `decode_stream` in `decode_shards_stream`
- UDP ingress: shard index → direct RS slot write (no full body)
- **Not planned as default:** rayon global pool

## FEC ↔ UDP datagram mapping (sketch)

```text
Datagram header: [segment_id | stripe_id | shard_index | chunk_offset]
Payload: up to chunk_len bytes (one RS shard fragment)

Receiver:
  - Buffer 8 shards per stripe (any 4 sufficient)
  - On stripe complete → RS reconstruct → feed Bao leaf verifier
  - Bao ordering independent of datagram arrival order
```

50% packet loss ≈ 50% shard loss at the **chaos-injection coordinates** (`InboardShardLayout` / `erase_shards`) — within RS 4/8 if losses are spread (not concentrated on >4 shards). True inboard wire is Bao-wrapped; `tests/udp_fec_sim.rs` documents the approximate model explicitly. `fec_chaos.rs` models distributed knockout at the same coordinates.

## JBOD / RAID replacement

| RAID/JBOD concept | Carbonado equivalent |
|-------------------|-------------------|
| Disk stripe | RS shard (8 per stripe) |
| Disk failure | Shard erasure (`erase_shards`) |
| Degraded read | `fec` / `fec_with_parity` with 4 good shards |
| Scrub/rebuild | `scrub` / `scrub_outboard` + deterministic re-encode |
| Content verify | Keyed Bao root + slice verify |

Tests: `fec_chaos.rs` (distributed knockout), `shard_fec_scrub.rs` (per-segment heal).

## Phase 2: Async I/O (shipped)

Phase 2 adds **concurrency** (non-blocking fetch / range-read / UDP assembly adapters) without making async the only path or coupling the library core to a required Tokio runtime. **Parallelism** (rayon, fork-join) remains Phase 3.

### Design principles

1. **Sync remains default and canonical** — `encode_stream`, `decode_stream`, `file::decode`, `stream_decode`, buffer helpers unchanged.
2. **Async is an adapter layer** — same internal stage graph; different trait bounds on sources/sinks.
3. **Runtime-agnostic traits** — `futures_lite::AsyncRead` / `AsyncWrite` (stdlib-compatible async I/O surface), not a hard Tokio dependency in library core.
4. **Optional `async` Cargo feature** — enables `stream_decode_async` and `stream::io` async helpers; default build stays sync-only. `bao_tree` keeps `default-features = false, features = ["validate"]`; with `async`, `bao_tree/tokio_fsm` is enabled but **not referenced by crate code yet** (reserved; no runtime effect on decode today).
5. **Bao bridge choice (Phase 2)** — async decode **does not** call `bao_tree::io::fsm`. Encoded input is fully staged to a disk-backed [`SeekableSpool`](../src/stream/spool.rs) via [`async_copy_bounded`](../src/stream/io.rs), then the existing sync keyed Bao + FEC + decrypt stages run unchanged. This preserves MAC-before-decrypt and bounded-read contracts without duplicating crypto logic, at the cost of **O(encoded_body)** disk I/O per decode (explicit tradeoff vs sync S4 incremental read). Phase 3 milestone: wire FSM or incremental async Bao to skip encoded spool.
6. **Executor blocking** — sync pipeline runs inside `async fn`; enable `async-tokio` for `spawn_blocking` offload or call from a dedicated thread pool.

### Feature flag matrix

| Feature | Default | Enables |
|---------|---------|---------|
| *(none)* | yes | Sync-only pipeline; `bao_tree` validate only |
| `async` | no | `futures-lite`, `stream_decode_async`, `stream::io` async adapters; `bao_tree/tokio_fsm` reserved (inert) |
| `async-tokio` | no | `async` + `tokio` dep + `spawn_blocking` for sync pipeline section |

### What async helps vs does not

| Helps (concurrency) | Does **not** help (parallelism) |
|---------------------|----------------------------------|
| P2P shard fetch while other I/O pending | FEC stripe encode across cores |
| HTTP range reads without blocking threads | Parallel Bao leaf hashing |
| UDP datagram assembly waiting on network | Scrub combinatorial subset search |
| Many concurrent decode sessions on one runtime | CTR counter partitioning for parallel encrypt |

### WASM

Keep **`async` off** on `wasm32` deployments: `SeekableSpool` uses host temp files. `stream_decode_async` is exported when `async` is enabled but returns `NotImplemented` on `wasm32` at runtime. CI may compile `--all-features` on `wasm32-unknown-unknown`; that means "compiles, unsupported at runtime" — not a deployment target for async decode.

### Disk I/O overhead (Phase 2)

Per decode on native targets with `async`: up to three temp spools (encoded staging, pipeline `post_preprocess`, plaintext staging). Encoded bytes are written once on ingress and read again by the sync pipeline — roughly **2× encoded-body disk traffic** vs sync incremental `Read`. Error cleanup uses `SeekableSpool::drop` (`0600` on Unix). Track elimination of encoded spool as a Phase 3 metric.

### Public API (async)

- [`stream_decode_async`](../src/stream/decode_async.rs) — `AsyncPipelineSource` → `AsyncPipelineSink` inboard decode; delegates to sync `stream_decode_inboard_pipeline` (format matrix tested in `tests/streaming_async.rs`: c4/c6/c8/c12/c14/c15). Verification-format truncated bounded reads surface staging `UnexpectedEof` on async vs `BaoResponseTruncated` on sync (documented in rustdoc).
- [`stream::io`](../src/stream/io.rs) — `PipelineSource` / `PipelineSink` (sync), `AsyncPipelineSource` / `AsyncPipelineSink` + `async_copy_bounded` / `async_copy_all` (feature `async`).

Tests: `cargo test --features async --test streaming_async`.

## Phase 3: Parallelism (shipped)

Phase 3 adds **optional CPU parallelism** via `std::thread::scope` fork-join only — not async/concurrency (Phase 2). No rayon global pool; no `tokio::spawn_blocking` for CPU work; no `std::sync::mpsc` pipeline stages in this phase.

### Chosen model

| Work | Technique | Status |
|------|-----------|--------|
| RS parity (4 shards / stripe) | `std::thread::scope` fork-join — scoped tasks per parity shard in waves of `max_threads`, deterministic shard index merge order | **Shipped** (`parallel` feature) |
| AES-CTR / HMAC | SIMD via `aes` / `sha2` crates | Document `RUSTFLAGS="-C target-cpu=native"` |
| Keyed BLAKE3 leaves | Embarrassingly parallel per 4 KiB leaf | **Deferred** (future fork-join batches within stripe) |
| Pipeline stages (`mpsc`) | Bounded worker pool + channels | **Deferred** (encode path remains direct call chain) |
| Bao root finalize | Serial (inherent) | Unchanged |
| CTR one header nonce | Serial | Unchanged — no parallel encrypt of single header-path archive |

**Decision:** `std::thread::scope` fork-join over a **persistent worker pool + `mpsc`** was considered and rejected for Phase 3. Stripe-bounded RS parity is short-lived (≤4 parity shards, joined before Bao); scoped threads avoid pool lifecycle, keep std-only deps, and guarantee join-before-return for determinism. A channel-backed pool would add cross-stripe state and ordering contracts without benefit at Carbonado’s one-stripe-at-a-time encode granularity.

Implementation: [`src/stream/parallel.rs`](../src/stream/parallel.rs) — `ParallelConfig`, `encode_rs_parity`, cached RS coefficient matrix.

**`chunk_len` geometry:** `calc_padding_len` pads to a 16 KiB stripe (`SLICE_LEN × FEC_K`), so `chunk_len = stripe_size / 4` is always a multiple of 4096 and **≥ 4096** for any non-empty logical input. `RS_PARITY_PARALLEL_MIN_CHUNK_LEN = 4096` is a defensive gate for direct API callers with synthetic shard sizes; it does **not** skip parallel encode for real Carbonado inboard/outboard stripes.

### Feature flag matrix

| Feature | Default | Enables |
|---------|---------|---------|
| `parallel` | yes | Scoped parallel RS parity in `FecInboardEncoder::take_stripe`; std only (serial at runtime on `wasm32`) |
| `--no-default-features` + `pqc,ots,cli` | — | Serial RS parity (`reed_solomon_erasure::encode`); CI-gated via `serial_fec_path` |
| `async` | no | Phase 2 async adapters (orthogonal) |
| `async-tokio` | no | Phase 2 + `spawn_blocking` offload |

Combine flags independently: `cargo test --all-features` exercises compile-time matrix; determinism tests gate on `parallel` only.

### WASM

On `wasm32`, `parallel` compiles but [`should_parallelize_rs_parity`](../src/stream/parallel.rs) is always false — RS parity stays serial at runtime regardless of the feature flag.

### SIMD / bench notes

- Native AES-NI / VAES / SHA extensions: `RUSTFLAGS="-C target-cpu=native" cargo build`
- RS parity bench: `cargo bench --features parallel --bench parallel_bench` — compares serial `encode_sep` vs scoped parity on Carbonado stripe sizes (16–256 KiB logical) and synthetic sub-threshold `chunk_len` values for the defensive serial fallback. Carbonado production stripes always parallelize when `max_threads > 1` and not `wasm32`.
- Full pipeline bench unchanged: `benches/crypto_bench.rs`

### What parallelizes vs serial bottlenecks

| Parallelizes (Phase 3) | Stays serial |
|------------------------|--------------|
| RS parity shard GF work within one stripe (4 tasks) | Keyed Bao root aggregation |
| (Future) BLAKE3 keyed leaf batches per stripe | Scrub combinatorial subset search |
| Multi-file directory segments (independent processes) | CTR stream under one archive nonce |
| | Bao root finalize after all leaves |

Determinism contract: parallel encode produces **bit-identical** body bytes and keyed Bao roots vs the serial `encode_sep` / `rs.encode` reference (`encode_rs_parity_serial`, unit-tested against `rs.encode`). Serial FEC path (no `parallel`) is CI-gated separately (`cargo test --no-default-features --features "pqc,ots,cli" --test serial_fec_path`). Scrub roundtrip under parallel encode: `parallel_determinism::parallel_encode_inboard_scrub_roundtrip_c12_c14`. Tests: `cargo test --test parallel_determinism`.

## References

- `AGENTS.md` §2 — RS 4/8 rationale
- `src/stream/fec.rs` — `FecInboardEncoder`
- `src/decoding.rs` — `scrub`, `fec`, `fec_with_parity`
- `tests/streaming_limits.rs` — bottleneck documentation tests
- `doc/TEST_STRATEGY.md` — full test matrix plan