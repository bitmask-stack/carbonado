# carbonado — specification matrix

Every product capability maps to Lean module(s), parity gate(s), and proof status.

| Capability | Lean | Parity gate | Proof status |
|------------|------|-------------|--------------|
| Magic / header sizes / format bits | `Carbonado.Constants`, `CarbonadoTest.Scaffold` | `demo` / AOT Main | **scaffold theorems** (no sorry/admit) |
| Header wire + header_mac | `Carbonado.Header` (177 B parse/build/verify), `Carbonado.Crypto.EtM.computeHeaderMac` | golden in `demo` + `ref/parity-harness/drivers/etm-vectors` | **Program E:** wire codec + header-MAC-before-body; auth_data 113 B formula theorem |
| AES-CTR + HMAC-SHA512 EtM | `Carbonado.Crypto.{SHA512,HMAC,AESCTR,EtM}` | `demo` goldens; driver `ref/parity-harness/drivers/etm-vectors` | **Program B closed**: MAC-before-decrypt theorems; SHA/HMAC/AES-CTR/EtM goldens; roundtrip + tamper + wrong-key |
| RS 4/8 + geometry | `Carbonado.Fec.{Galois,Matrix,RS,Inboard}`, `CarbonadoTest.Fec` | `demo` goldens; driver `ref/parity-harness/drivers/rs-vectors` | **Program C closed**: GF; geometry; encode/reconstruct; all 7 `FecError` variants |
| Keyed Bao 4 KiB | `Carbonado.Bao.{Blake3,Tree,Product}`, `CarbonadoTest.Bao` | `demo` goldens; driver `ref/parity-harness/drivers/bao-vectors` | **Program D closed**: stream slice decode; all `BaoError` variants |
| Pipeline c0–c15 | `Carbonado.Pipeline`, `CarbonadoTest.Pipeline` | `demo` format matrix; optional future `product-matrix` vs rust | **Program E+F**: compress(zstd-20 when bit set)→encrypt→FEC→Bao + reverse; headered + body paths; `encoded_len` bound; MAC-before-decrypt + header-MAC-before-body; strict `PipelineError` incl. zstd modes |
| Scrub | `Carbonado.Scrub` | demo knockout recovery | **Program E:** pure RS subset search + re-encode + Bao root compare; `unnecessaryScrub` / `scrubRequiresVerification` / `invalidScrubbedHash` |
| Outboard | `Carbonado.Bao` create/verify; `Carbonado.Outboard` product body (bare main + FEC parity + verification sidecar) | bao-vectors + `demo` outboard segment roundtrip | **Program D+G**: post-order Bao outboard; directory segments via `encodeOutboardBody` / `decodeOutboardBody` |
| Streaming bounds | `Carbonado.Stream` | demo greps + theorems | **Program E:** O(stripe) FEC retain theorems (`maxFecStripeRetain`); pure stripe transducer model |
| Sharding | `Carbonado.Shard` | demo multi-segment roundtrip | **Program E:** budget split + `chunk_index` sequence + headered segments |
| Zstd-20 compress | `Carbonado.Compress`, `CarbonadoTest.Compress` | `demo` API goldens (empty/hello); pipeline c2/c6 | **Program F closed**: linked zstd; status taxonomy; interpreter identity fallback (LIMITS) |
| SLH1 sidecars | `Carbonado.Slh`, `CarbonadoTest.Slh` | `demo` wire + bind-to-root | **Program F closed** for wire/binding theorems; real SLH-DSA FFI residual (LIMITS) |
| Adamantine directory | `Carbonado.Adamantine`, `Filepack`, `Outboard`, `Directory`, `CarbonadoTest.Directory` | `demo` Program G greps; pure roundtrip AOT | **Program G closed** for product path: Adamantine10 + CFP2 manifest + outboard segments + fail-closed paths + content BLAKE3. rkyv body residual (LIMITS) |
| CLI | `Carbonado.Cli`, `Carbonado.Main` | `demo` + CLI subcommands | **Program G:** encode/decode file+dir; single-file default `{bao_root_hex}.c{fmt:02x}`; dir default `{input}-archive/`; `slh parse` wire; `slh verify` fail-closed exit 1 until FFI |

Expand rows until full product parity with dual-backend G8 (`backend-rust` + `backend-lean` on `tests/`) and optional `ref/carbonado-rust` freeze is closed. Component rows above track Lean+Nix proof/oracle gates; dual-suite status is [GAPS.md](./GAPS.md) G8 / [TEST_CONTRACT.md](./TEST_CONTRACT.md).
