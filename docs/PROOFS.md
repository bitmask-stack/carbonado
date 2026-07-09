# carbonado — proof inventory

**Policy:** product Lean under `Carbonado/` and `CarbonadoTest/` must contain **no** proof holes.

**Dual-backend:** Lean theorems prove properties of the Lean engine and wire model. **Bit-match / behavioral parity** with production is additionally enforced by the Rust suite on `backend-lean` (G8) and `ref/` oracles ([PARITY.md](./PARITY.md)). Proofs do **not** replace `tests/`; they complement them.

**Hole vocabulary (forbidden):** `sorry`, `admit` (Lean alias for `sorry`).  
Enforced by `nix build .#checks.x86_64-linux.no-sorry` / `nix flake check` (and explicit check builds). The gate fails closed if those directories or their `*.lean` roots are missing.

## Counts

| Module | Theorems / notes |
|--------|------------------|
| `Carbonado/Constants.lean` | `magicBytes_length`, `magicBytes_eq_literal`, `sliceLen_eq_bao_group`, `stripeUnit_eq`, `fecM_eq_twice_fecK`, `slh1Magic_*`, `slh1SidecarLen_eq`, full `SubkeyLabel` registry, `formatBits_roundtrip`, `unencrypted_format_even`, `formatC14_byte`, `formatC15_byte`, `format_codes_roundtrip`, `headerLen_sum` |
| `Carbonado/Crypto/EtM.lean` | **MAC-before-decrypt:** `decryptAfterMacCheck_tag_fail`, `decryptAfterMacCheck_ok_implies_mac`, `decryptAfterMacCheck_auth_fail_no_plaintext`, `decryptResult_ok_implies_plaintext`. **Guard taxonomy:** `decryptWithNonce_short_input` (CT length first), `decryptWithNonce_short_master` (master after CT gate), `decryptWithNonce_bad_nonce` (`invalidNonceLength`) |
| `Carbonado/Fec/Galois.lean` | GF mul/div/exp goldens vs pin: `mul_1_1`, `mul_2_3`, `mul_0x53_0xca`, `mul_0xff_1`, `mul_7_11`, `div_2_3`, `exp_2_3`, `exp_0x53_3`, `mul_comm_7_11` |
| `Carbonado/Fec/RS.lean` | `carbonadoRS_constructs`, `carbonadoRS_geometry` (aligned with `fecK`/`fecM`); `invertOrSingular_zeros` / `invertOrSingular_identity` |
| `Carbonado/Fec/Inboard.lean` | `calcPaddingLen_{zero,one,stripe,stripe_plus_one,100,4096}`, `paddedLen_aligns_samples` |
| `Carbonado/Bao/Blake3.lean` | `hash_empty`, `hash_abc` (official BLAKE3 goldens) |
| `Carbonado/Bao/Tree.lean` | `leafBytes_eq_sliceLen`, `root_eq_keyed_hash`; stream `decodeSliceResponse` / auth-first inboard extract |
| `Carbonado/Bao/Product.lean` | `verification_key_format_domain`, `root_commits_to_format`, `encode_decode_empty_c4`, `hello_root_eq_keyed_hash` |
| `Carbonado/Header.lean` | `authData_len_formula` (113 B); `headerLen_eq_177` |
| `Carbonado/Pipeline.lean` | `encrypted_bit_is_odd`; full encode/decode composition; strict `PipelineError` taxonomy incl. zstd modes |
| `Carbonado/Stream.lean` | `full_stripe_inboard_len`, `full_stripe_retain`, `empty_stripe_retain`, `one_byte_stripe_retain`, `chunk_eq_slice`, `stripe_eq_k_slices` |
| `Carbonado/Scrub.lean` | Pure RS mask search + Bao root oracle (AOT + CarbonadoTest) |
| `Carbonado/Shard.lean` | `split_empty_budget`, `split_hello_budget_2`, `split_empty_plaintext` |
| `Carbonado/Compress.lean` | `zstdMagic_length`; `ofStatus_*`; `decode_status_*` for every status code; `statusOk_payload_identity` (pure framing helper; not an `@[extern]` decide) |
| `Carbonado/Slh.lean` | Wire: `parse_short_length`, `parse_empty`, `build_bad_sig_len`, `slh1_magic_bytes`, **`parse_magic_bad` / `zeros_not_slh1_magic` / `parse_bad_magic_when_exact`** (`badSlhMagic` path). Binding: `bind_bad_{pk,root,sig}`, **`wrong_root_fails`**, `sign_unavailable`, `sign_bad_root`. Full 7856 B wire: AOT Main |
| `CarbonadoTest/Scaffold.lean` | Re-exports / restates wire invariants |
| `CarbonadoTest/EtM.lean` | Re-exports MAC + guard theorems; **`native_decide` matrix** for crypto goldens |
| `CarbonadoTest/Fec.lean` | Geometry + RS; all 7 `FecError` paths |
| `CarbonadoTest/Bao.lean` | Geometry; BLAKE3; stream slice; **exact** every `BaoError` |
| `CarbonadoTest/Pipeline.lean` | Non-compression format matrix + path tests; **exact maps** incl. `ofZstdError` → `zstdInvalidInput` |
| `CarbonadoTest/Compress.lean` | Every `ZstdError` status map; bit-clear compress/decompress; pipeline maps |
| `CarbonadoTest/Slh.lean` | Short-path every `SlhError` **except** full-length AOT-only wire (length/magic/sig/pk/root/unavailable/verification via prefix+gate theorems; full 7860 B `badSlhMagic` + roundtrip in Main) |
| `Carbonado/Adamantine.lean` | `adamantineMagic_*`, `adamantineHeaderLen_eq`; encode/decode empty public; `invalid_flags_bit1`; `invalid_fmt_c0`; `short_header`; `dev_v2_rejected` |
| `Carbonado/Filepack.lean` | `cfp2Magic_length`; path: `rel_empty`, `rel_traversal`, `rel_absolute`, `rel_backslash`, `rel_ok`, `rel_empty_component` |
| `Carbonado/Outboard.lean` | Outboard encode/decode + FEC parity sidecar (AOT roundtrips in Main) |
| `Carbonado/Directory.lean` | `ofFilepack_*` / `ofAdamantine_*` maps; pure encode/decode (AOT); path fail-closed |
| `Carbonado/Cli.lean` | Product CLI dispatch (IO; no theorems) |
| `CarbonadoTest/Directory.lean` | Restates Adamantine/path maps; master-policy + path reject exact variants; padding helpers |
| `Carbonado/Main.lean` | AOT Programs A–G; full zstd goldens; SLH full wire; directory pure roundtrip; gated by `checks.demo` greps |

Refresh with theorem line counts (beastdb PROOFS pattern) as parity gates deepen.
