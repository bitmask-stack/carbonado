# `ref/parity-harness`

Compare drivers for Lean AOT vs pinned `ref/` implementations (verik1 style).

## Layout

```text
ref/parity-harness/
  drivers/
    etm-vectors/   # Program B: RustCrypto EtM goldens (aes/ctr/hmac/sha2)
    rs-vectors/    # Program C: reed-solomon-erasure 4/8 + Carbonado padding
  README.md
```

## EtM vectors (Program B)

```bash
cd ref/parity-harness/drivers/etm-vectors
cargo run --quiet
```

Emits SHA-512, HMAC-SHA512, AES-256-CTR NIST, Carbonado subkeys, EtM blobs, and header MAC samples matching Lean goldens in `Carbonado/Main.lean` and `CarbonadoTest/EtM.lean`.

## RS vectors (Program C)

```bash
cd ref/parity-harness/drivers/rs-vectors
cargo run --quiet
```

Emits GF(2^8) samples, `calc_padding_len` geometry, RS 4/8 encode goldens, and Carbonado inboard encode heads matching `Carbonado/Main.lean` and `CarbonadoTest/Fec.lean`. Depends on `ref/reed-solomon-erasure` (v5.0.3 pin).

Register each new gate under `flake.nix` `checks` and [docs/SPEC-MATRIX.md](../../docs/SPEC-MATRIX.md).
