/**
 * carbonado C ABI — Lean AOT engine (libcarbonado)
 *
 * See docs/ABI.md for ownership, error codes, and versioning.
 * ABI version 1 (v0 core + Phase 2 additive outboard/scrub/slice).
 */
#ifndef CARBONADO_H
#define CARBONADO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CARBONADO_ABI_VERSION 1u

#define CARBONADO_OK 0
#define CARBONADO_ERR_INVALID_ARGUMENT 1
#define CARBONADO_ERR_INVALID_KEY_LENGTH 2
#define CARBONADO_ERR_AUTHENTICATION 3
#define CARBONADO_ERR_INVALID_MAGIC 4
#define CARBONADO_ERR_INVALID_HEADER 5
#define CARBONADO_ERR_FEC 6
#define CARBONADO_ERR_BAO 7
#define CARBONADO_ERR_ZSTD 8
#define CARBONADO_ERR_SCRUB_UNNECESSARY 9
#define CARBONADO_ERR_SCRUB_FAILED 10
#define CARBONADO_ERR_NOT_IMPLEMENTED 11
#define CARBONADO_ERR_INTERNAL 12
/** Scrub called without Verification bit (distinct from recovery failure). */
#define CARBONADO_ERR_SCRUB_REQUIRES_VERIFICATION 13

/** Returns CARBONADO_ABI_VERSION. */
uint32_t carbonado_abi_version(void);

/** Free a buffer returned by libcarbonado (malloc family). */
void carbonado_free(void *p);

/**
 * Low-level encode (Rust encoding::encode body shape).
 * On success: *out is malloc'd body, hash_out is 32-byte Bao root.
 * Encrypted formats require nonce_len == 16.
 * padding/chunk/ecc/vsc/compressed/encrypted out-params may be NULL.
 * bytes_compressed / bytes_encrypted are 0 when those stages are skipped (R3).
 */
int carbonado_encode(
    const uint8_t *master, size_t master_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t format,
    const uint8_t *nonce, size_t nonce_len,
    uint8_t **out, size_t *out_len,
    uint8_t hash_out[32],
    uint32_t *padding_out,
    uint32_t *chunk_len_out,
    uint32_t *bytes_ecc_out,
    uint32_t *verifiable_slice_count_out,
    uint32_t *bytes_compressed_out,
    uint32_t *bytes_encrypted_out);

/**
 * Low-level decode of a verifiable body (hash + padding + format).
 */
int carbonado_decode(
    const uint8_t *master, size_t master_len,
    const uint8_t *hash, size_t hash_len,
    const uint8_t *body, size_t body_len,
    uint32_t padding,
    uint8_t format,
    uint8_t **out, size_t *out_len);

/**
 * Headered encode: full file Header || body (Rust file::encode shape).
 * slh_pk: NULL → zero-filled 32 B field; non-NULL must point to exactly 32 valid bytes
 *         (C always copies 32 when non-NULL; wrong lengths are Lean ByteArray-only).
 * metadata: NULL → zero-filled 8 B field; non-NULL must point to exactly 8 valid bytes
 *           (C always copies 8 when non-NULL; wrong lengths are Lean ByteArray-only).
 * Stage-counter out-params (nullable): padding/chunk/ecc/vsc/compressed/encrypted (R3).
 */
int carbonado_encode_headered(
    const uint8_t *master, size_t master_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t format,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *slh_pk,
    const uint8_t *metadata,
    uint8_t **out, size_t *out_len,
    uint32_t *padding_out,
    uint32_t *chunk_len_out,
    uint32_t *bytes_ecc_out,
    uint32_t *verifiable_slice_count_out,
    uint32_t *bytes_compressed_out,
    uint32_t *bytes_encrypted_out);

/**
 * Headered decode: full file archive → plaintext.
 */
int carbonado_decode_headered(
    const uint8_t *master, size_t master_len,
    const uint8_t *archive, size_t archive_len,
    uint8_t **out, size_t *out_len);

/** Format-keyed verification key (32 bytes). */
int carbonado_verification_key(uint8_t format, uint8_t key_out[32]);

/**
 * Outboard encode: bare main + optional verification outboard + FEC parity sidecars.
 * Any of main_out / outboard_out / parity_out must be non-NULL with matching len ptr.
 * Empty sidecars return *out=NULL, *out_len=0.
 *
 * header_path != 0: encrypted bare main is [tag|ct] (nonce out-of-band; file::encode_outboard).
 * header_path == 0: encrypted bare main is [nonce|tag|ct] (encoding::encode_outboard).
 * Encrypted formats require nonce_len == 16.
 * bytes_compressed_out / bytes_encrypted_out may be NULL (0 when stage skipped; R3).
 */
int carbonado_encode_outboard(
    const uint8_t *master, size_t master_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t format,
    const uint8_t *nonce, size_t nonce_len,
    uint8_t header_path,
    uint8_t **main_out, size_t *main_len,
    uint8_t **outboard_out, size_t *outboard_len,
    uint8_t **parity_out, size_t *parity_len,
    uint8_t hash_out[32],
    uint32_t *padding_out,
    uint32_t *chunk_len_out,
    uint32_t *bytes_compressed_out,
    uint32_t *bytes_encrypted_out);

/**
 * Outboard decode: bare main + optional sidecars → plaintext.
 * outboard/parity may be null with len 0 when the format does not require them.
 *
 * header_path / nonce must match encode-time layout (see carbonado_encode_outboard).
 */
int carbonado_decode_outboard(
    const uint8_t *master, size_t master_len,
    const uint8_t *hash, size_t hash_len,
    const uint8_t *main, size_t main_len,
    const uint8_t *outboard, size_t outboard_len,
    const uint8_t *parity, size_t parity_len,
    uint32_t padding,
    uint8_t format,
    uint8_t header_path,
    const uint8_t *nonce, size_t nonce_len,
    uint8_t **out, size_t *out_len);

/**
 * Inboard scrub: recover damaged Bao+FEC body (or SCRUB_UNNECESSARY / REQUIRES_VERIFICATION).
 */
int carbonado_scrub(
    const uint8_t *body, size_t body_len,
    const uint8_t *hash, size_t hash_len,
    uint32_t padding,
    uint8_t format,
    uint8_t **out, size_t *out_len);

/**
 * Outboard scrub: recover damaged bare main using outboard + FEC parity.
 */
int carbonado_scrub_outboard(
    const uint8_t *main, size_t main_len,
    const uint8_t *outboard, size_t outboard_len,
    const uint8_t *parity, size_t parity_len,
    const uint8_t *hash, size_t hash_len,
    uint32_t padding,
    uint32_t chunk_len,
    uint8_t format,
    uint8_t **out, size_t *out_len);

/**
 * Inboard verify_slice / extract_slice: authenticated slice bytes from inboard body.
 *
 * W4a: Lean retains O(slice) output while walking the full inboard response for
 * auth (O(N) time). Caller still supplies the full body buffer (input).
 * count==0 returns empty after full auth (Lean auth-first path).
 */
int carbonado_verify_slice(
    const uint8_t *body, size_t body_len,
    const uint8_t *hash, size_t hash_len,
    uint32_t index,
    uint32_t count,
    uint8_t format,
    uint8_t **out, size_t *out_len);

/**
 * Seekable outboard verify_slice: authenticated slice bytes from bare main +
 * post-order outboard sidecar (keyed Bao, 4 KiB groups).
 *
 * Time/hash work is O(slice + tree height) over the requested ranges (not full
 * re-encode). C ABI still takes full main + outboard buffers in memory — W4b
 * permanent residual (no streaming ReadAt / callback ABI); see docs/LIMITS.md.
 *
 * count==0 → empty success immediately (no auth / geometry / OOB checks) —
 * matches Rust `verify_slice_outboard` extract semantics. OOB index and
 * authentication apply only when count > 0.
 */
int carbonado_verify_slice_outboard(
    const uint8_t *main, size_t main_len,
    const uint8_t *outboard, size_t outboard_len,
    const uint8_t *hash, size_t hash_len,
    uint32_t index,
    uint32_t count,
    uint8_t format,
    uint8_t **out, size_t *out_len);

/**
 * SLH-DSA-SHA2-128s keygen (G10). entropy_len must be ≥ 128.
 * pk_out: 32 bytes; sk_out: 64 bytes (caller-owned stack/heap buffers).
 */
int carbonado_slh_keygen(
    const uint8_t *entropy, size_t entropy_len,
    uint8_t pk_out[32],
    uint8_t sk_out[64]);

/**
 * SLH-DSA-SHA2-128s sign. secret_key_len must be 64.
 * On success: *out is malloc'd 7856-byte signature (free with carbonado_free).
 */
int carbonado_slh_sign(
    const uint8_t *secret_key, size_t secret_key_len,
    const uint8_t *message, size_t message_len,
    uint8_t **out, size_t *out_len);

/**
 * SLH-DSA-SHA2-128s verify. public_key_len 32; signature_len 7856.
 * Returns CARBONADO_OK on accept, CARBONADO_ERR_AUTHENTICATION on reject.
 */
int carbonado_slh_verify(
    const uint8_t *public_key, size_t public_key_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *signature, size_t signature_len);

#ifdef __cplusplus
}
#endif

#endif /* CARBONADO_H */
