/**
 * carbonado C ABI — Lean AOT engine (libcarbonado)
 *
 * See docs/ABI.md for ownership, error codes, and versioning.
 * ABI version 1 (v0 surface).
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

/** Returns CARBONADO_ABI_VERSION. */
uint32_t carbonado_abi_version(void);

/** Free a buffer returned by libcarbonado (malloc family). */
void carbonado_free(void *p);

/**
 * Low-level encode (Rust encoding::encode body shape).
 * On success: *out is malloc'd body, hash_out is 32-byte Bao root.
 * Encrypted formats require nonce_len == 16.
 */
int carbonado_encode(
    const uint8_t *master, size_t master_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t format,
    const uint8_t *nonce, size_t nonce_len,
    uint8_t **out, size_t *out_len,
    uint8_t hash_out[32]);

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
 */
int carbonado_encode_headered(
    const uint8_t *master, size_t master_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t format,
    const uint8_t *nonce, size_t nonce_len,
    uint8_t **out, size_t *out_len);

/**
 * Headered decode: full file archive → plaintext.
 */
int carbonado_decode_headered(
    const uint8_t *master, size_t master_len,
    const uint8_t *archive, size_t archive_len,
    uint8_t **out, size_t *out_len);

/** Format-keyed verification key (32 bytes). */
int carbonado_verification_key(uint8_t format, uint8_t key_out[32]);

#ifdef __cplusplus
}
#endif

#endif /* CARBONADO_H */
