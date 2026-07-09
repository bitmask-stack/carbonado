/**
 * C ABI surface for libcarbonado (docs/ABI.md, include/carbonado.h).
 *
 * Phase 1: version + free + thin wrappers. Full encode/decode path is driven from
 * Lean `@[export]` symbols when linked into the AOT image; until those symbols are
 * part of the shared static archive used by carbonado-sys, encode/decode return
 * CARBONADO_ERR_NOT_IMPLEMENTED so Rust can fail closed instead of linking garbage.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "carbonado.h"

uint32_t carbonado_abi_version(void) {
  return CARBONADO_ABI_VERSION;
}

void carbonado_free(void *p) {
  free(p);
}

/* Weak stubs: real implementations may be provided by Lean @[export] objects
 * when the full static archive is linked. These provide a defined symbol so
 * partial links still resolve. */
__attribute__((weak)) int carbonado_encode(
    const uint8_t *master, size_t master_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t format,
    const uint8_t *nonce, size_t nonce_len,
    uint8_t **out, size_t *out_len,
    uint8_t hash_out[32]) {
  (void)master; (void)master_len; (void)plaintext; (void)plaintext_len;
  (void)format; (void)nonce; (void)nonce_len; (void)out; (void)out_len; (void)hash_out;
  return CARBONADO_ERR_NOT_IMPLEMENTED;
}

__attribute__((weak)) int carbonado_decode(
    const uint8_t *master, size_t master_len,
    const uint8_t *hash, size_t hash_len,
    const uint8_t *body, size_t body_len,
    uint32_t padding,
    uint8_t format,
    uint8_t **out, size_t *out_len) {
  (void)master; (void)master_len; (void)hash; (void)hash_len;
  (void)body; (void)body_len; (void)padding; (void)format; (void)out; (void)out_len;
  return CARBONADO_ERR_NOT_IMPLEMENTED;
}

__attribute__((weak)) int carbonado_encode_headered(
    const uint8_t *master, size_t master_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t format,
    const uint8_t *nonce, size_t nonce_len,
    uint8_t **out, size_t *out_len) {
  (void)master; (void)master_len; (void)plaintext; (void)plaintext_len;
  (void)format; (void)nonce; (void)nonce_len; (void)out; (void)out_len;
  return CARBONADO_ERR_NOT_IMPLEMENTED;
}

__attribute__((weak)) int carbonado_decode_headered(
    const uint8_t *master, size_t master_len,
    const uint8_t *archive, size_t archive_len,
    uint8_t **out, size_t *out_len) {
  (void)master; (void)master_len; (void)archive; (void)archive_len;
  (void)out; (void)out_len;
  return CARBONADO_ERR_NOT_IMPLEMENTED;
}

__attribute__((weak)) int carbonado_verification_key(uint8_t format, uint8_t key_out[32]) {
  (void)format; (void)key_out;
  return CARBONADO_ERR_NOT_IMPLEMENTED;
}
