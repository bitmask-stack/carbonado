/**
 * Carbonado SLH-DSA-SHA2-128s FFI (R9 / G10).
 *
 * Links libbitcoinpqc SLH sources (sphincsplus + slh_dsa wrappers) only —
 * no secp256k1 / ML-DSA. This path is for the Lean AOT demo binary only
 * (`@[extern]`), not a Rust `-sys` / C ABI product.
 *
 * Lean @[extern] wire (status-prefixed ByteArray, like zstd):
 *   carbonado_slh_keygen_raw : @& ByteArray → ByteArray
 *     status 0 + pk(32) + sk(64); else status only
 *   carbonado_slh_sign_raw   : @& ByteArray → @& ByteArray → ByteArray
 *     sk + message → status 0 + sig(7856); else status only
 *   carbonado_slh_verify_raw : @& ByteArray → @& ByteArray → @& ByteArray → UInt8
 *     pk + message + sig → 1 accept / 0 reject
 *
 * Status codes (Lean decodeSlhStatusPayload):
 *   0 OK
 *   1 short entropy (keygen)
 *   2 other bad argument (wrong sk/pk/sig sizes)
 *   3 crypto failure (keygen/sign library error)
 *
 */
#include <lean/lean.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libbitcoinpqc/slh_dsa.h"

enum {
  SLH_ST_OK = 0,
  SLH_ST_BAD_ENTROPY = 1,
  SLH_ST_BAD_ARG = 2,
  SLH_ST_CRYPTO = 3
};

/* Non-NULL empty buffer for SLH APIs that reject NULL message pointers. */
static const uint8_t g_empty_msg[1] = {0};

static lean_obj_res mk_status(uint8_t status, const uint8_t *payload, size_t payload_len) {
  size_t total = 1 + payload_len;
  lean_obj_res out = lean_alloc_sarray(1, total, total);
  uint8_t *p = lean_sarray_cptr(out);
  p[0] = status;
  if (payload_len > 0 && payload != NULL) {
    memcpy(p + 1, payload, payload_len);
  }
  return out;
}

static lean_obj_res mk_status_only(uint8_t status) {
  return mk_status(status, NULL, 0);
}

static const uint8_t *msg_ptr(const uint8_t *message, size_t message_len) {
  if (message_len == 0) {
    return g_empty_msg;
  }
  return message;
}

/* carbonado_slh_keygen_raw : @& ByteArray → ByteArray */
LEAN_EXPORT lean_obj_res carbonado_slh_keygen_raw(b_lean_obj_arg entropy) {
  size_t ent_len = lean_sarray_size(entropy);
  const uint8_t *ent = lean_sarray_cptr(entropy);
  if (ent_len < 128 || ent == NULL) {
    return mk_status_only(SLH_ST_BAD_ENTROPY);
  }
  uint8_t pk[SLH_DSA_SHA2_128S_PUBLIC_KEY_SIZE];
  uint8_t sk[SLH_DSA_SHA2_128S_SECRET_KEY_SIZE];
  if (slh_dsa_sha2_128s_keygen(pk, sk, ent, ent_len) != 0) {
    memset(sk, 0, sizeof sk);
    return mk_status_only(SLH_ST_CRYPTO);
  }
  uint8_t payload[SLH_DSA_SHA2_128S_PUBLIC_KEY_SIZE + SLH_DSA_SHA2_128S_SECRET_KEY_SIZE];
  memcpy(payload, pk, SLH_DSA_SHA2_128S_PUBLIC_KEY_SIZE);
  memcpy(payload + SLH_DSA_SHA2_128S_PUBLIC_KEY_SIZE, sk, SLH_DSA_SHA2_128S_SECRET_KEY_SIZE);
  lean_obj_res out = mk_status(SLH_ST_OK, payload, sizeof payload);
  memset(sk, 0, sizeof sk);
  memset(payload + SLH_DSA_SHA2_128S_PUBLIC_KEY_SIZE, 0, SLH_DSA_SHA2_128S_SECRET_KEY_SIZE);
  return out;
}

/* carbonado_slh_sign_raw : @& ByteArray → @& ByteArray → ByteArray  (sk, message) */
LEAN_EXPORT lean_obj_res carbonado_slh_sign_raw(b_lean_obj_arg sk, b_lean_obj_arg message) {
  size_t sk_len = lean_sarray_size(sk);
  size_t m_len = lean_sarray_size(message);
  const uint8_t *sk_p = lean_sarray_cptr(sk);
  const uint8_t *m_p = lean_sarray_cptr(message);
  if (sk_len != SLH_DSA_SHA2_128S_SECRET_KEY_SIZE || sk_p == NULL) {
    return mk_status_only(SLH_ST_BAD_ARG);
  }
  if (m_p == NULL && m_len != 0) {
    return mk_status_only(SLH_ST_BAD_ARG);
  }
  const uint8_t *msg = msg_ptr(m_p, m_len);
  uint8_t sig[SLH_DSA_SHA2_128S_SIGNATURE_SIZE];
  size_t siglen = 0;
  if (slh_dsa_sha2_128s_sign(sig, &siglen, msg, m_len, sk_p) != 0 ||
      siglen != SLH_DSA_SHA2_128S_SIGNATURE_SIZE) {
    return mk_status_only(SLH_ST_CRYPTO);
  }
  return mk_status(SLH_ST_OK, sig, SLH_DSA_SHA2_128S_SIGNATURE_SIZE);
}

/* carbonado_slh_verify_raw : @& ByteArray → @& ByteArray → @& ByteArray → UInt8 */
LEAN_EXPORT uint8_t carbonado_slh_verify_raw(b_lean_obj_arg pk, b_lean_obj_arg message,
                                             b_lean_obj_arg signature) {
  size_t pk_len = lean_sarray_size(pk);
  size_t m_len = lean_sarray_size(message);
  size_t sig_len = lean_sarray_size(signature);
  const uint8_t *pk_p = lean_sarray_cptr(pk);
  const uint8_t *m_p = lean_sarray_cptr(message);
  const uint8_t *sig_p = lean_sarray_cptr(signature);
  if (pk_len != SLH_DSA_SHA2_128S_PUBLIC_KEY_SIZE || pk_p == NULL) {
    return 0;
  }
  if (sig_len != SLH_DSA_SHA2_128S_SIGNATURE_SIZE || sig_p == NULL) {
    return 0;
  }
  if (m_p == NULL && m_len != 0) {
    return 0;
  }
  const uint8_t *msg = msg_ptr(m_p, m_len);
  return slh_dsa_sha2_128s_verify(sig_p, sig_len, msg, m_len, pk_p) == 0 ? 1 : 0;
}
