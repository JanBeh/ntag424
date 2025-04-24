#ifndef LRP_H_
#define LRP_H_

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdalign.h>

#include "aes.h"

// Size of lrp_block_t in bytes:
#define LRP_BLOCK_LEN 16

// Size of key in bytes
#define LRP_KEY_LEN LRP_BLOCK_LEN

// Size of MAC in bytes:
#define LRP_MAC_LEN LRP_BLOCK_LEN

// Count of precalculated plaintext blocks used by LRP algorithm:
#define LRP_PT_COUNT 16

// Size of initialization vector for encryption and decryption in bytes:
#define LRP_ENC_IV_LEN 4

// Count of derived keys needed by LRP-CMAC:
#define LRP_MAC_KEY_COUNT 3

// Return value of lrp_enc function to indicate padding decryption error:
#define LRP_INVALID ((size_t)0 - (size_t)1)

// Data block for underlying cipher:
typedef union {
  alignas(AES_BLOCK_ALIGN) uint8_t bytes[LRP_BLOCK_LEN];
} lrp_block_t;

// Structure holding derived keys, initialization vector, and caching info:
typedef struct {
  // Precalculated plaintext blocks used by LRP algorithm:
  lrp_block_t pts[LRP_PT_COUNT];
  // mac_keys[0] is a derived key used for MAC calculation,
  // mac_keys[1] and mac_keys[2] are derived keys (K1 and K2) used by CMAC:
  lrp_block_t mac_keys[LRP_MAC_KEY_COUNT];
  // enc_states[0] is a derived key used for encryption and decryption,
  // enc_states[i] additionally processed the first i bytes of the counter:
  lrp_block_t enc_states[LRP_ENC_IV_LEN+1];
  // Context of underlying AES library:
  aes_ctx_t aes_ctx;
  // Indicates how many bytes i of enc_counter have been processed and whose
  // results are cached in enc_states[i]:
  int enc_counter_pos;
  // Initialization vector (counter stored as big endian):
  uint8_t enc_counter[LRP_ENC_IV_LEN];
} lrp_ctx_t;

// Set key for MAC and optionally also for encryption and decryption:
void lrp_key(
  lrp_ctx_t *restrict ctx,
  uint8_t *restrict key,
  bool encryption
);

// Set initialiation vector (IV) with LRP_ENC_IV_LEN bytes for encryption and
// decryption:
void lrp_enc_iv(
  lrp_ctx_t *restrict ctx,
  uint8_t *restrict iv
);

// Encrypt or decrypt data in place:
// Returns LRP_INVALID on padding decryption error, otherwise length of result.
// When encrypting with padding, then the data pointer must refer to a large
// enough chunk of usable memory.
size_t lrp_enc(
  lrp_ctx_t *restrict ctx,
  uint8_t *restrict data,
  size_t len,
  bool padding,
  bool decrypt
);

// Calculate message authentication code (MAC) with LRP_MAC_LEN bytes:
void lrp_mac(
  lrp_ctx_t *restrict ctx,
  uint8_t *restrict mac,
  uint8_t *restrict data,
  size_t len
);

#endif
