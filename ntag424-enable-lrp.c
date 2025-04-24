#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdalign.h>
#include <string.h>
#include <unistd.h>
#include <sys/random.h>

#include <nfc/nfc.h>

#include "aes.h"

// Context for CMAC calculation:
typedef struct {
  aes_ctx_t aes_ctx[1];
  alignas(AES_BLOCK_ALIGN) uint8_t k1[16];
  alignas(AES_BLOCK_ALIGN) uint8_t k2[16];
} cmac_ctx_t;

// Set 16 byte CMAC key (no alignment required):
void cmac_key(cmac_ctx_t *ctx, uint8_t *key) {
  bool msb_set, tmp;
  // Encrypt zero block with key:
  aes_key(ctx->aes_ctx, key);
  memset(ctx->k1, 0, 16);
  aes_enc(ctx->aes_ctx, ctx->k1);
  // Shift block one bit to the left:
  msb_set = false;
  for (int i=16-1; i>=0; i--) {
    tmp = ctx->k1[i] & 0x80;
    ctx->k1[i] <<= 1;
    if (msb_set) ctx->k1[i] |= 1;
    msb_set = tmp;
  }
  // And XOR with 0x87 on carry:
  if (msb_set) ctx->k1[16-1] ^= 0x87;
  // For second additional key, shift and optionally XOR again:
  memcpy(ctx->k2, ctx->k1, 16);
  msb_set = false;
  for (int i=16-1; i>=0; i--) {
    tmp = ctx->k2[i] & 0x80;
    ctx->k2[i] <<= 1;
    if (msb_set) ctx->k2[i] |= 1;
    msb_set = tmp;
  }
  if (msb_set) ctx->k2[16-1] ^= 0x87;
}

// Calculate MAC for given data:
// NOTE: mac pointer must be aligned, but data pointer requires no alignment.
void cmac(cmac_ctx_t *ctx, uint8_t *mac, uint8_t *data, size_t len) {
  memset(mac, 0, 16);
  for (; len>16; len-=16) {
    for (int i=0; i<16; i++) mac[i] ^= *(data++);
    aes_enc(ctx->aes_ctx, mac);
  }
  for (int i=0; i<len; i++) mac[i] ^= *(data++);
  if (len == 16) {
    for (int i=0; i<16; i++) mac[i] ^= ctx->k1[i];
  } else {
    mac[len] ^= 0x80;
    for (int i=0; i<16; i++) mac[i] ^= ctx->k2[i];
  }
  aes_enc(ctx->aes_ctx, mac);
}

// Modulation for NTAG424:
static const nfc_modulation nmMifare = {
  .nmt = NMT_ISO14443A,
  .nbr = NBR_106,
};

// Helper function for printing hex values to stderr:
static void print_hex(char *name, uint8_t *data, size_t len) {
  if (len) {
    size_t rpos, wpos;
    int status;
    char hex[3*len];
    for (rpos=0, wpos=0; rpos<len; rpos++) {
      status = sprintf(hex+wpos, rpos?":%02X":"%02X", data[rpos]);
      if (status < 0) abort();
      wpos += status;
    }
    fprintf(stderr, "%s: %s\n", name, hex);
  } else {
    fprintf(stderr, "%s: (none)\n", name);
  }
}

// Main function:
int main(int argc, char **argv) {
  int exitcode = 1;
  nfc_context *context = NULL;
  nfc_device *pnd = NULL;
  nfc_target nt;
  int status;
  fprintf(stderr, "Initializing NFC library...\n");
  nfc_init(&context);
  if (!context) {
    fprintf(stderr, "Terminating due to memory allocation error.\n");
    goto close;
  }
  fprintf(stderr, "Initialization done.\n");
  fprintf(stderr, "Opening NFC device...\n");
  pnd = nfc_open(context, NULL);
  if (!pnd) {
    fprintf(stderr, "Could not open NFC device.\n");
    goto close;
  }
  fprintf(stderr, "Initializing NFC device as initiator...\n");
  if (nfc_initiator_init(pnd) < 0) {
    nfc_perror(pnd, "nfc_initiator_init");
    goto close;
  }
  if (nfc_device_set_property_bool(pnd, NP_INFINITE_SELECT, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    goto close;
  }
  fprintf(stderr, "Initiator initialized.\n");
  fprintf(stderr, "Waiting for card...\n");
  while (1) {
    status = nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt);
    if (status > 0) break;
    if (status < 0) nfc_perror(pnd, "nfc_initiator_select_passive_target");
    usleep(500000);
  }
  // Print out card data:
  print_hex("ATQA", nt.nti.nai.abtAtqa, 2);
  print_hex("SAK", &nt.nti.nai.btSak, 1);
  print_hex("UID", nt.nti.nai.abtUid, nt.nti.nai.szUidLen);
  print_hex("ATS", nt.nti.nai.abtAts, nt.nti.nai.szAtsLen);
  // Buffer for card response (aligned for AES operations):
  alignas(AES_BLOCK_ALIGN) uint8_t rx[256];
  // Execute ISOSelectFile command with Application/DF name 0xD2760000850101:
  fprintf(stderr, "Selecting application file..\n");
  {
    uint8_t tx[13] = {
      0x00, // class byte for standard ISO command
      0xA4, // instruction byte for ISOSelectFile
      0x04, // parameter 1: select by DF name
      0x0C, // parameter 2: no response data
      7, // length of following data (without final byte for response length)
      0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, // 7 bytes DF name
      0x00 // accept any response length
    };
    status = nfc_initiator_transceive_bytes(
      pnd, tx, sizeof(tx), rx, sizeof(rx), -1
    );
  }
  if (status < 0) {
    nfc_perror(pnd, "nfc_initiator_transceive_bytes");
    goto close;
  }
  if (status != 2 || rx[0] != 0x90 || rx[1] != 0x00) {
    if (status != 2) fprintf(stderr, "Unexpected response length.\n");
    if (status >= 2) fprintf(stderr,
      "Status: %02X:%02X\n", rx[status-2], rx[status-1]);
    goto close;
  }
  fprintf(stderr, "Application selected.\n");
  // Generate random data for cryptography:
  uint8_t rnd_a[16];
  if (getrandom(rnd_a, 16, 0) != 16) {
    fprintf(stderr, "getrandom failed\n");
    goto close;
  }
  // Execute AuthenticateEV2First command:
  fprintf(stderr, "Authenticating with AppMasterKey...\n");
  // Send first part of AuthenticateEV2First command sequence:
  {
    uint8_t tx[9] = {
      0x90, // class byte
      0x71, // instruction byte for first part of AuthenticateEV2First
      0x00, 0x00, // unused parameters set to zero
      3, // length of following data (without final byte for response length)
      0x00, // key number of AppMasterKey
      1, // length of following PCDcap2 array
      0x00, // PCDcap2.1 set to zero for EV2 secure messaging (instead of LRP)
      0x00 // accept any response length
    };
    status = nfc_initiator_transceive_bytes(
      pnd, tx, sizeof(tx), rx, sizeof(rx), -1
    );
  }
  if (status < 0) {
    nfc_perror(pnd, "nfc_initiator_transceive_bytes");
    goto close;
  }
  if (status != 18 || rx[status-2] != 0x91 || rx[status-1] != 0xAF) {
    if (status != 18 && status != 2) fprintf(stderr,
      "Unexpected response length in authentication step #1.\n");
    if (status >= 2) fprintf(stderr,
      "Status in authentication step #1: %02X:%02X\n",
      rx[status-2], rx[status-1]);
    goto close;
  }
  // Initialize CMAC (and AES) with key (set all to zero):
  uint8_t key[16] = { 0, };
  cmac_ctx_t cmac_ctx[1];
  cmac_key(cmac_ctx, key);
  // Use AES context from CMAC for now:
  aes_ctx_t *aes_ctx = cmac_ctx->aes_ctx;
  // Decrypt RndB from card:
  alignas(AES_BLOCK_ALIGN) uint8_t rnd_b[16];
  memcpy(rnd_b, rx, 16);
  aes_dec(aes_ctx, rnd_b);
  // Encrypt RndA concatenated with byte shifted RndB in CBC mode with IV=0,
  // which is our authentication response:
  alignas(AES_BLOCK_ALIGN) uint8_t auth_data[32];
  memcpy(auth_data, rnd_a, 16);
  memcpy(auth_data+16, rnd_b+1, 15);
  auth_data[31] = rnd_b[0];
  aes_enc(aes_ctx, auth_data);
  for (int i=0; i<16; i++) auth_data[16+i] ^= auth_data[i];
  aes_enc(aes_ctx, auth_data+16);
  // Send second part of AuthenticateEV2First command sequence:
  {
    uint8_t tx[38] = {
      0x90, // class byte
      0xAF, // instruction byte for second part
      0x00, 0x00, // unused parameters set to zero
      32, // length of following data (without final byte for response length)
      // further data filled in below
    };
    // Fill in authentication response:
    memcpy(tx+5, auth_data, 32);
    status = nfc_initiator_transceive_bytes(
      pnd, tx, sizeof(tx), rx, sizeof(rx), -1
    );
  }
  if (status < 0) {
    nfc_perror(pnd, "nfc_initiator_transceive_bytes");
    goto close;
  }
  if (status != 34 || rx[status-2] != 0x91 || rx[status-1] != 0x00) {
    if (status != 34 && status != 2) fprintf(stderr,
      "Unexpected response length in authentication step #2.\n");
    if (status >= 2) fprintf(stderr,
      "Status in authentication step #2: %02X:%02X\n",
      rx[status-2], rx[status-1]);
    goto close;
  }
  // Decrypt response from card in CBC mode with IV=0:
  aes_dec(aes_ctx, rx+16);
  for (int i=0; i<16; i++) rx[16+i] ^= rx[i];
  aes_dec(aes_ctx, rx);
  // Verify if byte shifted RndA has been received:
  if (memcmp(rx+4, rnd_a+1, 15) || rx[19] != rnd_a[0]) {
    fprintf(stderr, "Response signature failed.\n");
    goto close;
  }
  // Verify requested PCDcap2 that has been sent in step 1:
  {
    uint8_t val[6] = { 0, };
    if (memcmp(rx+26, val, 6)) {
      fprintf(stderr, "PCDcap2 verification failed.\n");
      goto close;
    }
  }
  if (memcmp(rx+4, rnd_a+1, 15) || rx[19] != rnd_a[0]) {
    fprintf(stderr, "Response signature failed.\n");
    goto close;
  }
  fprintf(stderr, "Authentication successful.\n");
  // Store decrypted 4 byte transaction identifier:
  uint8_t ti[4];
  memcpy(ti, rx, 4);
  // Derive encryption and signing keys:
  alignas(AES_BLOCK_ALIGN) uint8_t enc_key[16];
  alignas(AES_BLOCK_ALIGN) uint8_t mac_key[16];
  {
    uint8_t sv1[32] = { 0xA5, 0x5A, 0x00, 0x01, 0x00, 0x80, };
    uint8_t sv2[32] = { 0x5A, 0xA5, 0x00, 0x01, 0x00, 0x80, };
    sv1[6] = rnd_a[0];
    sv1[7] = rnd_a[1];
    for (int i=0; i<6; i++) sv1[8+i] = rnd_a[2+i] ^ rnd_b[0+i];
    memcpy(sv1+14, rnd_b+6, 10);
    memcpy(sv1+24, rnd_a+8, 8);
    memcpy(sv2+6, sv1+6, 26);
    cmac(cmac_ctx, enc_key, sv1, sizeof(sv1));
    cmac(cmac_ctx, mac_key, sv2, sizeof(sv2));
  }
  // Use derived signing key for CMAC from now on:
  cmac_key(cmac_ctx, mac_key);
  // Use derived encryption key for AES encryption/decryption from now on:
  aes_ctx_t new_aes_ctx[1];
  aes_ctx = new_aes_ctx;
  aes_key(aes_ctx, enc_key);
  // Buffer for MAC calculation:
  alignas(AES_BLOCK_ALIGN) uint8_t mac[16];
  // Execute SetConfiguration command:
  fprintf(stderr, "Permanently enabling LRP mode...\n");
  {
    uint8_t tx[31] = {
      0x90, // class byte
      0x5C, // instruction byte for SetConfiguration
      0x00, 0x00, // unused parameters set to zero
      25, // length of following data (without final byte for response length)
      // (one option byte, 16 byte encrypted data, and 8 byte signature)
      0x05, // option byte: capability data
      // further data filled in below
    };
    // Build initialization vector for encrypting command data:
    alignas(AES_BLOCK_ALIGN) uint8_t iv[16] = {
      0xA5, 0x5A, // bytes for command data encryption
      0x00, 0x00, 0x00, 0x00, // transaction identifier filled in below
      0x00, 0x00, // command counter (LSB first) set to zero
    };
    // Fill in transaction identifier:
    memcpy(iv+2, ti, 4);
    // Command data:
    alignas(AES_BLOCK_ALIGN) uint8_t tx_data[16] = {
      0x00, 0x00, 0x00, 0x00, // 4 bytes reserved for future use
      0x02, // PDCap2.1 set to 0x02 to enable LRP
      0x00, 0x00, 0x00, // 3 bytes reserved for future use
      0x00, 0x00, // PDCap2.5 and PDCap2.6
      0x80, // begin of padding
      // trailing zeros
    };
    // Encrypt command data in CBC mode using IV:
    aes_enc(aes_ctx, iv);
    for (int i=0; i<16; i++) tx_data[i] ^= iv[i];
    aes_enc(aes_ctx, tx_data);
    // Calculate MAC input:
    uint8_t mac_msg[24] = {
      0x00, // command byte filled in below
      0x00, 0x00, // 2 byte command counter (LSB first) set to zero
      // further data filled in below
    };
    // Command byte in MAC input:
    mac_msg[0] = tx[1];
    // Transaction identifier in MAC input:
    memcpy(mac_msg+3, ti, 4);
    // Option byte in MAC input:
    mac_msg[7] = tx[5];
    // Command data in MAC input:
    memcpy(mac_msg+8, tx_data, 16);
    // Calculate MAC:
    cmac(cmac_ctx, mac, mac_msg, sizeof(mac_msg));
    // Copy command data to transmit buffer:
    memcpy(tx+6, tx_data, 16);
    // Copy (even bytes of) MAC to transmit buffer:
    for (int i=0; i<8; i++) tx[22+i] = mac[2*i+1];
    // Transmit:
    status = nfc_initiator_transceive_bytes(
      pnd, tx, sizeof(tx), rx, sizeof(rx), -1
    );
  }
  if (status < 0) {
    nfc_perror(pnd, "nfc_initiator_transceive_bytes");
    goto close;
  }
  // NOTE: On success, no MAC is generated.
  if (status < 2 || rx[status-2] != 0x91 || rx[status-1] != 0x00) {
    if (status < 2) fprintf(stderr, "Unexpected response length.\n");
    else fprintf(stderr, "Status: %02X:%02X\n", rx[status-2], rx[status-1]);
    goto close;
  }
  fprintf(stderr, "Operation successfully terminated.\n");
  // Success:
  exitcode = 0;
close:
  // Cleanup:
  if (pnd) nfc_close(pnd);
  if (context) nfc_exit(context);
  return exitcode;
}
