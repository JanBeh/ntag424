#ifndef NTAG424_H_
#define NTAG424_H_

#include <stdint.h>
#include <stdbool.h>

#include "lrp.h"

// Length of authentication keys:
#define NTAG424_KEY_LEN LRP_KEY_LEN

// Length of transaction identifier:
#define NTAG424_TI_LEN 4

// Length of UID
#define NTAG424_UID_LEN 7

// Maximum read length of this library:
// (Note that the used interface for transceiving may impose lower limits.)
#define NTAG424_READLEN_MAX 256

// Read buffer length:
#define NTAG424_RXBUF_LEN (NTAG424_READLEN_MAX+16+8+2)

// Error codes:
#define NTAG424_ERR_NOT_IMPL -1
#define NTAG424_ERR_INV_ARG -2
#define NTAG424_ERR_TRX_ERROR -3
#define NTAG424_ERR_NO_STATUS -4
#define NTAG424_ERR_BAD_STATUS -5
#define NTAG424_ERR_INV_RESP -6
#define NTAG424_ERR_RANDOM -7
#define NTAG424_ERR_LRP_DISABLED -8
#define NTAG424_ERR_NO_SUCH_KEY -9
#define NTAG424_ERR_PERMISSION_DENIED -10
#define NTAG424_ERR_AUTH_DELAY -11
#define NTAG424_ERR_AUTH_ERROR -12
#define NTAG424_ERR_INTEGRITY -13

// Communication modes:
// (values match internal bit masks, ordering matters)
#define NTAG424_MODE_PLAIN 0
#define NTAG424_MODE_MAC 1
#define NTAG424_MODE_FULL 3

// Files:
#define NTAG424_FILE_CAPABILITIES 1
#define NTAG424_FILE_NDEF 2
#define NTAG424_FILE_PROPRIETARY 3

// Default capabilities and file settings:
#define NTAG424_CAPABILITIES_LEN 32
extern const uint8_t ntag424_default_capabilities[NTAG424_CAPABILITIES_LEN];
extern const uint8_t ntag424_default_file1_settings[3];
extern const uint8_t ntag424_default_file2_settings[3];
extern const uint8_t ntag424_default_file3_settings[3];
extern const uint8_t ntag424_default_config_failctr[5];
extern const uint8_t ntag424_default_config_hardware[1];

// Type of transceive callback function:
// (callback returns byte count on success or negative error code)
typedef int (*transceive_fptr)(
  void *device,
  uint8_t *txbuf, size_t txlen,
  uint8_t *rxbuf, size_t rxlen
);

// Type for status words reported by card:
typedef struct {
  uint8_t sw1;
  uint8_t sw2;
} nfc424_picc_status_t;

// Context:
typedef struct {
  // LRP (signing and encryption) context:
  lrp_ctx_t lrp_ctx[1];
  // Opaque pointer passed to transceive callback:
  void *device;
  // Transceive callback:
  transceive_fptr transceive;
  // Error code of this library (zero indicates success):
  int error;
  // Error code of transceive callback (negative on error, otherwise zero):
  int trx_error;
  // PICC status words if error is NTAG424_ERR_BAD_STATUS (otherwise zero):
  nfc424_picc_status_t picc_status;
  // Receive buffer (also used for dynamic error messages):
  uint8_t rxbuf[NTAG424_RXBUF_LEN];
  // Length of data (without status words) in receive buffer:
  size_t datalen;
  // Transaction identifier:
  uint8_t ti[NTAG424_TI_LEN];
  // Command counter:
  uint16_t cmd_ctr;
  // True if application has been selected with ISOSelectFile command:
  bool application_selected;
  // True if authenticated:
  bool authenticated;
} ntag424_ctx_t;

// Manufacturing related data:
typedef struct {
  uint8_t VendorID;
  uint8_t Type;
  uint8_t SubType;
  uint8_t MajorVersion;
  uint8_t MinorVersion;
  uint8_t StorageSize;
  uint8_t Protocol;
} ntag424_version_t;
typedef struct {
  ntag424_version_t hw;
  ntag424_version_t sw;
  uint8_t uid[7]; // set to zero on randomized UID
  uint8_t batch[15]; // only batch_length bytes are used
  size_t batch_length;
} ntag424_mfg_t;

// Obtain error string:
// (no allocation, valid until context is used again)
char *ntag424_strerror(
  ntag424_ctx_t *ctx
);

// Depending on the return type, the following functions indictate errors
// by returning false (for bool), -1 (for int), or NULL (for pointers).

// Initialize context:
bool ntag424_init(
  ntag424_ctx_t *ctx,
  void *device, // opaque pointer passed to transceive callback
  transceive_fptr transceive
);

// Leave application (select PICC level):
bool ntag424_ISOSelectFile_master(
  ntag424_ctx_t *ctx
);

// Enter application (select dedicated file):
bool ntag424_ISOSelectFile_application(
  ntag424_ctx_t *ctx
);

// Retrieve manufacturing data:
// (only supported mode is plain communication mode, prior authentication)
bool ntag424_GetVersion(
  ntag424_ctx_t *ctx,
  ntag424_mfg_t *mfg
);

// Get key version:
// (returns -1 on error)
int ntag424_GetKeyVersion(
  ntag424_ctx_t *ctx,
  int key_number
);

// Select application and authenticate:
bool ntag424_AuthenticateLRP(
  ntag424_ctx_t *ctx,
  int key_number,
  uint8_t *key // key has NTAG424_KEY_LEN bytes
);

// Change master key:
bool ntag424_ChangeKey_master(
  ntag424_ctx_t *ctx,
  const uint8_t *new_key, // new_key has NTAG424_KEY_LEN bytes
  int new_key_version
);

// Change key:
bool ntag424_ChangeKey(
  ntag424_ctx_t *ctx,
  int key_number,
  const uint8_t *old_key, // old_key has NTAG424_KEY_LEN bytes
  const uint8_t *new_key, // new_key has NTAG424_KEY_LEN bytes
  int new_key_version
);

// Get UID (NTAG424_UID_LEN bytes):
// (no allocation, result valid until context is used again)
uint8_t *ntag424_GetCardUID(
  ntag424_ctx_t *ctx
);

// Get file settings:
// (result available in ctx->rxbuf with a length of ctx->datalen bytes)
bool ntag424_GetFileSettings(
  ntag424_ctx_t *ctx,
  int file_number
);

// Change file settings:
bool ntag424_ChangeFileSettings(
  ntag424_ctx_t *ctx,
  int file_number,
  const uint8_t *settings,
  size_t settings_length
);

#define NTAG424_FILE_SETTINGS_LEN 3
#define NTAG424_FILE_ACCESS_FREE 0xE
#define NTAG424_FILE_ACCESS_DENY 0xF

// Create file settings (without secure dynamic messaging):
void ntag424_file_settings(
  uint8_t *settings, // minimum NTAG424_FILE_SETTINGS_LEN bytes
  int mode,
  uint8_t read_key,
  uint8_t write_key,
  uint8_t read_write_key,
  uint8_t change_key
);

// Initialize capabilities in temporary memory:
void ntag424_init_capabilities(
  uint8_t *capabilities // NTAG424_CAPABILITIES_LEN bytes
);

// Edit capabilities in temporary memory based on file settings:
void ntag424_edit_capabilities(
  uint8_t *capabilities, // NTAG424_CAPABILITIES_LEN bytes
  int file_number,
  uint8_t read_key,
  uint8_t write_key,
  uint8_t read_write_key,
  uint8_t change_key
);

// Read file without MAC or encryption:
// (result available in ctx->rxbuf with a length of ctx->datalen bytes)
bool ntag424_ISOReadBinary(
  ntag424_ctx_t *ctx,
  int file_number,
  size_t offset,
  size_t length // less bytes may be read, specifying zero means read all
);

// Read exact number of bytes from file:
// (no allocation, result valid until context is used again)
uint8_t *ntag424_ReadData(
  ntag424_ctx_t *ctx,
  int mode,
  int file_number,
  size_t offset,
  size_t length // zero means read nothing, error if not all bytes can be read
);

// Write to file:
bool ntag424_WriteData(
  ntag424_ctx_t *ctx,
  int mode,
  int file_number,
  size_t offset,
  const uint8_t *data,
  size_t length
);

// Get read counter:
int32_t ntag424_GetFileCounters_SDMReadCtr(
  ntag424_ctx_t *ctx,
  int file_number
);

// Configuration options:
#define NTAG424_CONFIG_OPTION_PICC 0x00 // PICCConfig
#define NTAG424_CONFIG_OPTION_SECURE 0x04 // SMConfig
#define NTAG424_CONFIG_OPTION_PDCAP2 0x05 // Capability data
#define NTAG424_CONFIG_OPTION_FAILCTR 0x0A // Failed authentication counter
#define NTAG424_CONFIG_OPTION_HARDWARE 0x0B // Hardware configuration

// Change device configuration:
bool ntag424_SetConfiguration(
  ntag424_ctx_t *ctx,
  int option,
  const uint8_t *data,
  size_t length
);

// Reset file settings and capability container:
bool ntag424_reset_settings(
  ntag424_ctx_t *ctx
);

#endif
