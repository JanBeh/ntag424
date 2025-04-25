#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <nfc/nfc.h>

#include "ntag424.h"

static const nfc_modulation nmMifare = {
  .nmt = NMT_ISO14443A,
  .nbr = NBR_106,
};

int transceive(
  void *restrict device,
  uint8_t *txbuf, size_t txlen,
  uint8_t *rxbuf, size_t rxlen
) {
  nfc_device *const pnd = device;
  return nfc_initiator_transceive_bytes(pnd, txbuf, txlen, rxbuf, rxlen, -1);
}

int main(int argc, char **argv) {
  int exitcode = 1;
  nfc_context *context = NULL;
  nfc_device *pnd = NULL;
  nfc_target nt;
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
  {
    int status;
    do {
      status = nfc_initiator_select_passive_target(
        pnd, nmMifare, NULL, 0, &nt
      );
      if (status < 0) {
        nfc_perror(pnd, "nfc_initiator_select_passive_target");
        usleep(500000);
        continue;
      }
    } while (status == 0);
  }
  fprintf(stderr, "Card in field.\n");
  ntag424_ctx_t ctx[1];
  ntag424_init(ctx, pnd, transceive);
  fprintf(stderr, "Get manufacturing info...\n");
  ntag424_mfg_t mfg;
  if (!ntag424_GetVersion(ctx, &mfg)) {
    fprintf(stderr, "Request failed: %s\n", ntag424_strerror(ctx));
    goto close;
  }
  fprintf(stderr,
    "Hardware: %02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX\n",
    mfg.hw.VendorID, mfg.hw.Type, mfg.hw.SubType,
    mfg.hw.MajorVersion, mfg.hw.MinorVersion,
    mfg.hw.StorageSize, mfg.hw.Protocol);
  fprintf(stderr,
    "Software: %02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX\n",
    mfg.sw.VendorID, mfg.sw.Type, mfg.sw.SubType,
    mfg.sw.MajorVersion, mfg.sw.MinorVersion,
    mfg.sw.StorageSize, mfg.sw.Protocol);
  fprintf(stderr,
    "UID: %02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX\n",
    mfg.uid[0], mfg.uid[1], mfg.uid[2], mfg.uid[3], mfg.uid[4], mfg.uid[5],
    mfg.uid[6]);
  fprintf(stderr, "Batch: ");
  for (int i=0; i<mfg.batch_length; i++) {
    if (i) fprintf(stderr, ":");
    fprintf(stderr, "%02hhX", mfg.batch[i]);
  }
  fprintf(stderr, "\n");
  fprintf(stderr, "Selecting application...\n");
  if (!ntag424_ISOSelectFile_application(ctx)) {
    fprintf(stderr,
      "Failed to select application: %s\n", ntag424_strerror(ctx));
    goto close;
  }
  fprintf(stderr, "Application selected.\n");
  {
    fprintf(stderr, "Reading capability file with standard ISO command...\n");
    // NOTE: Using NTAG424_READLEN_MAX seems to cause issues with too big
    // frames, depending on the used interface. We read a maximum of 128 bytes,
    // i.e. 0x80 bytes, instead.
    if (!ntag424_ISOReadBinary(ctx, NTAG424_FILE_CAPABILITIES, 0, 0x80)) {
      fprintf(stderr,
        "Reading capabilities failed: %s\n", ntag424_strerror(ctx));
      goto close;
    }
    for (int i=0; i<ctx->datalen; i++) {
      fprintf(stdout, "%02hhX", ctx->rxbuf[i]);
    }
    fprintf(stdout, "\n");
    fprintf(stderr, "Done.\n");
  }
  fprintf(stderr, "Get key version...\n");
  {
    int version = ntag424_GetKeyVersion(ctx, 0);
    if (version < 0) {
      fprintf(stderr, "Request failed: %s\n", ntag424_strerror(ctx));
      goto close;
    }
    fprintf(stderr, "Key version is %i.\n", version);
  }
  fprintf(stderr, "Authenticating...\n");
  uint8_t key[16] = { 0x00, };
  if (!ntag424_AuthenticateLRP(ctx, 0, key)) {
    fprintf(stderr, "Authentication failed: %s\n", ntag424_strerror(ctx));
    goto close;
  }
  fprintf(stderr, "Authentication successful.\n");
  fprintf(stderr, "Get key version again...\n");
  {
    int version = ntag424_GetKeyVersion(ctx, 0);
    if (version < 0) {
      fprintf(stderr, "Request failed: %s\n", ntag424_strerror(ctx));
      goto close;
    }
    fprintf(stderr, "Key version is %i.\n", version);
  }
  {
    fprintf(stderr, "Getting UID...\n");
    uint8_t *uid = ntag424_GetCardUID(ctx);
    if (!uid) {
      fprintf(stderr, "Request failed: %s\n", ntag424_strerror(ctx));
      goto close;
    }
    fprintf(stderr,
      "UID: %02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX\n",
      uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6]);
  }
  {
    fprintf(stderr, "Change configuration...\n");
    uint8_t setting[10] = {
      0x00, 0x00, 0x00, 0x00,
      0x02, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    if (!ntag424_SetConfiguration(
      ctx, NTAG424_CONFIG_OPTION_PDCAP2, setting, sizeof(setting)
    )) {
      fprintf(stderr, "Failed: %s\n", ntag424_strerror(ctx));
      goto close;
    }
    fprintf(stderr, "Done.\n");
  }
  for (int file_no=1; file_no<=3; file_no++) {
    fprintf(stderr, "Get file settings for file #%i...\n", file_no);
    if (!ntag424_GetFileSettings(ctx, file_no)) {
      fprintf(stderr,
        "Getting file settings failed: %s\n", ntag424_strerror(ctx));
      goto close;
    }
    fprintf(stderr, "Settings: ");
    for (int i=0; i<ctx->datalen; i++) {
      if (i) fprintf(stderr, ":");
      fprintf(stderr, "%02hhX", ctx->rxbuf[i]);
    }
    fprintf(stderr, "\n");
  }
  {
    fprintf(stderr, "Reading capability file...\n");
    uint8_t *rx;
    rx = ntag424_ReadData(
      ctx, NTAG424_MODE_PLAIN,
      NTAG424_FILE_CAPABILITIES, 0, NTAG424_CAPABILITIES_LEN
    );
    if (!rx) {
      fprintf(stderr,
        "Reading capabilities failed: %s\n", ntag424_strerror(ctx));
      goto close;
    }
    for (int i=0; i<NTAG424_CAPABILITIES_LEN; i++) {
      fprintf(stdout, "%02hhX", rx[i]);
    }
    fprintf(stdout, "\n");
    fprintf(stderr, "Done.\n");
  }
  {
    fprintf(stderr, "Protect file #2...\n");
    uint8_t file_settings[NTAG424_FILE_SETTINGS_LEN];
    uint8_t capabilities[NTAG424_CAPABILITIES_LEN];
    ntag424_init_capabilities(capabilities);
    ntag424_file_settings(file_settings, NTAG424_MODE_FULL, 0, 0, 0, 0);
    ntag424_edit_capabilities(capabilities, 2, 0, 0, 0, 0);
    if (!ntag424_ChangeFileSettings(
      ctx, 2, file_settings, sizeof(file_settings)
    )) {
      fprintf(stderr,
        "Changing file settings failed: %s\n", ntag424_strerror(ctx));
      goto close;
    }
    if (!ntag424_WriteData(
      ctx, NTAG424_MODE_PLAIN, NTAG424_FILE_CAPABILITIES, 0,
      capabilities, sizeof(capabilities)
    )) {
      fprintf(stderr,
        "Writing capabilities failed: %s\n", ntag424_strerror(ctx));
      goto close;
    }
    fprintf(stderr, "File #2 protected.\n");
  }
  {
    fprintf(stderr, "Reading capability file...\n");
    uint8_t *rx;
    rx = ntag424_ReadData(
      ctx, NTAG424_MODE_PLAIN,
      NTAG424_FILE_CAPABILITIES, 0, NTAG424_CAPABILITIES_LEN 
    );
    if (!rx) {
      fprintf(stderr,
        "Reading capabilities failed: %s\n", ntag424_strerror(ctx));
      goto close;
    }
    for (int i=0; i<NTAG424_CAPABILITIES_LEN; i++) {
      fprintf(stdout, "%02hhX", rx[i]);
    }
    fprintf(stdout, "\n");
    fprintf(stderr, "Done.\n");
  }
  {
    fprintf(stderr, "Reading file #2 (with encryption)...\n");
    uint8_t *rx;
    for (int chunk=0; chunk<2; chunk++) {
      const size_t chunk_len = 128;
      rx = ntag424_ReadData(ctx, NTAG424_MODE_FULL, 2, 0, chunk_len);
      if (!rx) {
        fprintf(stderr,
          "Reading file #2 (with encryption) failed: %s\n",
          ntag424_strerror(ctx));
        goto close;
      }
      for (int i=0; i<chunk_len; i++) fprintf(stdout, "%02hhX", rx[i]);
    }
    fprintf(stdout, "\n");
    fprintf(stderr, "Done.\n");
  }
  fprintf(stderr, "Resetting settings...\n");
  if (!ntag424_reset_settings(ctx)) {
    fprintf(stderr,
      "Reset failed: %s\n", ntag424_strerror(ctx));
    goto close;
  }
  fprintf(stderr, "Reset complete.\n");
  for (int file_no=1; file_no<=3; file_no++) {
    fprintf(stderr, "Get file settings for file #%i...\n", file_no);
    if (!ntag424_GetFileSettings(ctx, file_no)) {
      fprintf(stderr,
        "Getting file settings failed: %s\n", ntag424_strerror(ctx));
      goto close;
    }
    fprintf(stderr, "Settings: ");
    for (int i=0; i<ctx->datalen; i++) {
      if (i) fprintf(stderr, ":");
      fprintf(stderr, "%02hhX", ctx->rxbuf[i]);
    }
    fprintf(stderr, "\n");
  }
  {
    fprintf(stderr, "Reading capability file...\n");
    uint8_t *rx;
    rx = ntag424_ReadData(
      ctx, NTAG424_MODE_PLAIN,
      NTAG424_FILE_CAPABILITIES, 0, NTAG424_CAPABILITIES_LEN 
    );
    if (!rx) {
      fprintf(stderr,
        "Reading capabilities failed: %s\n", ntag424_strerror(ctx));
      goto close;
    }
    for (int i=0; i<NTAG424_CAPABILITIES_LEN; i++) {
      fprintf(stdout, "%02hhX", rx[i]);
    }
    fprintf(stdout, "\n");
    fprintf(stderr, "Done.\n");
  }
  exitcode = 0;
close:
  if (pnd) nfc_close(pnd);
  if (context) nfc_exit(context);
  return exitcode;
}
