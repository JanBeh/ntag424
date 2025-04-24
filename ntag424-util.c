#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

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

void usage(FILE *out, char *cmd) {
  fprintf(out, "Usage: %s\n\
  [ -h | --help ]\n\
  [ -q | --query-key-version ]\n\
  [ { -n | --key-number } <key number> ]\n\
  [ { -k | --key-file } <key file> ]\n\
  [ { -v | --key-version } <key version> ]\n\
  [ { -N | --change-key-number } <key number to change>\n\
    [ { -O | --old-key-file } <old key file> ]\n\
    { -K | --new-key-file } <new key file>\n\
    { -V | --new_key-version } <new key version> ]\n",
  cmd);
}

bool read_key(char *filename, uint8_t *key) {
  uint8_t dummy[1];
  FILE *keyfile = fopen(optarg, "r");
  if (!keyfile) {
    perror("Could not open key file");
    return false;
  }
  if (fread(key, NTAG424_KEY_LEN, 1, keyfile) != 1) {
    if (ferror(keyfile)) {
      perror("I/O error when reading from key file");
      fclose(keyfile);
      return false;
    } else {
      fprintf(stderr, "Premature EOF in key file\n");
      fclose(keyfile);
      return false;
    }
  }
  if (fread(dummy, 1, 1, keyfile) == 1) {
    fprintf(stderr, "Excessive bytes in key file\n");
    fclose(keyfile);
    return false;
  }
  if (ferror(keyfile)) {
    perror("I/O error when reading from key file");
    fclose(keyfile);
    return false;
  }
  return true;
}

static struct option longopts[] = {
  { "help", no_argument, NULL, 'h' },
  { "query-key-version", no_argument, NULL, 'q' },
  { "key-number", required_argument, NULL, 'n' },
  { "key-file", required_argument, NULL, 'k' },
  { "key-version", required_argument, NULL, 'v' },
  { "change-key-number", required_argument, NULL, 'N' },
  { "old-key-file", required_argument, NULL, 'O' },
  { "new-key-file", required_argument, NULL, 'K' },
  { "new-key-version", required_argument, NULL, 'V' },
  { NULL, 0, NULL, 0 }
};

static const char *shortopts = "hqn:k:v:N:O:K:V:";

int main(int argc, char **argv) {
  int exitcode = 1;
  nfc_context *context = NULL;
  nfc_device *pnd = NULL;
  nfc_target nt;
  int status;
  char *cmd = argc ? argv[0] : "ntag424-util";
  bool query_key_version = false;
  int key_number = 0;
  uint8_t key[NTAG424_KEY_LEN] = { 0, };
  int key_version = -1;
  int change_key_number = -1;
  uint8_t old_key[NTAG424_KEY_LEN] = { 0, };
  bool old_key_set = false;
  uint8_t new_key[NTAG424_KEY_LEN] = { 0, };
  bool new_key_set = false;
  int new_key_version = -1;
  char *endptr;
  int ch;
  while ((ch = getopt_long(argc, argv, shortopts, longopts, NULL)) != -1) {
    switch (ch) {
    case 'h':
      usage(stdout, cmd);
      return 0;
    case 'q':
      query_key_version = true;
      break;
    case 'n':
      key_number = strtol(optarg, &endptr, 10);
      if (*endptr || key_number < 0x00 || key_number > 0x1F) {
        fprintf(stderr, "Invalid key number\n");
        return 1;
      }
      break;
    case 'k':
      if (!read_key(optarg, key)) return 1;
      break;
    case 'v':
      key_version = strtol(optarg, &endptr, 10);
      if (*endptr || key_version < 0x00 || key_version > 0xFF) {
        fprintf(stderr, "Invalid key version\n");
        return 1;
      }
      break;
    case 'N':
      change_key_number = strtol(optarg, &endptr, 10);
      if (*endptr || change_key_number < 0x00 || change_key_number > 0x1F) {
        fprintf(stderr, "Invalid key number to change\n");
        return 1;
      }
      break;
    case 'O':
      if (!read_key(optarg, old_key)) return 1;
      old_key_set = true;
      break;
    case 'K':
      if (!read_key(optarg, new_key)) return 1;
      new_key_set = true;
      break;
    case 'V':
      new_key_version = strtol(optarg, &endptr, 10);
      if (*endptr || new_key_version < 0x00 || new_key_version > 0xFF) {
        fprintf(stderr, "Invalid new key version\n");
        return 1;
      }
      break;
   }
  }
  argc -= optind;
  argv += optind;
  if (argc) {
    fprintf(stderr, "Excessive command line arguments\n");
    return 1;
  }
  if (
    (old_key_set || new_key_set || new_key_version >= 0) &&
    change_key_number < 0
  ) {
    fprintf(stderr, "Missing key number to change\n");
    return 1;
  }
  if (change_key_number >= 1 && !old_key_set) {
    fprintf(stderr, "Missing old key\n");
    return 1;
  }
  if (change_key_number >= 0 && !new_key_set) {
    fprintf(stderr, "Missing new key\n");
    return 1;
  }
  if (change_key_number >= 0 && new_key_version < 0) {
    fprintf(stderr, "Missing new key version\n");
    return 1;
  }
  if (change_key_number >= 0 && key_number != 0) {
    fprintf(stderr, "Master key required\n");
    return 1;
  }
  nfc_init(&context);
  if (!context) {
    fprintf(stderr, "Memory allocation error\n");
    goto close;
  }
  pnd = nfc_open(context, NULL);
  if (!pnd) {
    fprintf(stderr, "Could not open NFC device.\n");
    goto close;
  }
  if (nfc_initiator_init(pnd) < 0) {
    nfc_perror(pnd, "nfc_initiator_init");
    goto close;
  }
  if (nfc_device_set_property_bool(pnd, NP_INFINITE_SELECT, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    goto close;
  }
  fprintf(stderr, "Waiting for card...\n");
  do {
    status = nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt);
    if (status < 0) {
      nfc_perror(pnd, "nfc_initiator_select_passive_target");
      usleep(500000);
      continue;
    }
  } while (status == 0);
  fprintf(stderr, "Card detected.\n");
  ntag424_ctx_t ctx[1];
  ntag424_init(ctx, pnd, transceive);
  if (!ntag424_ISOSelectFile_application(ctx)) {
    fprintf(stderr,
      "Failed to select application: %s\n", ntag424_strerror(ctx));
    goto close;
  }
  if (query_key_version || key_version >= 0) {
    int version = ntag424_GetKeyVersion(ctx, key_number);
    if (version < 0) {
      fprintf(stderr,
        "Could not get key version: %s\n", ntag424_strerror(ctx));
      goto close;
    }
    if (query_key_version) {
      fprintf(stderr, "Obtained key version.\n");
      fprintf(stdout, "%i\n", version);
      exitcode = 0;
      goto close;
    }
    if (key_version >= 0 && version != key_version) {
      fprintf(stderr,
        "Card has key version %i but expected version %i\n",
        version, key_version);
      goto close;
    }
  }
  fprintf(stderr, "Authenticating...\n");
  if (!ntag424_AuthenticateLRP(ctx, key_number, key)) {
    fprintf(stderr, "Authentication failed: %s\n", ntag424_strerror(ctx));
    goto close;
  }
  fprintf(stderr, "Authentication successful.\n");
  if (change_key_number >= 0) {
    if (change_key_number == 0) {
      if (!ntag424_ChangeKey_master(ctx, new_key, new_key_version)) {
        fprintf(stderr,
          "Failed to change master key: %s\n", ntag424_strerror(ctx));
        goto close;
      }
      fprintf(stderr, "Successfully changed master key.\n");
    } else {
      if (!ntag424_ChangeKey(
        ctx, change_key_number, old_key, new_key, new_key_version
      )) {
        char *errmsg = (
          (ctx->picc_status.sw1 = 0x91 && ctx->picc_status.sw2 == 0x1E) ?
          "old key not matching" : ntag424_strerror(ctx)
        );
        fprintf(stderr,
          "Failed to change key %i: %s\n", change_key_number, errmsg);
        goto close;
      }
      fprintf(stderr, "Successfully changed key %i.\n", change_key_number);
    }
  }
  exitcode = 0;
close:
  if (pnd) nfc_close(pnd);
  if (context) nfc_exit(context);
  return exitcode;
}
