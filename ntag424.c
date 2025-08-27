#include "ntag424.h"

#include <string.h>
#include <stdio.h>
#include <sys/random.h>

typedef struct {
  int code;
  const char *message;
} ntag424_errstr_t;

static ntag424_errstr_t ntag424_errstr[] = {
  { 0, "success" },
  { NTAG424_ERR_NOT_IMPL, "not implemented" },
  { NTAG424_ERR_INV_ARG, "invalid argument" },
  { NTAG424_ERR_TRX_ERROR, "I/O error during transceiving" },
  { NTAG424_ERR_NO_STATUS, "status not received" },
  { NTAG424_ERR_INV_RESP, "invalid response received" },
  { NTAG424_ERR_RANDOM, "random number generation failed" },
  { NTAG424_ERR_LRP_DISABLED, "LRP encryption is not enabled" },
  { NTAG424_ERR_NO_SUCH_KEY, "key does not exist" },
  { NTAG424_ERR_PERMISSION_DENIED, "permission denied" },
  { NTAG424_ERR_AUTH_DELAY, "authentication delay active" },
  { NTAG424_ERR_AUTH_ERROR, "authentication error" },
  { NTAG424_ERR_INTEGRITY, "integrity error" },
  { 0, NULL }
};

char *ntag424_strerror(
  ntag424_ctx_t *ctx
) {
  if (ctx->error == NTAG424_ERR_BAD_STATUS) {
    // Use RX buffer for dynamic error message:
    char *const buf = (char *)ctx->rxbuf;
    const size_t buflen = sizeof(ctx->rxbuf);
    snprintf(
      buf, buflen,
      "status code %02hhX%02hhXh received",
      ctx->picc_status.sw1, ctx->picc_status.sw2
    );
    return buf;
  } else {
    const char *errmsg;
    for (int i=0; ; i++) {
      errmsg = ntag424_errstr[i].message;
      if (ntag424_errstr[i].code == ctx->error) break;
    }
    if (!errmsg) errmsg = "unknown error";
    return (char *)errmsg;
  }
}

static uint32_t ntag424_crc(const uint8_t *data, size_t length) {
  uint32_t crc = 0xFFFFFFFF;
  while (length--) {
    crc ^= *data++;
    for (int i=0; i<8; i++) {
      if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320;
      else crc >>= 1;
    }
  }
  return crc; // NTAG424 does not do final negation
}

const uint8_t ntag424_default_capabilities[32] = {
  0x00, 0x17, // length (23 bytes) in big endian
  0x20, // version 2.0
  0x01, 0x00, // maximum response length (256 bytes) in big endian
  0x00, 0xFF, // maximum command data length (255 bytes) in big endian
  0x04, // NDEF file
  0x06, // length of following data
  0xE1, 0x04, // NDEF file identifier
  0x01, 0x00, // file size (256 bytes)
  0x00, // public read access
  0x00, // public write access
  0x05, // proprietary file
  0x06, // length of the following data
  0xE1, 0x05, // proprietary file identifier
  0x00, 0x80, // file size (128 bytes)
  0x82, // read access with proprietary methods using key number 2
  0x83, // write access with proprietary methods using key number 3
  // rest is zero
};
const uint8_t ntag424_default_file1_settings[3] = { 0x00, 0x00, 0xE0 };
const uint8_t ntag424_default_file2_settings[3] = { 0x00, 0xE0, 0xEE };
const uint8_t ntag424_default_file3_settings[3] = { 0x03, 0x30, 0x23 };

const uint8_t ntag424_default_config_failctr[5] = {
  0x01, 0xE8, 0x03, 0x0A, 0x00
};

const uint8_t ntag424_default_config_hardware[1] = { 0x01 };

static void ntag424_lrp_key(
  lrp_ctx_t *ctx, uint8_t *key, uint8_t *rnd_a, uint8_t *rnd_b
) {
  lrp_key(ctx, key, false);
  uint8_t msg[32] = {
    0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x96, 0x69
  };
  uint8_t mac[LRP_MAC_LEN];
  msg[4] = rnd_a[0];
  msg[5] = rnd_a[1];
  for (int i=0; i<6; i++) msg[6+i] = rnd_a[2+i] ^ rnd_b[0+i];
  memcpy(msg+12, rnd_b+6, 10);
  memcpy(msg+22, rnd_a+8, 8);
  lrp_mac(ctx, mac, msg, 32);
  lrp_key(ctx, mac, true);
}

static bool ntag424_set_error(ntag424_ctx_t *ctx, int code) {
  ctx->error = code;
  ctx->trx_error = 0;
  if (code != NTAG424_ERR_BAD_STATUS) {
    ctx->picc_status.sw1 = 0;
    ctx->picc_status.sw2 = 0;
  }
  if (code == 0) return true;
  ctx->datalen = 0;
  return false;
}

static bool ntag424_transceive(
  ntag424_ctx_t *ctx, uint8_t *txbuf, size_t txlen
) {
  int status = ctx->transceive(
    ctx->device, txbuf, txlen, ctx->rxbuf, sizeof(ctx->rxbuf)
  );
  if (status < 0) {
    ctx->error = NTAG424_ERR_TRX_ERROR;
    ctx->trx_error = status;
    ctx->picc_status.sw1 = 0;
    ctx->picc_status.sw2 = 0;
    ctx->datalen = 0;
    return false;
  } else if (status < 2) {
    ntag424_set_error(ctx, NTAG424_ERR_NO_STATUS);
    ctx->datalen = 0;
    return false;
  } else {
    ctx->error = 0;
    ctx->trx_error = 0;
    ctx->picc_status.sw1 = ctx->rxbuf[status-2];
    ctx->picc_status.sw2 = ctx->rxbuf[status-1];
    ctx->datalen = status - 2;
    return true;
  }
}

static bool ntag424_command(
  ntag424_ctx_t *ctx,
  int mode,
  uint8_t cmd,
  const uint8_t *header,
  size_t headerlen,
  const uint8_t *data,
  size_t datalen
) {
  if (!ctx->authenticated) mode = NTAG424_MODE_PLAIN;
  size_t maclen = (mode >= NTAG424_MODE_MAC) ? 8 : 0;
  size_t datalen_padded = (
    (mode >= NTAG424_MODE_FULL && datalen) ?
    (((datalen / 16) + 1) * 16) :
    datalen
  );
  size_t total_len = headerlen + datalen_padded + maclen;
  if (total_len > 0xFF) {
    return ntag424_set_error(ctx, NTAG424_ERR_INV_ARG);
  }
  size_t initlen = total_len ? 5 : 4;
  size_t txlen = initlen + headerlen + datalen_padded + maclen + 1;
  uint8_t txbuf[txlen];
  txbuf[0] = 0x90;
  txbuf[1] = cmd;
  txbuf[2] = 0;
  txbuf[3] = 0;
  if (total_len) txbuf[4] = (uint8_t)(total_len);
  memcpy(txbuf+initlen, header, headerlen);
  if (datalen) {
    memcpy(txbuf+initlen+headerlen, data, datalen);
    if (mode >= NTAG424_MODE_FULL) {
      lrp_enc(ctx->lrp_ctx, txbuf+initlen+headerlen, datalen, true, false);
    }
  }
  if (maclen) {
    uint8_t msg[7+headerlen+datalen_padded], mac[16];
    msg[0] = cmd;
    msg[1] = ctx->cmd_ctr & 0xFF;
    msg[2] = ctx->cmd_ctr >> 8;
    memcpy(msg+3, ctx->ti, 4);
    memcpy(msg+7, header, headerlen);
    memcpy(msg+7+headerlen, txbuf+5+headerlen, datalen_padded);
    lrp_mac(ctx->lrp_ctx, mac, msg, 7+headerlen+datalen_padded);
    for (int i=0; i<8; i++) {
      txbuf[initlen+headerlen+datalen_padded+i] = mac[2*i+1];
    }
  }
  txbuf[txlen-1] = 0;
  ctx->cmd_ctr++;
  if (!ntag424_transceive(ctx, txbuf, txlen)) return false;
  if (ctx->picc_status.sw1 != 0x91 || ctx->picc_status.sw2 != 0x00) {
    return ntag424_set_error(ctx, NTAG424_ERR_BAD_STATUS);
  }
  if (mode >= NTAG424_MODE_MAC && ctx->datalen) {
    if (ctx->datalen < 8) {
      return ntag424_set_error(ctx, NTAG424_ERR_INV_RESP);
    }
    ctx->datalen -= 8;
    {
      uint8_t msg[7+ctx->datalen], mac[16];
      msg[0] = ctx->picc_status.sw2;
      msg[1] = ctx->cmd_ctr & 0xFF;
      msg[2] = ctx->cmd_ctr >> 8;
      memcpy(msg+3, ctx->ti, 4);
      memcpy(msg+7, ctx->rxbuf, ctx->datalen);
      lrp_mac(ctx->lrp_ctx, mac, msg, sizeof(msg));
      for (int i=0; i<8; i++) if (ctx->rxbuf[ctx->datalen+i] != mac[2*i+1]) {
        return ntag424_set_error(ctx, NTAG424_ERR_INTEGRITY);
      }
    }
  }
  if (mode >= NTAG424_MODE_FULL && ctx->datalen) {
    ctx->datalen = lrp_enc(ctx->lrp_ctx, ctx->rxbuf, ctx->datalen, true, true);
    if (ctx->datalen == LRP_INVALID) {
      return ntag424_set_error(ctx, NTAG424_ERR_INTEGRITY);
    }
  }
  return ntag424_set_error(ctx, 0);
}

bool ntag424_init(
  ntag424_ctx_t *ctx,
  void *device,
  transceive_fptr transceive
) {
  ctx->device = device;
  ctx->transceive = transceive;
  ctx->application_selected = false;
  ctx->authenticated = false;
  return ntag424_set_error(ctx, 0);
}

bool ntag424_ISOSelectFile_master(
  ntag424_ctx_t *ctx
) {
  uint8_t tx[4] = {
    0x00, // class byte for standard ISO command
    0xA4, // instruction byte for ISOSelectFile
    0x00, // parameter 1: select MF/DF/EF by file identifier
    0x0C, // parameter 2: no response data
  };
  if (!ntag424_transceive(ctx, tx, sizeof(tx))) return false;
  if (ctx->picc_status.sw1 != 0x90 || ctx->picc_status.sw2 != 0x00) {
    ctx->error = NTAG424_ERR_BAD_STATUS;
    return false;
  }
  ctx->application_selected = false;
  return true;
}

bool ntag424_ISOSelectFile_application(
  ntag424_ctx_t *ctx
) {
  uint8_t tx[12] = {
    0x00, // class byte for standard ISO command
    0xA4, // instruction byte for ISOSelectFile
    0x04, // parameter 1: select by DF name
    0x0C, // parameter 2: no response data
    7, // length of following data (without final byte for response length)
    0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01 // 7 bytes DF name
  };
  if (!ntag424_transceive(ctx, tx, sizeof(tx))) return false;
  if (ctx->picc_status.sw1 != 0x90 || ctx->picc_status.sw2 != 0x00) {
    ctx->error = NTAG424_ERR_BAD_STATUS;
    return false;
  }
  ctx->application_selected = true;
  return true;
}

bool ntag424_GetVersion(
  ntag424_ctx_t *ctx,
  ntag424_mfg_t *mfg
) {
  if (ctx->authenticated) {
    return ntag424_set_error(ctx, NTAG424_ERR_NOT_IMPL);
  }
  uint8_t tx[5] = {
    0x90, // class byte
    0x60, // instruction byte for GetVersion
    0x00, 0x00, // unused parameters set to zero
    0x00 // accept any response length
  };
  if (!ntag424_transceive(ctx, tx, sizeof(tx))) return false;
  if (ctx->picc_status.sw1 != 0x91 || ctx->picc_status.sw2 != 0xAF) {
    return ntag424_set_error(ctx, NTAG424_ERR_BAD_STATUS);
  }
  if (ctx->datalen != 7) {
    return ntag424_set_error(ctx, NTAG424_ERR_INV_RESP);
  }
  memcpy(&mfg->hw, ctx->rxbuf, 7);
  tx[1] = 0xAF; // set instruction byte to second/third part
  if (!ntag424_transceive(ctx, tx, sizeof(tx))) return false;
  if (ctx->picc_status.sw1 != 0x91 || ctx->picc_status.sw2 != 0xAF) {
    return ntag424_set_error(ctx, NTAG424_ERR_BAD_STATUS);
  }
  if (ctx->datalen != 7) {
    return ntag424_set_error(ctx, NTAG424_ERR_INV_RESP);
  }
  memcpy(&mfg->sw, ctx->rxbuf, 7);
  if (!ntag424_transceive(ctx, tx, sizeof(tx))) return false;
  if (ctx->picc_status.sw1 != 0x91 || ctx->picc_status.sw2 != 0x00) {
    return ntag424_set_error(ctx, NTAG424_ERR_BAD_STATUS);
  }
  if (ctx->datalen < 14 || ctx->datalen > 15) {
    return ntag424_set_error(ctx, NTAG424_ERR_INV_RESP);
  }
  memcpy(mfg->uid, ctx->rxbuf, 7);
  mfg->batch_length = ctx->datalen-7;
  memcpy(mfg->batch, ctx->rxbuf+7, mfg->batch_length);
  return ntag424_set_error(ctx, 0);
}

int ntag424_GetKeyVersion(
  ntag424_ctx_t *ctx,
  int key_number
) {
  if (key_number < 0x00 || key_number > 0xFF) {
    ntag424_set_error(ctx, NTAG424_ERR_INV_ARG);
    return -1;
  }
  uint8_t header[1] = { (uint8_t)key_number };
  if (!ntag424_command(
    ctx, NTAG424_MODE_MAC, 0x64, header, sizeof(header), NULL, 0
  )) {
    return -1;
  }
  if (ctx->datalen != 1) {
    ntag424_set_error(ctx, NTAG424_ERR_INV_RESP);
    return -1;
  }
  return (uint8_t)ctx->rxbuf[0];
}

bool ntag424_AuthenticateLRP(
  ntag424_ctx_t *ctx,
  int key_number,
  uint8_t *key
) {
  if (key_number < 0x00 || key_number > 0x1F)
    return ntag424_set_error(ctx, NTAG424_ERR_INV_ARG);
  uint8_t rnd_a[16], rnd_b[16];
  if (getrandom(rnd_a, 16, 0) != 16) {
    return ntag424_set_error(ctx, NTAG424_ERR_RANDOM);
  }
  {
    uint8_t tx[9] = {
      0x90, // class byte
      0x71, // instruction byte for AuthenticationLRPFirst
      0x00, 0x00, // unused parameters set to zero
      3, // length of following data (without final byte for response length)
      0x00, // key number filled in below
      1, // length of following PCDcap2 array
      0x02, // bit 1 of PCDcap2.1 set to one for LRP secure messaging
      0x00 // accept any response length
    };
    tx[5] = (uint8_t)key_number;
    if (!ntag424_transceive(ctx, tx, sizeof(tx))) return false;
  }
  if (ctx->picc_status.sw1 == 0x91 && ctx->picc_status.sw2 == 0x40) {
    return ntag424_set_error(ctx, NTAG424_ERR_NO_SUCH_KEY);
  }
  if (ctx->picc_status.sw1 == 0x91 && ctx->picc_status.sw2 == 0x9D) {
    return ntag424_set_error(ctx, NTAG424_ERR_PERMISSION_DENIED);
  }
  if (ctx->picc_status.sw1 == 0x91 && ctx->picc_status.sw2 == 0xAD) {
    return ntag424_set_error(ctx, NTAG424_ERR_AUTH_DELAY);
  }
  if (ctx->picc_status.sw1 != 0x91 || ctx->picc_status.sw2 != 0xAF) {
    return ntag424_set_error(ctx, NTAG424_ERR_BAD_STATUS);
  }
  if (ctx->datalen == 16) {
    return ntag424_set_error(ctx, NTAG424_ERR_LRP_DISABLED);
  }
  if (ctx->datalen != 17 || ctx->rxbuf[0] != 0x01) {
    return ntag424_set_error(ctx, NTAG424_ERR_INV_RESP);
  }
  memcpy(rnd_b, ctx->rxbuf+1, 16);
  ntag424_lrp_key(ctx->lrp_ctx, key, rnd_a, rnd_b);
  {
    uint8_t msg[32], mac[16];
    memcpy(msg, rnd_a, 16);
    memcpy(msg+16, rnd_b, 16);
    lrp_mac(ctx->lrp_ctx, mac, msg, 32);
    uint8_t tx[38] = {
      0x90, // class byte
      0xAF, // instruction byte for second part
      0x00, 0x00, // unused parametes set to zero
      32, // length of following data (without final byte for response length)
      // further data filled in below
    };
    memcpy(tx+5, rnd_a, 16);
    memcpy(tx+21, mac, 16);
    if (!ntag424_transceive(ctx, tx, sizeof(tx))) return false;
  }
  ctx->authenticated = false;
  if (ctx->picc_status.sw1 == 0x91 && ctx->picc_status.sw2 == 0xAE) {
    return ntag424_set_error(ctx, NTAG424_ERR_AUTH_ERROR);
  }
  if (ctx->picc_status.sw1 != 0x91 || ctx->picc_status.sw2 != 0x00) {
    return ntag424_set_error(ctx, NTAG424_ERR_BAD_STATUS);
  }
  if (ctx->application_selected) ctx->authenticated = true;
  if (ctx->datalen != 32) {
    return ntag424_set_error(ctx, NTAG424_ERR_INV_RESP);
  }
  {
    uint8_t pcdcap2[6] = { 0x02, }; // transmitted PCDcap2 with implicit zeros
    uint8_t msg[48], mac[16];
    memcpy(msg, rnd_b, 16);
    memcpy(msg+16, rnd_a, 16);
    memcpy(msg+32, ctx->rxbuf, 16);
    lrp_mac(ctx->lrp_ctx, mac, msg, 48);
    if (memcmp(ctx->rxbuf+16, mac, 16)) {
      return ntag424_set_error(ctx, NTAG424_ERR_AUTH_ERROR);
    }
    lrp_enc(ctx->lrp_ctx, ctx->rxbuf, 16, false, true);
    memcpy(ctx->ti, ctx->rxbuf, 4);
    ctx->cmd_ctr = 0;
    if (memcmp(ctx->rxbuf+10, pcdcap2, 6)) {
      return ntag424_set_error(ctx, NTAG424_ERR_AUTH_ERROR);
    }
  }
  return ntag424_set_error(ctx, 0);
}

bool ntag424_ChangeKey_master(
  ntag424_ctx_t *ctx,
  const uint8_t *new_key,
  int new_key_version
) {
  if (new_key_version < 0x00 || new_key_version > 0xFF) {
    return ntag424_set_error(ctx, NTAG424_ERR_INV_ARG);
  }
  uint8_t header[1] = { 0x00 };
  uint8_t data[17];
  memcpy(data, new_key, 16);
  data[16] = (uint8_t)new_key_version;
  return ntag424_command(ctx, NTAG424_MODE_FULL, 0xC4, header, 1, data, 17);
}

bool ntag424_ChangeKey(
  ntag424_ctx_t *ctx,
  int key_number,
  const uint8_t *old_key,
  const uint8_t *new_key,
  int new_key_version
) {
  if (key_number == 0x00) {
    return ntag424_ChangeKey_master(ctx, new_key, new_key_version);
  }
  if (
    key_number < 0x00 || key_number > 0x1F ||
    new_key_version < 0x00 || new_key_version > 0xFF
  ) {
    return ntag424_set_error(ctx, NTAG424_ERR_INV_ARG);
  }
  uint8_t header[1] = { (uint8_t)key_number };
  uint8_t data[21];
  for (int i=0; i<16; i++) data[i] = old_key[i] ^ new_key[i];
  data[16] = (uint8_t)new_key_version;
  uint32_t crc = ntag424_crc(new_key, 16);
  for (int i=0; i<4; i++) {
    data[17+i] = crc & 0xFF;
    crc >>= 8;
  }
  return ntag424_command(ctx, NTAG424_MODE_FULL, 0xC4, header, 1, data, 21);
}

uint8_t *ntag424_GetCardUID(
  ntag424_ctx_t *ctx
) {
  if (!ntag424_command(ctx, NTAG424_MODE_FULL, 0x51, NULL, 0, NULL, 0)) {
    return NULL;
  }
  if (ctx->datalen != 7) {
    ntag424_set_error(ctx, NTAG424_ERR_INV_RESP);
    return NULL;
  }
  ntag424_set_error(ctx, 0);
  return ctx->rxbuf;
}

bool ntag424_GetFileSettings(
  ntag424_ctx_t *ctx,
  int file_number
) {
  uint8_t header[1];
  if (file_number < 0x00 || file_number > 0x1F) {
    return ntag424_set_error(ctx, NTAG424_ERR_INV_ARG);
  }
  header[0] = (uint8_t)file_number;
  if (!ntag424_command(
    ctx, NTAG424_MODE_MAC, 0xF5, header, sizeof(header), NULL, 0
  )) {
    return false;
  }
  if (ctx->datalen < 7) {
    return ntag424_set_error(ctx, NTAG424_ERR_INV_RESP);
  }
  return ntag424_set_error(ctx, 0);
}

bool ntag424_ChangeFileSettings(
  ntag424_ctx_t *ctx,
  int file_number,
  const uint8_t *settings,
  size_t settings_length
) {
  if (file_number < 0x00 || file_number > 0x1F) {
    return ntag424_set_error(ctx, NTAG424_ERR_INV_ARG);
  }
  uint8_t header[1];
  header[0] = (uint8_t)file_number;
  return ntag424_command(
    ctx, NTAG424_MODE_FULL, 0x5F,
    header, sizeof(header), settings, settings_length
  );
}

void ntag424_file_settings(
  uint8_t *settings, // minimum NTAG424_FILE_SETTING_LEN bytes
  int mode,
  uint8_t read_key,
  uint8_t write_key,
  uint8_t read_write_key,
  uint8_t change_key
) {
  settings[0] = (uint8_t)mode & 0x03;
  settings[1] = (read_write_key << 4) | (change_key & 0x0F);
  settings[2] = (read_key << 4) | (write_key & 0x0F);
}

void ntag424_init_capabilities(
  uint8_t *capabilities
) {
  memcpy(
    capabilities, ntag424_default_capabilities,
    sizeof(ntag424_default_capabilities)
  );
}

void ntag424_edit_capabilities(
  uint8_t *capabilities,
  int file_number,
  uint8_t read_key,
  uint8_t write_key,
  uint8_t read_write_key,
  uint8_t change_key
) {
  size_t offset;
  if (file_number == 2) offset = 13;
  else if (file_number == 3) offset = 21;
  else return;
  if (
    read_key == NTAG424_FILE_ACCESS_FREE ||
    read_write_key == NTAG424_FILE_ACCESS_FREE
  ) {
    capabilities[offset+0] = 0x00;
  } else if (
    read_key == NTAG424_FILE_ACCESS_DENY &&
    read_write_key == NTAG424_FILE_ACCESS_DENY
  ) {
    capabilities[offset+0] = 0xFF;
  } else if (read_key == NTAG424_FILE_ACCESS_DENY) {
    capabilities[offset+0] = 0x80 | read_write_key;
  } else {
    capabilities[offset+0] = 0x80 | read_key;
  }
  if (
    ( read_key == NTAG424_FILE_ACCESS_FREE &&
      write_key == NTAG424_FILE_ACCESS_FREE ) ||
    read_write_key == NTAG424_FILE_ACCESS_FREE
  ) {
    capabilities[offset+1] = 0x00;
  } else if (read_write_key != NTAG424_FILE_ACCESS_DENY) {
    capabilities[offset+1] = 0x80 | read_write_key;
  } else if (
    read_key == NTAG424_FILE_ACCESS_FREE &&
    write_key != NTAG424_FILE_ACCESS_DENY
  ) {
    capabilities[offset+1] = 0x80 | write_key;
  } else if (
    read_key != NTAG424_FILE_ACCESS_DENY &&
    ( write_key == NTAG424_FILE_ACCESS_FREE || write_key == read_key )
  ) {
    capabilities[offset+1] = 0x80 | read_key;
  } else {
    capabilities[offset+1] = 0xFF;
  }
}

bool ntag424_ISOReadBinary(
  ntag424_ctx_t *ctx,
  int file_number,
  size_t offset,
  size_t length
) {
  if (
    file_number < 0x00 || file_number > 0x1C ||
    offset > 0xFF || length > NTAG424_READLEN_MAX
  ) {
    ntag424_set_error(ctx, NTAG424_ERR_INV_ARG);
    return NULL;
  }
  if (length == 0) {
    ctx->datalen = 0;
    return true;
  }
  uint8_t tx[5] = {
    0x00, // class byte for standard ISO command
    0xB0, // instruction byte for ISOReadBinary
    // further data filled in below
  };
  tx[2] = 0x80 | (uint8_t)(file_number+2);
  tx[3] = (uint8_t)offset;
  if (length <= 0xFF) tx[4] = (uint8_t)length;
  if (!ntag424_transceive(ctx, tx, sizeof(tx))) return false;
  if (ctx->picc_status.sw1 != 0x90 || ctx->picc_status.sw2 != 0x00) {
    return ntag424_set_error(ctx, NTAG424_ERR_BAD_STATUS);
  }
  return ntag424_set_error(ctx, 0);
}

uint8_t *ntag424_ReadData(
  ntag424_ctx_t *ctx,
  int mode,
  int file_number,
  size_t offset,
  size_t length
) {
  if (
    file_number < 0x00 || file_number > 0x1F ||
    offset > 0xFFFFFF || length > NTAG424_READLEN_MAX
  ) {
    ntag424_set_error(ctx, NTAG424_ERR_INV_ARG);
    return NULL;
  }
  if (length == 0) {
    ctx->datalen = 0;
    return ctx->rxbuf;
  }
  uint8_t header[7] = {
    (uint8_t)file_number,
    (uint8_t)offset, (uint8_t)(offset >> 8), (uint8_t)(offset >> 16),
    (uint8_t)length, (uint8_t)(length >> 8), (uint8_t)(length >> 16),
  };
  if (!ntag424_command(ctx, mode, 0xAD, header, sizeof(header), NULL, 0)) {
    return NULL;
  }
  if (ctx->datalen != length) {
    ntag424_set_error(ctx, NTAG424_ERR_INV_RESP);
    return NULL;
  }
  ntag424_set_error(ctx, 0);
  return ctx->rxbuf;
}

bool ntag424_WriteData(
  ntag424_ctx_t *ctx,
  int mode,
  int file_number,
  size_t offset,
  const uint8_t *data,
  size_t length
) {
  if (
    file_number < 0x00 || file_number > 0x1F ||
    offset > 0xFFFFFF || length > 0xFFFFFF
  ) {
    return ntag424_set_error(ctx, NTAG424_ERR_INV_ARG);
  }
  uint8_t header[7] = {
    (uint8_t)file_number,
    (uint8_t)offset, (uint8_t)(offset >> 8), (uint8_t)(offset >> 16),
    (uint8_t)length, (uint8_t)(length >> 8), (uint8_t)(length >> 16),
  };
  if (!ntag424_command(
    ctx, mode, 0x8D, header, sizeof(header), data, length
  )) {
    return false;
  }
  return ntag424_set_error(ctx, 0);
}

int32_t ntag424_GetFileCounters_SDMReadCtr(
  ntag424_ctx_t *ctx,
  int file_number
) {
  if (file_number < 0x00 || file_number > 0x1F) {
    ntag424_set_error(ctx, NTAG424_ERR_INV_ARG);
    return -1;
  }
  uint8_t header[1] = { (uint8_t)file_number };
  if (!ntag424_command(
    ctx, NTAG424_MODE_FULL, 0xF6, header, sizeof(header), NULL, 0
  )) {
    return -1;
  }
  if (ctx->datalen < 3) {
    return ntag424_set_error(ctx, NTAG424_ERR_INV_RESP);
  }
  return (
    (int32_t)ctx->rxbuf[0] +
    ((int32_t)ctx->rxbuf[1] << 8) +
    ((int32_t)ctx->rxbuf[2] << 16)
  );
}

bool ntag424_SetConfiguration(
  ntag424_ctx_t *ctx,
  int option,
  const uint8_t *data,
  size_t length
) {
  if (option < 0x00 || option > 0xFF) {
    return ntag424_set_error(ctx, NTAG424_ERR_INV_ARG);
  }
  uint8_t header[1] = { (uint8_t)option };
  return ntag424_command(
    ctx, NTAG424_MODE_FULL, 0x5C, header, sizeof(header), data, length
  );
}

bool ntag424_reset_settings(
  ntag424_ctx_t *ctx
) {
  if (!ntag424_SetConfiguration(
    ctx, 0x0A,
    ntag424_default_config_failctr, sizeof(ntag424_default_config_failctr)
  )) return false;
  if (!ntag424_SetConfiguration(
    ctx, 0x0B,
    ntag424_default_config_hardware, sizeof(ntag424_default_config_hardware)
  )) return false;
  if (!ntag424_ChangeFileSettings(
    ctx, 1,
    ntag424_default_file1_settings, sizeof(ntag424_default_file1_settings)
  )) return false;
  if (!ntag424_ChangeFileSettings(
    ctx, 2,
    ntag424_default_file2_settings, sizeof(ntag424_default_file2_settings)
  )) return false;
  if (!ntag424_ChangeFileSettings(
    ctx, 3,
    ntag424_default_file3_settings, sizeof(ntag424_default_file3_settings)
  )) return false;
  if (!ntag424_WriteData(
    ctx, NTAG424_MODE_PLAIN, 1, 0,
    ntag424_default_capabilities, sizeof(ntag424_default_capabilities)
  )) return false;
  return ntag424_set_error(ctx, 0);
}
