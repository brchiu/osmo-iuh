#pragma once

#include <stdint.h>

#include <osmocom/ranap/ranap_common.h>
//#include <osmocom/ranap/ranap_ies_defs.h>

typedef int (*ranap_handle_cb)(void *ctx, RANAP_RANAP_PDU_t *pdu);

/* receive a connection-less RANAP message */
int ranap_cn_rx_cl(ranap_handle_cb cb, void *ctx, uint8_t *data, size_t len);

/* receive a connection-oriented RANAP message */
int ranap_cn_rx_co(ranap_handle_cb cb, void *ctx, uint8_t *data, size_t len);
