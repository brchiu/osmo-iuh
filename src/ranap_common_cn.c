/* RANAP interface for a core-network node */

/* (C) 2015 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>

#include <osmocom/ranap/ranap_common.h>
#include <osmocom/ranap/ranap_common_cn.h>

#include <osmocom/iuh/hnbgw.h>

/* receive a connection-oriented RANAP message and call
 * cn_ranap_handle_co() with the resulting ranap_message struct */
int ranap_cn_rx_co(ranap_handle_cb cb, void *ctx, uint8_t *data, size_t len)
{
	RANAP_RANAP_PDU_t *pdu = NULL;
	asn_dec_rval_t dec_ret;
	int rc;

	dec_ret = aper_decode(NULL, &asn_DEF_RANAP_RANAP_PDU, (void **) &pdu,
			      data, len, 0, 0);
	if (dec_ret.code != RC_OK) {
		LOGP(DRANAP, LOGL_ERROR, "Error in RANAP ASN.1 decode\n");
		return -1;
	}

	rc = (*cb)(ctx, pdu);

	if (rc) {
		LOGP(DRANAP, LOGL_ERROR, "Not calling cn_ranap_handle_co() due to rc=%d\n", rc);
	}

	/* Free the asn1 structs in message */
	ASN_STRUCT_FREE(asn_DEF_RANAP_RANAP_PDU, pdu);

	return rc;
}

/* receive a connection-less RANAP message and call
 * cn_ranap_handle_co() with the resulting ranap_message struct */
int ranap_cn_rx_cl(ranap_handle_cb cb, void *ctx, uint8_t *data, size_t len)
{
	RANAP_RANAP_PDU_t *pdu = NULL;
	asn_dec_rval_t dec_ret;
	int rc;

	dec_ret = aper_decode(NULL, &asn_DEF_RANAP_RANAP_PDU, (void **) &pdu,
			      data, len, 0, 0);
	if (dec_ret.code != RC_OK) {
		LOGP(DRANAP, LOGL_ERROR, "Error in RANAP ASN.1 decode\n");
		return -1;
	}

	rc = (*cb)(ctx, pdu);

	if (rc) {
		LOGP(DRANAP, LOGL_ERROR, "Not calling cn_ranap_handle_cl() due to rc=%d\n", rc);
	}

	/* Free the asn1 structs in message */
	ASN_STRUCT_FREE(asn_DEF_RANAP_RANAP_PDU, pdu);

	return rc;
}
