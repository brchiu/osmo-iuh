/* hnb-gw specific code for RUA (Ranap User Adaption) */

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


#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include <osmocom/netif/stream.h>

#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sccp_helpers.h>

#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "asn1helpers.h"

#include <osmocom/iuh/hnbgw.h>
#include <osmocom/iuh/hnbgw_ranap.h>
#include <osmocom/rua/rua_common.h>
//#include <osmocom/rua/rua_ies_defs.h>
#include <osmocom/iuh/context_map.h>
#include <osmocom/hnbap/CN-DomainIndicator.h>

static const char *cn_domain_indicator_to_str(CN_DomainIndicator_t cN_DomainIndicator)
{
	switch (cN_DomainIndicator) {
	case RUA_CN_DomainIndicator_cs_domain:
		return "IuCS";
	case RUA_CN_DomainIndicator_ps_domain:
		return "IuPS";
	default:
		return "(unknown-domain)";
	}
}

static int hnbgw_rua_tx(struct hnb_context *ctx, struct msgb *msg)
{
	if (!msg)
		return -EINVAL;

	msgb_sctp_ppid(msg) = IUH_PPI_RUA;
	osmo_stream_srv_send(ctx->conn, msg);

	return 0;
}

int rua_tx_udt(struct hnb_context *hnb, const uint8_t *data, unsigned int len)
{

	RUA_RUA_PDU_t pdu;
	RUA_ConnectionlessTransfer_t *out;
	RUA_ConnectionlessTransferIEs_t *ie;
	struct msgb *msg;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = RUA_RUA_PDU_PR_initiatingMessage;
	pdu.choice.initiatingMessage.procedureCode = RUA_ProcedureCode_id_ConnectionlessTransfer;
	pdu.choice.initiatingMessage.criticality = RUA_Criticality_ignore;
	pdu.choice.initiatingMessage.value.present = RUA_InitiatingMessage__value_PR_ConnectionlessTransfer;
	out = &pdu.choice.initiatingMessage.value.choice.ConnectionlessTransfer;

	ie = (RUA_ConnectionlessTransferIEs_t *)calloc(1, sizeof(RUA_ConnectionlessTransferIEs_t));
	ie->id = RUA_ProtocolIE_ID_id_RANAP_Message;
	ie->criticality = RUA_Criticality_reject;
	ie->value.present = RUA_ConnectionlessTransferIEs__value_PR_RANAP_Message;
	OCTET_STRING_fromBuf(&ie->value.choice.RANAP_Message,  (const char *)data, len);
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	msg = _rua_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RUA_RUA_PDU, &pdu);

	DEBUGP(DRUA, "transmitting RUA payload of %u bytes\n", msgb_length(msg));

	return hnbgw_rua_tx(hnb, msg);
}

int rua_tx_dt(struct hnb_context *hnb, int is_ps, uint32_t context_id,
	      const uint8_t *data, unsigned int len)
{
	RUA_RUA_PDU_t pdu;
	RUA_DirectTransfer_t *out;
	RUA_DirectTransferIEs_t *ie;
	struct msgb *msg;
	uint32_t ctxidbuf;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = RUA_RUA_PDU_PR_initiatingMessage;
	pdu.choice.initiatingMessage.procedureCode = RUA_ProcedureCode_id_DirectTransfer;
	pdu.choice.initiatingMessage.criticality = RUA_Criticality_ignore;
	pdu.choice.initiatingMessage.value.present = RUA_InitiatingMessage__value_PR_DirectTransfer;
	out = &pdu.choice.initiatingMessage.value.choice.DirectTransfer;

	ie = (RUA_DirectTransferIEs_t *)calloc(1, sizeof(RUA_DirectTransferIEs_t));
	ie->id = RUA_ProtocolIE_ID_id_CN_DomainIndicator;
	ie->criticality = RUA_Criticality_reject;
	ie->value.present = RUA_DirectTransferIEs__value_PR_CN_DomainIndicator;
	ie->value.choice.CN_DomainIndicator = is_ps ? RUA_CN_DomainIndicator_ps_domain : RUA_CN_DomainIndicator_cs_domain;
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	ie = (RUA_DirectTransferIEs_t *)calloc(1, sizeof(RUA_DirectTransferIEs_t));
	ie->id = RUA_ProtocolIE_ID_id_Context_ID;
	ie->criticality = RUA_Criticality_reject;
	ie->value.present = RUA_DirectTransferIEs__value_PR_Context_ID;
	asn1_u24_to_bitstring(&ie->value.choice.Context_ID, &ctxidbuf, context_id);
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	ie = (RUA_DirectTransferIEs_t *)calloc(1, sizeof(RUA_DirectTransferIEs_t));
	ie->id = RUA_ProtocolIE_ID_id_RANAP_Message;
	ie->criticality = RUA_Criticality_reject;
	ie->value.present = RUA_DirectTransferIEs__value_PR_RANAP_Message;
	OCTET_STRING_fromBuf(&ie->value.choice.RANAP_Message, (const char *)data, len);
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	msg = _rua_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RUA_RUA_PDU, &pdu);

	DEBUGP(DRUA, "transmitting RUA (cn=%s) payload of %u bytes\n",
		is_ps ? "ps" : "cs", msgb_length(msg));

	return hnbgw_rua_tx(hnb, msg);
}

int rua_tx_disc(struct hnb_context *hnb, int is_ps, uint32_t context_id,
	        const RUA_Cause_t *cause, const uint8_t *data, unsigned int len)
{
	RUA_RUA_PDU_t pdu;
	RUA_Disconnect_t *out;
	RUA_DisconnectIEs_t *ie;
	struct msgb *msg;
	uint32_t ctxidbuf;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = RUA_RUA_PDU_PR_initiatingMessage;
	pdu.choice.initiatingMessage.procedureCode = RUA_ProcedureCode_id_Connect;
	pdu.choice.initiatingMessage.criticality = RUA_Criticality_ignore;
	pdu.choice.initiatingMessage.value.present = RUA_InitiatingMessage__value_PR_Disconnect;
	out = &pdu.choice.initiatingMessage.value.choice.Disconnect;

	ie = (RUA_DisconnectIEs_t *)calloc(sizeof(RUA_DisconnectIEs_t), 1);
	ie->id = RUA_ProtocolIE_ID_id_CN_DomainIndicator;
	ie->criticality = RUA_Criticality_reject;
	ie->value.present = RUA_DisconnectIEs__value_PR_CN_DomainIndicator;
	ie->value.choice.CN_DomainIndicator = is_ps ? RUA_CN_DomainIndicator_ps_domain : RUA_CN_DomainIndicator_cs_domain;
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	ie = (RUA_DisconnectIEs_t *)calloc(sizeof(RUA_DisconnectIEs_t), 1);
	ie->id = RUA_ProtocolIE_ID_id_Context_ID;
	ie->criticality = RUA_Criticality_reject;
	ie->value.present = RUA_DisconnectIEs__value_PR_Context_ID;
	asn1_u24_to_bitstring(&ie->value.choice.Context_ID, &ctxidbuf, context_id);
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	ie = (RUA_DisconnectIEs_t *)calloc(sizeof(RUA_DisconnectIEs_t), 1);
	ie->id = RUA_ProtocolIE_ID_id_Cause;
	ie->criticality = RUA_Criticality_reject;
	ie->value.present = RUA_DisconnectIEs__value_PR_Cause;
	ie->value.choice.Cause.present = RUA_Cause_PR_radioNetwork;
	ie->value.choice.Cause.choice.radioNetwork = RUA_CauseRadioNetwork_normal;
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	if (data && (len > 9)) {
		ie = (RUA_DisconnectIEs_t *)calloc(sizeof(RUA_DisconnectIEs_t), 1);
		ie->id = RUA_ProtocolIE_ID_id_RANAP_Message;
		ie->criticality = RUA_Criticality_reject;
		ie->value.present = RUA_DisconnectIEs__value_PR_RANAP_Message;
		OCTET_STRING_fromBuf(&ie->value.choice.RANAP_Message, (const char *)data, len);
		ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);
	}

	msg = _rua_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RUA_RUA_PDU, &pdu);

	DEBUGP(DRUA, "transmitting RUA (cn=%s) payload of %u bytes\n",
		is_ps ? "ps" : "cs", msgb_length(msg));

	return hnbgw_rua_tx(hnb, msg);
}

/* forward a RUA message to the SCCP User API to SCCP */
static int rua_to_scu(struct hnb_context *hnb,
		      CN_DomainIndicator_t cN_DomainIndicator,
		      enum osmo_scu_prim_type type,
		      uint32_t context_id, uint32_t cause,
		      const uint8_t *data, unsigned int len)
{
	struct msgb *msg;
	struct osmo_scu_prim *prim;
	struct hnbgw_context_map *map = NULL;
	struct hnbgw_cnlink *cn = hnb->gw->sccp.cnlink;
	struct osmo_sccp_addr *remote_addr;
	bool is_ps;
	bool release_context_map = false;
	int rc;

	switch (cN_DomainIndicator) {
	case RUA_CN_DomainIndicator_cs_domain:
		remote_addr = &hnb->gw->sccp.iucs_remote_addr;
		is_ps = false;
		break;
	case RUA_CN_DomainIndicator_ps_domain:
		remote_addr = &hnb->gw->sccp.iups_remote_addr;
		is_ps = true;
		break;
	default:
		LOGP(DRUA, LOGL_ERROR, "Unsupported Domain %ld\n",
		     cN_DomainIndicator);
		return -1;
	}

	if (!cn) {
		DEBUGP(DRUA, "CN=NULL, discarding message\n");
		return 0;
	}

	msg = msgb_alloc(1500, "rua_to_sccp");

	prim = (struct osmo_scu_prim *) msgb_put(msg, sizeof(*prim));
	osmo_prim_init(&prim->oph, SCCP_SAP_USER, type, PRIM_OP_REQUEST, msg);

	switch (type) {
	case OSMO_SCU_PRIM_N_UNITDATA:
		DEBUGP(DRUA, "rua_to_scu() %s to %s, rua_ctx_id %u (unitdata, no scu_conn_id)\n",
		       cn_domain_indicator_to_str(cN_DomainIndicator),
		       osmo_sccp_addr_dump(remote_addr),
		       context_id);
		break;
	default:
		map = context_map_alloc_by_hnb(hnb, context_id, is_ps, cn);
		OSMO_ASSERT(map);
		DEBUGP(DRUA, "rua_to_scu() %s to %s, rua_ctx_id %u scu_conn_id %u\n",
		       cn_domain_indicator_to_str(cN_DomainIndicator),
		       osmo_sccp_addr_dump(remote_addr),
		       map->rua_ctx_id, map->scu_conn_id);
	}

	/* add primitive header */
	switch (type) {
	case OSMO_SCU_PRIM_N_CONNECT:
		prim->u.connect.called_addr = *remote_addr;
		prim->u.connect.calling_addr = cn->gw->sccp.local_addr;
		prim->u.connect.sccp_class = 2;
		prim->u.connect.conn_id = map->scu_conn_id;
		/* Two separate logs because of osmo_sccp_addr_dump(). */
		DEBUGP(DRUA, "RUA to SCCP N_CONNECT: called_addr:%s\n",
		       osmo_sccp_addr_dump(&prim->u.connect.called_addr));
		DEBUGP(DRUA, "RUA to SCCP N_CONNECT: calling_addr:%s\n",
		       osmo_sccp_addr_dump(&prim->u.connect.calling_addr));
		break;
	case OSMO_SCU_PRIM_N_DATA:
		prim->u.data.conn_id = map->scu_conn_id;
		break;
	case OSMO_SCU_PRIM_N_DISCONNECT:
		prim->u.disconnect.conn_id = map->scu_conn_id;
		prim->u.disconnect.cause = cause;
		release_context_map = true;
		break;
	case OSMO_SCU_PRIM_N_UNITDATA:
		prim->u.unitdata.called_addr = *remote_addr;
		prim->u.unitdata.calling_addr = cn->gw->sccp.local_addr;
		/* Two separate logs because of osmo_sccp_addr_dump(). */
		DEBUGP(DRUA, "RUA to SCCP N_UNITDATA: called_addr:%s\n",
		       osmo_sccp_addr_dump(&prim->u.unitdata.called_addr));
		DEBUGP(DRUA, "RUA to SCCP N_UNITDATA: calling_addr:%s\n",
		       osmo_sccp_addr_dump(&prim->u.unitdata.calling_addr));
		break;
	default:
		return -EINVAL;
	}

	/* add optional data section, if needed */
	if (data && len) {
		msg->l2h = msgb_put(msg, len);
		memcpy(msg->l2h, data, len);
	}

	rc = osmo_sccp_user_sap_down(cn->sccp_user, &prim->oph);

	if (map && release_context_map)
		context_map_deactivate(map);

	return rc;
}

static uint32_t rua_to_scu_cause(RUA_Cause_t *in)
{
	/* FIXME: Implement this! */
#if 0
	switch (in->present) {
	case RUA_Cause_PR_NOTHING:
		break;
	case RUA_Cause_PR_radioNetwork:
		switch (in->choice.radioNetwork) {
		case RUA_CauseRadioNetwork_normal:
		case RUA_CauseRadioNetwork_connect_failed:
		case RUA_CauseRadioNetwork_network_release:
		case RUA_CauseRadioNetwork_unspecified:
		}
		break;
	case RUA_Cause_PR_transport:
		switch (in->choice.transport) {
		case RUA_CauseTransport_transport_resource_unavailable:
			break;
		case RUA_CauseTransport_unspecified:
			break;
		}
		break;
	case RUA_Cause_PR_protocol:
		switch (in->choice.protocol) {
		case RUA_CauseProtocol_transfer_syntax_error:
			break;
		case RUA_CauseProtocol_abstract_syntax_error_reject:
			break;
		case RUA_CauseProtocol_abstract_syntax_error_ignore_and_notify:
			break;
		case RUA_CauseProtocol_message_not_compatible_with_receiver_state:
			break;
		case RUA_CauseProtocol_semantic_error:
			break;
		case RUA_CauseProtocol_unspecified:
			break;
		case RUA_CauseProtocol_abstract_syntax_error_falsely_constructed_message:
			break;
		}
		break;
	case RUA_Cause_PR_misc:
		switch (in->choice.misc) {
		case RUA_CauseMisc_processing_overload:
			break;
		case RUA_CauseMisc_hardware_failure:
			break;
		case RUA_CauseMisc_o_and_m_intervention:
			break;
		case RUA_CauseMisc_unspecified:
			break;
		}
		break;
	default:
		break;
	}
#else
	return 0;
#endif

}

static int rua_rx_init_connect(struct msgb *msg, RUA_Connect_t *in)
{
	RUA_ConnectIEs_t *ie, *ie_cause, *ie_ranap_msg;
	struct hnb_context *hnb = msg->dst;
	uint32_t context_id;

	RUA_FIND_PROTOCOLIE_BY_ID(RUA_ConnectIEs_t, ie, in, RUA_ProtocolIE_ID_id_Context_ID, true);

	context_id = asn1bitstr_to_u24(&ie->value.choice.Context_ID);

	RUA_FIND_PROTOCOLIE_BY_ID(RUA_ConnectIEs_t, ie, in, RUA_ProtocolIE_ID_id_CN_DomainIndicator, true);
	RUA_FIND_PROTOCOLIE_BY_ID(RUA_ConnectIEs_t, ie_cause, in, RUA_ProtocolIE_ID_id_Establishment_Cause, true);

	DEBUGP(DRUA, "RUA %s Connect.req(ctx=0x%x, %s)\n",
	       cn_domain_indicator_to_str(ie->value.choice.CN_DomainIndicator),
	       context_id,
	       ie_cause->value.choice.Establishment_Cause == RUA_Establishment_Cause_emergency_call
		? "emergency" : "normal");

	RUA_FIND_PROTOCOLIE_BY_ID(RUA_ConnectIEs_t, ie_ranap_msg, in, RUA_ProtocolIE_ID_id_RANAP_Message, true);

	return rua_to_scu(hnb, ie->value.choice.CN_DomainIndicator, OSMO_SCU_PRIM_N_CONNECT,
			context_id, 0, ie_ranap_msg->value.choice.RANAP_Message.buf,
			ie_ranap_msg->value.choice.RANAP_Message.size);
}

static int rua_rx_init_disconnect(struct msgb *msg, RUA_Disconnect_t *in)
{
	RUA_DisconnectIEs_t *ie, *ie_ranap_msg;
	struct hnb_context *hnb = msg->dst;
	uint32_t context_id;
	uint32_t scu_cause;
	uint8_t *ranap_data = NULL;
	unsigned int ranap_len = 0;

	RUA_FIND_PROTOCOLIE_BY_ID(RUA_DisconnectIEs_t, ie, in, RUA_ProtocolIE_ID_id_Context_ID, true);

	context_id = asn1bitstr_to_u24(&ie->value.choice.Context_ID);

	RUA_FIND_PROTOCOLIE_BY_ID(RUA_DisconnectIEs_t, ie, in, RUA_ProtocolIE_ID_id_Cause, true);

	scu_cause = rua_to_scu_cause(&ie->value.choice.Cause);

	DEBUGP(DRUA, "RUA Disconnect.req(ctx=0x%x,cause=%s)\n", context_id,
		rua_cause_str(&ie->value.choice.Cause));

	RUA_FIND_PROTOCOLIE_BY_ID(RUA_DisconnectIEs_t, ie_ranap_msg, in, RUA_ProtocolIE_ID_id_RANAP_Message, false);
	if (ie_ranap_msg) {
		ranap_data = ie_ranap_msg->value.choice.RANAP_Message.buf;
		ranap_len = ie_ranap_msg->value.choice.RANAP_Message.size;
	}

	RUA_FIND_PROTOCOLIE_BY_ID(RUA_DisconnectIEs_t, ie, in, RUA_ProtocolIE_ID_id_CN_DomainIndicator, true);

	return rua_to_scu(hnb, ie->value.choice.CN_DomainIndicator,
			OSMO_SCU_PRIM_N_DISCONNECT,
			context_id, scu_cause, ranap_data, ranap_len);
}

static int rua_rx_init_dt(struct msgb *msg, RUA_DirectTransfer_t *in)
{
	RUA_DirectTransferIEs_t *ie, *ie_ranap_msg;
	struct hnb_context *hnb = msg->dst;
	uint32_t context_id;

	RUA_FIND_PROTOCOLIE_BY_ID(RUA_DirectTransferIEs_t, ie, in, RUA_ProtocolIE_ID_id_Context_ID, true);

	context_id = asn1bitstr_to_u24(&ie->value.choice.Context_ID);

	DEBUGP(DRUA, "RUA Data.req(ctx=0x%x)\n", context_id);

	RUA_FIND_PROTOCOLIE_BY_ID(RUA_DirectTransferIEs_t, ie, in, RUA_ProtocolIE_ID_id_CN_DomainIndicator, true);
	RUA_FIND_PROTOCOLIE_BY_ID(RUA_DirectTransferIEs_t, ie_ranap_msg, in, RUA_ProtocolIE_ID_id_RANAP_Message, true);

	return rua_to_scu(hnb,
			ie->value.choice.CN_DomainIndicator,
			OSMO_SCU_PRIM_N_DATA,
			context_id, 0, ie_ranap_msg->value.choice.RANAP_Message.buf,
			ie_ranap_msg->value.choice.RANAP_Message.size);
}

static int rua_rx_init_udt(struct msgb *msg, RUA_ConnectionlessTransfer_t *in)
{
	RUA_ConnectionlessTransferIEs_t *ie;

	RUA_FIND_PROTOCOLIE_BY_ID(RUA_ConnectionlessTransferIEs_t, ie, in, RUA_ProtocolIE_ID_id_RANAP_Message, true);

	DEBUGP(DRUA, "RUA UData.req()\n");

	/* according tot the spec, we can primarily receive Overload,
	 * Reset, Reset ACK, Error Indication, reset Resource, Reset
	 * Resurce Acknowledge as connecitonless RANAP.  There are some
	 * more messages regarding Information Transfer, Direct
	 * Information Transfer and Uplink Information Trnansfer that we
	 * can ignore.  In either case, it is RANAP that we need to
	 * decode... */
	return hnbgw_ranap_rx(msg, ie->value.choice.RANAP_Message.buf, ie->value.choice.RANAP_Message.size);
}


static int rua_rx_init_err_ind(struct msgb *msg, RUA_ErrorIndication_t *in)
{
	RUA_ErrorIndicationIEs_t *ie;

	RUA_FIND_PROTOCOLIE_BY_ID(RUA_ErrorIndicationIEs_t, ie, in, RUA_ProtocolIE_ID_id_Cause, true);

	LOGP(DRUA, LOGL_ERROR, "RUA UData.ErrorInd(%s)\n",
		rua_cause_str(&ie->value.choice.Cause));

	return 0;
}

static int rua_rx_initiating_msg(struct msgb *msg, RUA_InitiatingMessage_t *imsg)
{
	int rc;

	switch (imsg->procedureCode) {
	case RUA_ProcedureCode_id_Connect:
		rc = rua_rx_init_connect(msg, &imsg->value.choice.Connect);
		break;
	case RUA_ProcedureCode_id_DirectTransfer:
		rc = rua_rx_init_dt(msg, &imsg->value.choice.DirectTransfer);
		break;
	case RUA_ProcedureCode_id_Disconnect:
		rc = rua_rx_init_disconnect(msg, &imsg->value.choice.Disconnect);
		break;
	case RUA_ProcedureCode_id_ConnectionlessTransfer:
		rc = rua_rx_init_udt(msg, &imsg->value.choice.ConnectionlessTransfer);
		break;
	case RUA_ProcedureCode_id_ErrorIndication:
		rc = rua_rx_init_err_ind(msg, &imsg->value.choice.ErrorIndication);
		break;
	case RUA_ProcedureCode_id_privateMessage:
		LOGP(DRUA, LOGL_NOTICE,
		     "Unhandled: RUA Initiating Msg: Private Msg\n");
		rc = 0;
		break;
	default:
		LOGP(DRUA, LOGL_NOTICE, "Unknown RUA Procedure %lu\n",
		     imsg->procedureCode);
		rc = -1;
	}

	return rc;
}

static int rua_rx_successful_outcome_msg(struct msgb *msg, RUA_SuccessfulOutcome_t *in)
{
	/* FIXME */
	LOGP(DRUA, LOGL_NOTICE, "Unexpected RUA Sucessful Outcome\n");
	return -1;
}

static int rua_rx_unsuccessful_outcome_msg(struct msgb *msg, RUA_UnsuccessfulOutcome_t *in)
{
	/* FIXME */
	LOGP(DRUA, LOGL_NOTICE, "Unexpected RUA Unsucessful Outcome\n");
	return -1;
}


static int _hnbgw_rua_rx(struct msgb *msg, RUA_RUA_PDU_t *pdu)
{
	int rc;

	/* it's a bit odd that we can't dispatch on procedure code, but
	 * that's not possible */
	switch (pdu->present) {
	case RUA_RUA_PDU_PR_initiatingMessage:
		rc = rua_rx_initiating_msg(msg, &pdu->choice.initiatingMessage);
		break;
	case RUA_RUA_PDU_PR_successfulOutcome:
		rc = rua_rx_successful_outcome_msg(msg, &pdu->choice.successfulOutcome);
		break;
	case RUA_RUA_PDU_PR_unsuccessfulOutcome:
		rc = rua_rx_unsuccessful_outcome_msg(msg, &pdu->choice.unsuccessfulOutcome);
		break;
	default:
		LOGP(DRUA, LOGL_NOTICE, "Unknown RUA presence %u\n", pdu->present);
		rc = -1;
	}

	return rc;
}

int hnbgw_rua_rx(struct hnb_context *hnb, struct msgb *msg)
{
	RUA_RUA_PDU_t _pdu, *pdu = &_pdu;
	asn_dec_rval_t dec_ret;
	int rc;

	/* decode and handle to _hnbgw_hnbap_rx() */

	memset(pdu, 0, sizeof(*pdu));
	dec_ret = aper_decode(NULL, &asn_DEF_RUA_RUA_PDU, (void **) &pdu,
			      msg->data, msgb_length(msg), 0, 0);
	if (dec_ret.code != RC_OK) {
		LOGP(DRUA, LOGL_ERROR, "Error in ASN.1 decode\n");
		return -1;
	}

	rc = _hnbgw_rua_rx(msg, pdu);

	return rc;
}


int hnbgw_rua_init(void)
{
	return 0;
}
