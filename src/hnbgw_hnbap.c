/* hnb-gw specific code for HNBAP */

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
#include <osmocom/core/socket.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/netif/stream.h>

#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "asn1helpers.h"
#include <osmocom/hnbap/hnbap_common.h>
#include <osmocom/ranap/iu_helpers.h>

#include <osmocom/iuh/hnbgw.h>

#define IU_MSG_NUM_IES		32
#define IU_MSG_NUM_EXT_IES	32

static int hnbgw_hnbap_tx(struct hnb_context *ctx, struct msgb *msg)
{
	if (!msg)
		return -EINVAL;

	msgb_sctp_ppid(msg) = IUH_PPI_HNBAP;
	osmo_stream_srv_send(ctx->conn, msg);

	return 0;
}

static int hnbgw_tx_hnb_register_rej(struct hnb_context *ctx)
{
	HNBAP_PDU_t pdu;
	HNBRegisterReject_t *out;
	HNBRegisterRejectIEs_t *ie;
	struct msgb *msg;
	int rc;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = HNBAP_PDU_PR_unsuccessfulOutcome;
	pdu.choice.unsuccessfulOutcome.procedureCode = ProcedureCode_id_HNBRegister;
	pdu.choice.unsuccessfulOutcome.criticality = Criticality_reject;
	pdu.choice.unsuccessfulOutcome.value.present = UnsuccessfulOutcome__value_PR_HNBRegisterReject;
	out = &pdu.choice.unsuccessfulOutcome.value.choice.HNBRegisterReject;

	ie = (HNBRegisterRejectIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = ProtocolIE_ID_id_Cause;
	ie->criticality = Criticality_ignore;
	ie->value.present = HNBRegisterRejectIEs__value_PR_Cause;
	ie->value.choice.Cause.present = Cause_PR_radioNetwork;
	ie->value.choice.Cause.choice.radioNetwork = CauseRadioNetwork_unspecified;
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	/* optional */
	if (0) {
		ie = (HNBRegisterRejectIEs_t *)CALLOC(1, sizeof(*ie));
		ie->id = ProtocolIE_ID_id_CriticalityDiagnostics;
		ie->criticality = Criticality_ignore;
		ie->value.present = HNBRegisterRejectIEs__value_PR_CriticalityDiagnostics;

		/* TBD */

		ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);
	}

	/* BackoffTimer ::= INTEGER(0..3600) */

#if 0
	if ((backoff_timer >= 0) && (backoff_timer <= 3600)) {
		ie = (HNBRegisterRejectIEs_t *)CALLOC(1, sizeof(*ie));
		ie->id = ProtocolIE_ID_id_BackoffTimer;
		ie->criticality = Criticality_reject;
		ie->value.present = HNBRegisterRejectIEs__value_PR_BackoffTimer;
		ie->value.choice.BackoffTimer = backoff_timer;
		ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);
	} else {

		/* conditional : This IE shall be present if the Cause IE is set to "Overload". */
		if (((ie_cond->value.choice.Cause.present == Cause_PR_radioNetwork) &&
			(ie_cond->value.choice.Cause.choice.radioNetwork == CauseRadioNetwork_overload)) ||
			((ie_cond->value.choice.Cause.present == Cause_PR_radioNetwork) &&
			(ie_cond->value.choice.Cause.choice.radioNetwork == CauseRadioNetwork_overload))) {
			/* TBD : raise error */
		}
	}
#endif

	msg = _hnbap_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_HNBAP_PDU, &pdu);

	rc = hnbgw_hnbap_tx(ctx, msg);
	if (rc == 0) {
		/* Tell libosmo-netif to destroy this connection when it is done
		 * sending our HNB-REGISTER-REJECT response. */
		osmo_stream_srv_set_flush_and_destroy(ctx->conn);
	} else {
		/* The message was not queued. Destroy the connection right away. */
		hnb_context_release(ctx, true);
	}
	return rc;
}

static int hnbgw_tx_hnb_register_acc(struct hnb_context *ctx)
{
	HNBAP_PDU_t pdu;
	HNBRegisterAccept_t *out;
	HNBRegisterResponseIEs_t *ie;
	struct msgb *msg;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = HNBAP_PDU_PR_successfulOutcome;
	pdu.choice.successfulOutcome.procedureCode = ProcedureCode_id_HNBRegister;
	pdu.choice.successfulOutcome.criticality = Criticality_reject;
	pdu.choice.successfulOutcome.value.present = SuccessfulOutcome__value_PR_HNBRegisterAccept;
	out = &pdu.choice.successfulOutcome.value.choice.HNBRegisterAccept;

	ie = (HNBRegisterResponseIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = ProtocolIE_ID_id_RNC_ID;
	ie->criticality = Criticality_reject;
	ie->value.present = HNBRegisterResponseIEs__value_PR_RNC_ID;
	ie->value.choice.RNC_ID = ctx->gw->config.rnc_id;
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	msg = _hnbap_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_HNBAP_PDU, &pdu);

	return hnbgw_hnbap_tx(ctx, msg);
}


static int hnbgw_tx_ue_register_acc(struct ue_context *ue)
{
	HNBAP_PDU_t pdu;
	UERegisterAccept_t *out;
	UERegisterAcceptIEs_t *ie;
	struct msgb *msg;
	uint8_t encoded_imsi[10];
	uint32_t ctx_id;
	size_t encoded_imsi_len;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = HNBAP_PDU_PR_successfulOutcome;
	pdu.choice.successfulOutcome.procedureCode = ProcedureCode_id_UERegister;
	pdu.choice.successfulOutcome.criticality = Criticality_reject;
	pdu.choice.successfulOutcome.value.present = SuccessfulOutcome__value_PR_UERegisterAccept;
	out = &pdu.choice.successfulOutcome.value.choice.UERegisterAccept;

	ie = (UERegisterAcceptIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = ProtocolIE_ID_id_UE_Identity;
	ie->criticality = Criticality_reject;
	ie->value.present = UERegisterAcceptIEs__value_PR_UE_Identity;
	ie->value.choice.UE_Identity.present = UE_Identity_PR_iMSI;
	encoded_imsi_len = ranap_imsi_encode(encoded_imsi,
					  sizeof(encoded_imsi), ue->imsi);
	OCTET_STRING_fromBuf(&ie->value.choice.UE_Identity.choice.iMSI,
			     (const char *)encoded_imsi, encoded_imsi_len);
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	ie = (UERegisterAcceptIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = ProtocolIE_ID_id_Context_ID;
	ie->criticality = Criticality_reject;
	ie->value.present = UERegisterAcceptIEs__value_PR_Context_ID;
	asn1_u24_to_bitstring(&ie->value.choice.Context_ID, &ctx_id, ue->context_id);
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	msg = _hnbap_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_HNBAP_PDU, &pdu);

	return hnbgw_hnbap_tx(ue->hnb, msg);
}

static int hnbgw_tx_ue_register_rej_tmsi(struct hnb_context *hnb, UE_Identity_t *ue_id)
{
	HNBAP_PDU_t pdu;
	UERegisterReject_t *out;
	UERegisterRejectIEs_t *ie;
	struct msgb *msg;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = HNBAP_PDU_PR_unsuccessfulOutcome;
	pdu.choice.unsuccessfulOutcome.procedureCode = ProcedureCode_id_UERegister;
	pdu.choice.unsuccessfulOutcome.criticality = Criticality_reject;
	pdu.choice.unsuccessfulOutcome.value.present = UnsuccessfulOutcome__value_PR_UERegisterReject;
	out = &pdu.choice.unsuccessfulOutcome.value.choice.UERegisterReject;

	ie = (UERegisterRejectIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = ProtocolIE_ID_id_UE_Identity;
	ie->criticality = Criticality_ignore;
	ie->value.present = UERegisterRejectIEs__value_PR_UE_Identity;
	ie->value.choice.UE_Identity.present = ue_id->present;

	/* Copy the identity over to the reject message */
	switch (ue_id->present) {
	case UE_Identity_PR_tMSILAI:
		LOGP(DHNBAP, LOGL_DEBUG, "REJ UE_Id tMSI %ld %s\n",
		     ue_id->choice.tMSILAI.tMSI.size,
		     osmo_hexdump(ue_id->choice.tMSILAI.tMSI.buf,
				  ue_id->choice.tMSILAI.tMSI.size));

		LOGP(DHNBAP, LOGL_DEBUG, "REJ UE_Id pLMNID %ld %s\n",
		     ue_id->choice.tMSILAI.lAI.pLMNID.size,
		     osmo_hexdump(ue_id->choice.tMSILAI.lAI.pLMNID.buf,
				  ue_id->choice.tMSILAI.lAI.pLMNID.size));

		LOGP(DHNBAP, LOGL_DEBUG, "REJ UE_Id lAC %ld %s\n",
		     ue_id->choice.tMSILAI.lAI.lAC.size,
		     osmo_hexdump(ue_id->choice.tMSILAI.lAI.lAC.buf,
				  ue_id->choice.tMSILAI.lAI.lAC.size));

		BIT_STRING_fromBuf(&ie->value.choice.UE_Identity.choice.tMSILAI.tMSI,
				   ue_id->choice.tMSILAI.tMSI.buf,
				   ue_id->choice.tMSILAI.tMSI.size * 8
				   - ue_id->choice.tMSILAI.tMSI.bits_unused);
		OCTET_STRING_fromBuf(&ie->value.choice.UE_Identity.choice.tMSILAI.lAI.pLMNID,
				     (const char *)ue_id->choice.tMSILAI.lAI.pLMNID.buf,
				     ue_id->choice.tMSILAI.lAI.pLMNID.size);
		OCTET_STRING_fromBuf(&ie->value.choice.UE_Identity.choice.tMSILAI.lAI.lAC,
				     (const char *)ue_id->choice.tMSILAI.lAI.lAC.buf,
				     ue_id->choice.tMSILAI.lAI.lAC.size);
		break;

	case UE_Identity_PR_pTMSIRAI:
		LOGP(DHNBAP, LOGL_DEBUG, "REJ UE_Id pTMSI %ld %s\n",
		     ue_id->choice.pTMSIRAI.pTMSI.size,
		     osmo_hexdump(ue_id->choice.pTMSIRAI.pTMSI.buf,
				  ue_id->choice.pTMSIRAI.pTMSI.size));

		LOGP(DHNBAP, LOGL_DEBUG, "REJ UE_Id pLMNID %ld %s\n",
		     ue_id->choice.pTMSIRAI.rAI.lAI.pLMNID.size,
		     osmo_hexdump(ue_id->choice.pTMSIRAI.rAI.lAI.pLMNID.buf,
				  ue_id->choice.pTMSIRAI.rAI.lAI.pLMNID.size));

		LOGP(DHNBAP, LOGL_DEBUG, "REJ UE_Id lAC %ld %s\n",
		     ue_id->choice.pTMSIRAI.rAI.lAI.lAC.size,
		     osmo_hexdump(ue_id->choice.pTMSIRAI.rAI.lAI.lAC.buf,
				  ue_id->choice.pTMSIRAI.rAI.lAI.lAC.size));

		LOGP(DHNBAP, LOGL_DEBUG, "REJ UE_Id rAC %ld %s\n",
		     ue_id->choice.pTMSIRAI.rAI.rAC.size,
		     osmo_hexdump(ue_id->choice.pTMSIRAI.rAI.rAC.buf,
				  ue_id->choice.pTMSIRAI.rAI.rAC.size));

		BIT_STRING_fromBuf(&ie->value.choice.UE_Identity.choice.pTMSIRAI.pTMSI,
				   ue_id->choice.pTMSIRAI.pTMSI.buf,
				   ue_id->choice.pTMSIRAI.pTMSI.size * 8
				   - ue_id->choice.pTMSIRAI.pTMSI.bits_unused);
		OCTET_STRING_fromBuf(&ie->value.choice.UE_Identity.choice.pTMSIRAI.rAI.lAI.pLMNID,
				     (const char *)ue_id->choice.pTMSIRAI.rAI.lAI.pLMNID.buf,
				     ue_id->choice.pTMSIRAI.rAI.lAI.pLMNID.size);
		OCTET_STRING_fromBuf(&ie->value.choice.UE_Identity.choice.pTMSIRAI.rAI.lAI.lAC,
				     (const char *)ue_id->choice.pTMSIRAI.rAI.lAI.lAC.buf,
				     ue_id->choice.pTMSIRAI.rAI.lAI.lAC.size);
		OCTET_STRING_fromBuf(&ie->value.choice.UE_Identity.choice.pTMSIRAI.rAI.rAC,
				     (const char *)ue_id->choice.pTMSIRAI.rAI.rAC.buf,
				     ue_id->choice.pTMSIRAI.rAI.rAC.size);
		break;

	default:
		LOGP(DHNBAP, LOGL_ERROR, "Cannot compose UE Register Reject:"
		     " unsupported UE ID (present=%d)\n", ue_id->present);
		FREEMEM(ie);
		return -1;
	}
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	LOGP(DHNBAP, LOGL_ERROR, "Rejecting UE Register Request:"
	     " TMSI identity registration is switched off\n");

	ie = (UERegisterRejectIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = ProtocolIE_ID_id_Cause;
	ie->criticality = Criticality_ignore;
	ie->value.present = UERegisterRejectIEs__value_PR_Cause;
	ie->value.choice.Cause.present = Cause_PR_radioNetwork;
	ie->value.choice.Cause.choice.radioNetwork = CauseRadioNetwork_invalid_UE_identity;
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	msg = _hnbap_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_HNBAP_PDU, &pdu);

	return hnbgw_hnbap_tx(hnb, msg);
}

static int hnbgw_tx_ue_register_acc_tmsi(struct hnb_context *hnb, UE_Identity_t *ue_id)
{
	HNBAP_PDU_t pdu;
	UERegisterAccept_t *out;
	UERegisterAcceptIEs_t *ie;
	struct msgb *msg;
	uint32_t ctx_id;
	uint32_t tmsi = 0;
	struct ue_context *ue;

	pdu.present = HNBAP_PDU_PR_successfulOutcome;
	pdu.choice.successfulOutcome.procedureCode = ProcedureCode_id_UERegister;
	pdu.choice.successfulOutcome.criticality = Criticality_reject;
	pdu.choice.successfulOutcome.value.present = SuccessfulOutcome__value_PR_UERegisterAccept;
	out = &pdu.choice.successfulOutcome.value.choice.UERegisterAccept;

	ie = (UERegisterAcceptIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = ProtocolIE_ID_id_UE_Identity;
	ie->criticality = Criticality_reject;
	ie->value.present = UERegisterAcceptIEs__value_PR_UE_Identity;
	ie->value.choice.UE_Identity.present = ue_id->present;

	switch (ue_id->present) {
	case UE_Identity_PR_tMSILAI:
		BIT_STRING_fromBuf(&ie->value.choice.UE_Identity.choice.tMSILAI.tMSI,
				   ue_id->choice.tMSILAI.tMSI.buf,
				   ue_id->choice.tMSILAI.tMSI.size * 8
				   - ue_id->choice.tMSILAI.tMSI.bits_unused);
		tmsi = *(uint32_t*)ie->value.choice.UE_Identity.choice.tMSILAI.tMSI.buf;
		OCTET_STRING_fromBuf(&ie->value.choice.UE_Identity.choice.tMSILAI.lAI.pLMNID,
				     (const char *)ue_id->choice.tMSILAI.lAI.pLMNID.buf,
				     ue_id->choice.tMSILAI.lAI.pLMNID.size);
		OCTET_STRING_fromBuf(&ie->value.choice.UE_Identity.choice.tMSILAI.lAI.lAC,
				     (const char *)ue_id->choice.tMSILAI.lAI.lAC.buf,
				     ue_id->choice.tMSILAI.lAI.lAC.size);
		break;

	case UE_Identity_PR_pTMSIRAI:
		BIT_STRING_fromBuf(&ie->value.choice.UE_Identity.choice.pTMSIRAI.pTMSI,
				   ue_id->choice.pTMSIRAI.pTMSI.buf,
				   ue_id->choice.pTMSIRAI.pTMSI.size * 8
				   - ue_id->choice.pTMSIRAI.pTMSI.bits_unused);
		tmsi = *(uint32_t*)ie->value.choice.UE_Identity.choice.pTMSIRAI.pTMSI.buf;
		OCTET_STRING_fromBuf(&ie->value.choice.UE_Identity.choice.pTMSIRAI.rAI.lAI.pLMNID,
				     (const char *)ue_id->choice.pTMSIRAI.rAI.lAI.pLMNID.buf,
				     ue_id->choice.pTMSIRAI.rAI.lAI.pLMNID.size);
		OCTET_STRING_fromBuf(&ie->value.choice.UE_Identity.choice.pTMSIRAI.rAI.lAI.lAC,
				     (const char *)ue_id->choice.pTMSIRAI.rAI.lAI.lAC.buf,
				     ue_id->choice.pTMSIRAI.rAI.lAI.lAC.size);
		OCTET_STRING_fromBuf(&ie->value.choice.UE_Identity.choice.pTMSIRAI.rAI.rAC,
				     (const char *)ue_id->choice.pTMSIRAI.rAI.rAC.buf,
				     ue_id->choice.pTMSIRAI.rAI.rAC.size);
		break;

	default:
		LOGP(DHNBAP, LOGL_ERROR, "Unsupportedccept UE ID (present=%d)\n",
			ue_id->present);
		FREEMEM(ie);
		return -1;
	}
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	tmsi = ntohl(tmsi);
	LOGP(DHNBAP, LOGL_DEBUG, "HNBAP register with TMSI %x\n",
	     tmsi);

	ue = ue_context_by_tmsi(hnb->gw, tmsi);
	if (!ue)
		ue = ue_context_alloc(hnb, NULL, tmsi);

	ie = (UERegisterAcceptIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = ProtocolIE_ID_id_Context_ID;
	ie->criticality = Criticality_reject;
	ie->value.present = UERegisterAcceptIEs__value_PR_Context_ID;
	asn1_u24_to_bitstring(&ie->value.choice.Context_ID, &ctx_id, ue->context_id);
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	msg = _hnbap_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_HNBAP_PDU, &pdu);

	return hnbgw_hnbap_tx(hnb, msg);
}

static int hnbgw_rx_hnb_deregister(struct hnb_context *ctx, HNBDe_Register_t *in)
{
	HNBDe_RegisterIEs_t *ie;

	HNBAP_FIND_PROTOCOLIE_BY_ID(HNBDe_RegisterIEs_t, ie, in, ProtocolIE_ID_id_Cause, true);

	DEBUGP(DHNBAP, "HNB-DE-REGISTER cause=%s\n",
		hnbap_cause_str(&ie->value.choice.Cause));

	hnb_context_release(ctx, true);

	return 0;
}

static int hnbgw_rx_hnb_register_req(struct hnb_context *ctx, HNBRegisterRequest_t *in)
{
	struct hnb_context *hnb;
	HNBRegisterRequestIEs_t *ie;

	HNBAP_FIND_PROTOCOLIE_BY_ID(HNBRegisterRequestIEs_t, ie, in, ProtocolIE_ID_id_HNB_Identity, true);

	/* copy all identity parameters from the message to ctx */
	asn1_strncpy(ctx->identity_info, &ie->value.choice.HNB_Identity.hNB_Identity_Info,
			sizeof(ctx->identity_info));

	HNBAP_FIND_PROTOCOLIE_BY_ID(HNBRegisterRequestIEs_t, ie, in, ProtocolIE_ID_id_LAC, true);
	ctx->id.lac = asn1str_to_u16(&ie->value.choice.LAC);

	HNBAP_FIND_PROTOCOLIE_BY_ID(HNBRegisterRequestIEs_t, ie, in, ProtocolIE_ID_id_SAC, true);
	ctx->id.sac = asn1str_to_u16(&ie->value.choice.SAC);

	HNBAP_FIND_PROTOCOLIE_BY_ID(HNBRegisterRequestIEs_t, ie, in, ProtocolIE_ID_id_RAC, true);
	ctx->id.rac = asn1str_to_u8(&ie->value.choice.RAC);

	HNBAP_FIND_PROTOCOLIE_BY_ID(HNBRegisterRequestIEs_t, ie, in, ProtocolIE_ID_id_CellIdentity, true);
	ctx->id.cid = asn1bitstr_to_u28(&ie->value.choice.CellIdentity);

	HNBAP_FIND_PROTOCOLIE_BY_ID(HNBRegisterRequestIEs_t, ie, in, ProtocolIE_ID_id_PLMNidentity, true);
	gsm48_mcc_mnc_from_bcd(ie->value.choice.PLMNidentity.buf, &ctx->id.mcc, &ctx->id.mnc);

	llist_for_each_entry(hnb, &ctx->gw->hnb_list, list) {
		if (hnb->hnb_registered && ctx != hnb && memcmp(&ctx->id, &hnb->id, sizeof(ctx->id)) == 0) {
			struct osmo_fd *ofd = osmo_stream_srv_get_ofd(ctx->conn);
			char *name = osmo_sock_get_name(ctx, ofd->fd);
			LOGP(DHNBAP, LOGL_ERROR, "rejecting HNB-REGISTER-REQ with duplicate cell identity "
			     "MCC=%u,MNC=%u,LAC=%u,RAC=%u,SAC=%u,CID=%u from %s\n",
			     ctx->id.mcc, ctx->id.mnc, ctx->id.lac, ctx->id.rac, ctx->id.sac, ctx->id.cid, name);
			talloc_free(name);
			return hnbgw_tx_hnb_register_rej(ctx);
		}
	}

	ctx->hnb_registered = true;

	DEBUGP(DHNBAP, "HNB-REGISTER-REQ from %s\n", ctx->identity_info);

	/* Send HNBRegisterAccept */
	return hnbgw_tx_hnb_register_acc(ctx);
}

static int hnbgw_rx_ue_register_req(struct hnb_context *ctx, UERegisterRequest_t *in)
{
	UERegisterRequestIEs_t *ie, *ie_cause;
	struct ue_context *ue;
	char imsi[16];

	HNBAP_FIND_PROTOCOLIE_BY_ID(UERegisterRequestIEs_t, ie, in, ProtocolIE_ID_id_CellIdentity, true);

	switch (ie->value.choice.UE_Identity.present) {
	case UE_Identity_PR_iMSI:
		ranap_bcd_decode(imsi, sizeof(imsi), ie->value.choice.UE_Identity.choice.iMSI.buf,
			      ie->value.choice.UE_Identity.choice.iMSI.size);
		break;
	case UE_Identity_PR_iMSIDS41:
		ranap_bcd_decode(imsi, sizeof(imsi), ie->value.choice.UE_Identity.choice.iMSIDS41.buf,
			      ie->value.choice.UE_Identity.choice.iMSIDS41.size);
		break;
	case UE_Identity_PR_iMSIESN:
		ranap_bcd_decode(imsi, sizeof(imsi), ie->value.choice.UE_Identity.choice.iMSIESN.iMSIDS41.buf,
			      ie->value.choice.UE_Identity.choice.iMSIESN.iMSIDS41.size);
		break;
	case UE_Identity_PR_tMSILAI:
	case UE_Identity_PR_pTMSIRAI:
		if (ctx->gw->config.hnbap_allow_tmsi) {
			HNBAP_FIND_PROTOCOLIE_BY_ID(UERegisterRequestIEs_t, ie_cause, in, ProtocolIE_ID_id_Registration_Cause, true);

			DEBUGP(DHNBAP, "UE-REGISTER-REQ ID_type=%d cause=%ld\n",
				ie->value.choice.UE_Identity.present, ie_cause->value.choice.Registration_Cause);

			return hnbgw_tx_ue_register_acc_tmsi(ctx, &ie->value.choice.UE_Identity);
		} else {
			return hnbgw_tx_ue_register_rej_tmsi(ctx, &ie->value.choice.UE_Identity);
		}
		/* all has been handled by TMSI, skip the IMSI code below */
		break;
	default:
		LOGP(DHNBAP, LOGL_NOTICE,
		     "UE-REGISTER-REQ with unsupported UE Id type %d\n",
		     ie->value.choice.UE_Identity.present);
		return -1;
	}

	HNBAP_FIND_PROTOCOLIE_BY_ID(UERegisterRequestIEs_t, ie_cause, in, ProtocolIE_ID_id_Registration_Cause, true);

	DEBUGP(DHNBAP, "UE-REGISTER-REQ ID_type=%d imsi=%s cause=%ld\n",
		ie->value.choice.UE_Identity.present, imsi, ie_cause->value.choice.Registration_Cause);

	ue = ue_context_by_imsi(ctx->gw, imsi);
	if (!ue)
		ue = ue_context_alloc(ctx, imsi, 0);

	/* Send UERegisterAccept */
	return hnbgw_tx_ue_register_acc(ue);
}

static int hnbgw_rx_ue_deregister(struct hnb_context *ctx, UEDe_Register_t *in)
{
	UEDe_RegisterIEs_t *ie, *ie_cause;
	struct ue_context *ue;
	uint32_t ctxid;

	HNBAP_FIND_PROTOCOLIE_BY_ID(UEDe_RegisterIEs_t, ie, in, ProtocolIE_ID_id_Context_ID, true);

	ctxid = asn1bitstr_to_u24(&ie->value.choice.Context_ID);

	HNBAP_FIND_PROTOCOLIE_BY_ID(UEDe_RegisterIEs_t, ie_cause, in, ProtocolIE_ID_id_Cause, true);

	DEBUGP(DHNBAP, "UE-DE-REGISTER context=%u cause=%s\n",
		ctxid, hnbap_cause_str(&ie_cause->value.choice.Cause));

	ue = ue_context_by_id(ctx->gw, ctxid);
	if (ue)
		ue_context_free(ue);

	return 0;
}

static int hnbgw_rx_err_ind(struct hnb_context *hnb, ErrorIndication_t *in)
{
	ErrorIndicationIEs_t *ie;

	HNBAP_FIND_PROTOCOLIE_BY_ID(ErrorIndicationIEs_t, ie, in, ProtocolIE_ID_id_Cause, true);

	LOGP(DHNBAP, LOGL_NOTICE, "HNBAP ERROR.ind, cause: %s\n",
		hnbap_cause_str(&ie->value.choice.Cause));

	return 0;
}

static int hnbgw_rx_initiating_msg(struct hnb_context *hnb, InitiatingMessage_t *imsg)
{
	int rc = 0;

	switch (imsg->procedureCode) {
	case ProcedureCode_id_HNBRegister:	/* 8.2 */
		rc = hnbgw_rx_hnb_register_req(hnb, &imsg->value.choice.HNBRegisterRequest);
		break;
	case ProcedureCode_id_HNBDe_Register:	/* 8.3 */
		rc = hnbgw_rx_hnb_deregister(hnb, &imsg->value.choice.HNBDe_Register);
		break;
	case ProcedureCode_id_UERegister: 	/* 8.4 */
		rc = hnbgw_rx_ue_register_req(hnb, &imsg->value.choice.UERegisterRequest);
		break;
	case ProcedureCode_id_UEDe_Register:	/* 8.5 */
		rc = hnbgw_rx_ue_deregister(hnb, &imsg->value.choice.UEDe_Register);
		break;
	case ProcedureCode_id_ErrorIndication:	/* 8.6 */
		rc = hnbgw_rx_err_ind(hnb, &imsg->value.choice.ErrorIndication);
		break;
	case ProcedureCode_id_TNLUpdate:	/* 8.9 */
	case ProcedureCode_id_HNBConfigTransfer:	/* 8.10 */
	case ProcedureCode_id_RelocationComplete:	/* 8.11 */
	case ProcedureCode_id_U_RNTIQuery:	/* 8.12 */
	case ProcedureCode_id_privateMessage:
		LOGP(DHNBAP, LOGL_NOTICE, "Unimplemented HNBAP Procedure %ld\n",
			imsg->procedureCode);
		break;
	default:
		LOGP(DHNBAP, LOGL_NOTICE, "Unknown HNBAP Procedure %ld\n",
			imsg->procedureCode);
		break;
	}

	return rc;
}

static int hnbgw_rx_successful_outcome_msg(struct hnb_context *hnb, SuccessfulOutcome_t *msg)
{
	/* We don't care much about HNBAP */
	return 0;
}

static int hnbgw_rx_unsuccessful_outcome_msg(struct hnb_context *hnb, UnsuccessfulOutcome_t *msg)
{
	/* We don't care much about HNBAP */
	LOGP(DHNBAP, LOGL_ERROR, "Received Unsuccessful Outcome, procedureCode %ld, criticality %ld,"
	     " from '%s', cell mcc %u mnc %u lac %u rac %u sac %u cid %u\n",
	     msg->procedureCode, msg->criticality, hnb->identity_info,
	     hnb->id.mcc, hnb->id.mnc, hnb->id.lac, hnb->id.rac, hnb->id.sac, hnb->id.cid);
	return 0;
}


static int _hnbgw_hnbap_rx(struct hnb_context *hnb, HNBAP_PDU_t *pdu)
{
	int rc = 0;

	/* it's a bit odd that we can't dispatch on procedure code, but
	 * that's not possible */
	switch (pdu->present) {
	case HNBAP_PDU_PR_initiatingMessage:
		rc = hnbgw_rx_initiating_msg(hnb, &pdu->choice.initiatingMessage);
		break;
	case HNBAP_PDU_PR_successfulOutcome:
		rc = hnbgw_rx_successful_outcome_msg(hnb, &pdu->choice.successfulOutcome);
		break;
	case HNBAP_PDU_PR_unsuccessfulOutcome:
		rc = hnbgw_rx_unsuccessful_outcome_msg(hnb, &pdu->choice.unsuccessfulOutcome);
		break;
	default:
		LOGP(DHNBAP, LOGL_NOTICE, "Unknown HNBAP Presence %u\n",
			pdu->present);
		rc = -1;
	}

	return rc;
}

int hnbgw_hnbap_rx(struct hnb_context *hnb, struct msgb *msg)
{
	HNBAP_PDU_t _pdu, *pdu = &_pdu;
	asn_dec_rval_t dec_ret;
	int rc;

	/* decode and handle to _hnbgw_hnbap_rx() */

	memset(pdu, 0, sizeof(*pdu));
	dec_ret = aper_decode(NULL, &asn_DEF_HNBAP_PDU, (void **) &pdu,
			      msg->data, msgb_length(msg), 0, 0);
	if (dec_ret.code != RC_OK) {
		LOGP(DHNBAP, LOGL_ERROR, "Error in ASN.1 decode\n");
		return -1;
	}

	rc = _hnbgw_hnbap_rx(hnb, pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_HNBAP_PDU, pdu);

	return rc;
}


int hnbgw_hnbap_init(void)
{
	return 0;
}
