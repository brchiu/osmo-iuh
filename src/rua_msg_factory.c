#include <stdint.h>
#include <osmocom/netif/stream.h>

#include <osmocom/rua/rua_common.h>
#include <osmocom/rua/rua_msg_factory.h>
#include "asn1helpers.h"
#include <osmocom/iuh/hnbgw.h>


struct msgb *rua_new_udt(struct msgb *inmsg)
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
	OCTET_STRING_fromBuf(&ie->value.choice.RANAP_Message,  (const char *)inmsg->data, msgb_length(inmsg));
	msgb_free(inmsg);
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	msg = _rua_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RUA_RUA_PDU, &pdu);

	DEBUGP(DMAIN, "transmitting RUA payload of %u bytes\n", msgb_length(msg));

	msgb_sctp_ppid(msg) = IUH_PPI_RUA;

	return msg;
}

struct msgb *rua_new_conn(int is_ps, uint32_t context_id, struct msgb *inmsg)
{
	RUA_RUA_PDU_t pdu;
	RUA_Connect_t *out;
	RUA_ConnectIEs_t *ie;
	struct msgb *msg;
	uint32_t ctxidbuf;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = RUA_RUA_PDU_PR_initiatingMessage;
	pdu.choice.initiatingMessage.procedureCode = RUA_ProcedureCode_id_Connect;
	pdu.choice.initiatingMessage.criticality = RUA_Criticality_ignore;
	pdu.choice.initiatingMessage.value.present = RUA_InitiatingMessage__value_PR_Connect;
	out = &pdu.choice.initiatingMessage.value.choice.Connect;

	ie = (RUA_ConnectIEs_t *)calloc(1, sizeof(RUA_ConnectIEs_t));
	ie->id = RUA_ProtocolIE_ID_id_CN_DomainIndicator;
	ie->criticality = RUA_Criticality_reject;
	ie->value.present = RUA_DisconnectIEs__value_PR_CN_DomainIndicator;
	ie->value.choice.CN_DomainIndicator = is_ps ? RUA_CN_DomainIndicator_ps_domain : RUA_CN_DomainIndicator_cs_domain;
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	ie = (RUA_ConnectIEs_t *)calloc(1, sizeof(RUA_ConnectIEs_t));
	ie->id = RUA_ProtocolIE_ID_id_Context_ID;
	ie->criticality = RUA_Criticality_reject;
	ie->value.present = RUA_ConnectIEs__value_PR_Context_ID;
	asn1_u24_to_bitstring(&ie->value.choice.Context_ID, &ctxidbuf, context_id);
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	/* optional */
	if (9) {
		ie = (RUA_ConnectIEs_t *)calloc(1, sizeof(RUA_ConnectIEs_t));
		ie->id = RUA_ProtocolIE_ID_id_IntraDomainNasNodeSelector;
		ie->criticality = RUA_Criticality_reject;
		ie->value.present = RUA_ConnectIEs__value_PR_IntraDomainNasNodeSelector;

		/* TBD */

		ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);
	}

	ie = (RUA_ConnectIEs_t *)calloc(1, sizeof(RUA_ConnectIEs_t));
	ie->id = RUA_ProtocolIE_ID_id_Cause;
	ie->criticality = RUA_Criticality_reject;
	ie->value.present = RUA_ConnectIEs__value_PR_Establishment_Cause;
	ie->value.choice.Establishment_Cause = RUA_Establishment_Cause_normal_call;
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	ie = (RUA_ConnectIEs_t *)calloc(1, sizeof(RUA_ConnectIEs_t));
	ie->id = RUA_ProtocolIE_ID_id_RANAP_Message;
	ie->criticality = RUA_Criticality_reject;
	ie->value.present = RUA_ConnectIEs__value_PR_RANAP_Message;
	OCTET_STRING_fromBuf(&ie->value.choice.RANAP_Message,  (const char *)inmsg->data, msgb_length(inmsg));
	msgb_free(inmsg);
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	msg = _rua_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RUA_RUA_PDU, &pdu);

	DEBUGP(DMAIN, "transmitting RUA payload of %u bytes\n", msgb_length(msg));

	msgb_sctp_ppid(msg) = IUH_PPI_RUA;

	return msg;
}

struct msgb *rua_new_dt(int is_ps, uint32_t context_id, struct msgb *inmsg)
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
	OCTET_STRING_fromBuf(&ie->value.choice.RANAP_Message,  (const char *)inmsg->data, msgb_length(inmsg));
	msgb_free(inmsg);
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	msg = _rua_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RUA_RUA_PDU, &pdu);

	DEBUGP(DMAIN, "transmitting RUA payload of %u bytes\n", msgb_length(msg));

	msgb_sctp_ppid(msg) = IUH_PPI_RUA;

	return msg;
}

struct msgb *rua_new_disc(int is_ps, uint32_t context_id, struct msgb *inmsg)
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

	ie = (RUA_DisconnectIEs_t *)calloc(1, sizeof(RUA_DisconnectIEs_t));
	ie->id = RUA_ProtocolIE_ID_id_CN_DomainIndicator;
	ie->criticality = RUA_Criticality_reject;
	ie->value.present = RUA_DisconnectIEs__value_PR_CN_DomainIndicator;
	ie->value.choice.CN_DomainIndicator = is_ps ? RUA_CN_DomainIndicator_ps_domain : RUA_CN_DomainIndicator_cs_domain;
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	ie = (RUA_DisconnectIEs_t *)calloc(1, sizeof(RUA_DisconnectIEs_t));
	ie->id = RUA_ProtocolIE_ID_id_Context_ID;
	ie->criticality = RUA_Criticality_reject;
	ie->value.present = RUA_DisconnectIEs__value_PR_Context_ID;
	asn1_u24_to_bitstring(&ie->value.choice.Context_ID, &ctxidbuf, context_id);
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	ie = (RUA_DisconnectIEs_t *)calloc(1, sizeof(RUA_DisconnectIEs_t));
	ie->id = RUA_ProtocolIE_ID_id_Cause;
	ie->criticality = RUA_Criticality_reject;
	ie->value.present = RUA_DisconnectIEs__value_PR_Cause;
	ie->value.choice.Cause.present = RUA_Cause_PR_radioNetwork;
	ie->value.choice.Cause.choice.radioNetwork = RUA_CauseRadioNetwork_normal;
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	if (inmsg && inmsg->data && msgb_length(inmsg)) {
		ie = (RUA_DisconnectIEs_t *)calloc(1, sizeof(RUA_DisconnectIEs_t));
		ie->id = RUA_ProtocolIE_ID_id_RANAP_Message;
		ie->criticality = RUA_Criticality_reject;
		ie->value.present = RUA_DisconnectIEs__value_PR_RANAP_Message;
		OCTET_STRING_fromBuf(&ie->value.choice.RANAP_Message, (const char *)inmsg->data, msgb_length(inmsg));
		msgb_free(inmsg);
		ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);
	}

	msg = _rua_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RUA_RUA_PDU, &pdu);

	DEBUGP(DMAIN, "transmitting RUA payload of %u bytes\n", msgb_length(msg));

	msgb_sctp_ppid(msg) = IUH_PPI_RUA;

	return msg;
}

#if 0
struct msgb *rua_new_errorind(RUA_Cause_t *cause)
{
	RUA_RUA_PDU_t pdu;
	RUA_ErrorIndication_t *out;
	RUA_ErrorIndicationIEs_t *ie;
	struct msgb *msg;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = RUA_RUA_PDU_PR_initiatingMessage;
	pdu.choice.initiatingMessage.procedureCode = RUA_ProcedureCode_id_ErrorIndication;
	pdu.choice.initiatingMessage.criticality = RUA_Criticality_ignore;
	pdu.choice.initiatingMessage.value.present = RUA_InitiatingMessage__value_PR_ErrorIndication;
	out = &pdu.choice.initiatingMessage.value.choice.ErrorIndication;

	ie = (RUA_ErrorIndicationIEs_t *)calloc(1, sizeof(RUA_ErrorIndicationIEs_t));
	ie->id = RUA_ProtocolIE_ID_id_CN_DomainIndicator;
	ie->criticality = RUA_Criticality_ignore;
	ie->value.present = RUA_ErrorIndicationIEs__value_PR_Cause;
	ie->value.choice.Cause = *cause;
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	/* optional */
	if (0) {
		ie = (RUA_ErrorIndicationIEs_t *)calloc(1, sizeof(RUA_ErrorIndicationIEs_t));
		ie->id = RUA_ProtocolIE_ID_id_CriticalityDiagnostics;
		ie->criticality = RUA_Criticality_ignore;
		ie->value.present = RUA_ErrorIndicationIEs__value_PR_CriticalityDiagnostics;

		/* TBD */

		ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);
	}

	msg = _rua_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RUA_RUA_PDU, &pdu);

	DEBUGP(DMAIN, "transmitting RUA payload of %u bytes\n", msgb_length(msg));

	msgb_sctp_ppid(msg) = IUH_PPI_RUA;

	return msg;
}
#endif
