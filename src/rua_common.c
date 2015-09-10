#include <stdint.h>

#include <osmocom/core/msgb.h>

#include "rua_common.h"
#include "hnbgw.h"

extern int asn1_xer_print;

static const struct value_string rua_cause_radio_vals[] = {
	{ RUA_CauseRadioNetwork_normal,		 "normal" },
	{ RUA_CauseRadioNetwork_connect_failed,	 "connect failed" },
	{ RUA_CauseRadioNetwork_network_release, "network release" },
	{ RUA_CauseRadioNetwork_unspecified,	 "unspecified" },
	{ 0, NULL }
};

static const struct value_string rua_cause_transp_vals[] = {
	{ RUA_CauseTransport_transport_resource_unavailable, "resource unavailable" },
	{ RUA_CauseTransport_unspecified, "unspecified" },
	{ 0, NULL }
};

static const struct value_string rua_cause_prot_vals[] = {
	{ RUA_CauseProtocol_transfer_syntax_error, "syntax error" },
	{ RUA_CauseProtocol_abstract_syntax_error_reject,
		"abstract syntax error; reject" },
	{ RUA_CauseProtocol_abstract_syntax_error_ignore_and_notify,
		"abstract syntax error; ignore and notify" },
	{ RUA_CauseProtocol_message_not_compatible_with_receiver_state,
		"message not compatible with receiver state" },
	{ RUA_CauseProtocol_semantic_error, "semantic error" },
	{ RUA_CauseProtocol_unspecified, "unspecified" },
	{ RUA_CauseProtocol_abstract_syntax_error_falsely_constructed_message,
		"falsely constructed message" },
	{ 0, NULL }
};

static const struct value_string rua_cause_misc_vals[] = {
	{ RUA_CauseMisc_processing_overload,	"processing overload" },
	{ RUA_CauseMisc_hardware_failure,	"hardware failure" },
	{ RUA_CauseMisc_o_and_m_intervention,	"OAM intervention" },
	{ RUA_CauseMisc_unspecified, 		"unspecified" },
	{ 0, NULL }
};

char *rua_cause_str(RUA_Cause_t *cause)
{
	static char buf[32];

	switch (cause->present) {
	case RUA_Cause_PR_radioNetwork:
		snprintf(buf, sizeof(buf), "radio(%s)",
			 get_value_string(rua_cause_radio_vals,
					 cause->choice.radioNetwork));
		break;
	case RUA_Cause_PR_transport:
		snprintf(buf, sizeof(buf), "transport(%s)",
			get_value_string(rua_cause_transp_vals,
					cause->choice.transport));
		break;
	case RUA_Cause_PR_protocol:
		snprintf(buf, sizeof(buf), "protocol(%s)",
			get_value_string(rua_cause_prot_vals,
					cause->choice.protocol));
		break;
	case RUA_Cause_PR_misc:
		snprintf(buf, sizeof(buf), "misc(%s)",
			get_value_string(rua_cause_misc_vals,
					cause->choice.misc));
		break;
	}
	return buf;
}


static struct msgb *rua_msgb_alloc(void)
{
	return msgb_alloc(1024, "RUA Tx");
}

struct msgb *rua_generate_initiating_message(
					e_RUA_ProcedureCode procedureCode,
					RUA_Criticality_t criticality,
					asn_TYPE_descriptor_t * td, void *sptr)
{
	RUA_RUA_PDU_t pdu;
	struct msgb *msg = rua_msgb_alloc();
	asn_enc_rval_t rval;
	ssize_t encoded;

	memset(&pdu, 0, sizeof(pdu));
	pdu.present = RUA_RUA_PDU_PR_initiatingMessage;
	pdu.choice.initiatingMessage.procedureCode = procedureCode;
	pdu.choice.initiatingMessage.criticality = criticality;
	ANY_fromType_aper(&pdu.choice.initiatingMessage.value, td, sptr);

	rval = aper_encode_to_buffer(&asn_DEF_RUA_RUA_PDU, &pdu,
				     msg->data, msgb_tailroom(msg));
	if (rval.encoded < 0) {
		LOGP(DMAIN, LOGL_ERROR, "Error encoding type %s\n", rval.failed_type->name);
		msgb_free(msg);
		return NULL;
	}

	msgb_put(msg, rval.encoded/8);

	return msg;
}

struct msgb *rua_generate_successful_outcome(
					   e_RUA_ProcedureCode procedureCode,
					   RUA_Criticality_t criticality,
					   asn_TYPE_descriptor_t * td,
					   void *sptr)
{

	RUA_RUA_PDU_t pdu;
	struct msgb *msg = rua_msgb_alloc();
	asn_enc_rval_t rval;
	int rc;

	memset(&pdu, 0, sizeof(pdu));
	pdu.present = RUA_RUA_PDU_PR_successfulOutcome;
	pdu.choice.successfulOutcome.procedureCode = procedureCode;
	pdu.choice.successfulOutcome.criticality = criticality;
	rc = ANY_fromType_aper(&pdu.choice.successfulOutcome.value, td, sptr);
	if (rc < 0) {
		LOGP(DMAIN, LOGL_ERROR, "Error in ANY_fromType_aper\n");
		msgb_free(msg);
		return NULL;
	}

	rval = aper_encode_to_buffer(&asn_DEF_RUA_RUA_PDU, &pdu,
				     msg->data, msgb_tailroom(msg));
	if (rval.encoded < 0) {
		LOGP(DMAIN, LOGL_ERROR, "Error encoding type %s\n", rval.failed_type->name);
		msgb_free(msg);
		return NULL;
	}

	msgb_put(msg, rval.encoded/8);

	return msg;
}

#if 0
ssize_t rua_generate_unsuccessful_outcome(uint8_t ** buffer,
					  uint32_t * length,
					  e_RUA_ProcedureCode procedureCode,
					  RUA_Criticality_t criticality,
					  asn_TYPE_descriptor_t * td,
					  void *sptr)
{

	RUA_RUA_PDU_t pdu;
	ssize_t encoded;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = RUA_RUA_PDU_PR_unsuccessfulOutcome;
	pdu.choice.successfulOutcome.procedureCode = procedureCode;
	pdu.choice.successfulOutcome.criticality = criticality;
	ANY_fromType_aper(&pdu.choice.successfulOutcome.value, td, sptr);

	if ((encoded =
	     aper_encode_to_new_buffer(&asn_DEF_RUA_RUA_PDU, 0, &pdu,
				       (void **)buffer)) < 0) {
		return -1;
	}

	*length = encoded;

	return encoded;
}
#endif

RUA_IE_t *rua_new_ie(RUA_ProtocolIE_ID_t id,
		     RUA_Criticality_t criticality,
		     asn_TYPE_descriptor_t * type, void *sptr)
{

	RUA_IE_t *buff;

	if ((buff = malloc(sizeof(*buff))) == NULL) {
		// Possible error on malloc
		return NULL;
	}
	memset((void *)buff, 0, sizeof(*buff));

	buff->id = id;
	buff->criticality = criticality;

	ANY_fromType_aper(&buff->value, type, sptr);

	if (asn1_xer_print)
		if (xer_fprint(stdout, &asn_DEF_RUA_IE, buff) < 0) {
			free(buff);
			return NULL;
		}

	return buff;
}
