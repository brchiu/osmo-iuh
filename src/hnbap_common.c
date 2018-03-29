/* HNBAP common code */

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


#include <stdint.h>

#include <osmocom/core/msgb.h>

#include <osmocom/hnbap/HNBAP-PDU.h>
#include <osmocom/hnbap/hnbap_common.h>
#include <osmocom/iuh/hnbgw.h>

static const struct value_string hnbap_cause_radio_vals[] = {
	{ CauseRadioNetwork_overload,		    "overload" },
	{ CauseRadioNetwork_unauthorised_Location,  "unauthorized location" },
	{ CauseRadioNetwork_unauthorised_HNB,	    "unauthorized HNB" },
	{ CauseRadioNetwork_hNB_parameter_mismatch, "HNB parameter mismatch" },
	{ CauseRadioNetwork_invalid_UE_identity,    "invalid UE identity" },
	{ CauseRadioNetwork_uE_not_allowed_on_this_HNB,
				"UE not allowed on this HNB" },
	{ CauseRadioNetwork_uE_unauthorised,	    "unauthorised UE" },
	{ CauseRadioNetwork_connection_with_UE_lost, "connection with UE lost" },
	{ CauseRadioNetwork_ue_RRC_release,	    "UE RRC release" },
	{ CauseRadioNetwork_hNB_not_registered,	    "HNB not registered" },
	{ CauseRadioNetwork_unspecified,	    "unspecified" },
	{ CauseRadioNetwork_normal,		    "normal" },
	{ CauseRadioNetwork_uE_relocated,	    "UE relocated" },
	{ CauseRadioNetwork_ue_registered_in_another_HNB,
				"UE registered in another HNB" },
	{ 0, NULL }
};

static const struct value_string hnbap_cause_transp_vals[] = {
	{ CauseTransport_transport_resource_unavailable,
				"transport resource unavailable" },
	{ CauseTransport_unspecified, "unspecified" },
	{ 0, NULL }
};

static const struct value_string hnbap_cause_prot_vals[] = {
	{ CauseProtocol_transfer_syntax_error, "syntax error" },
	{ CauseProtocol_abstract_syntax_error_reject,
		"abstract syntax error; reject" },
	{ CauseProtocol_abstract_syntax_error_ignore_and_notify,
		"abstract syntax error; ignore and notify" },
	{ CauseProtocol_message_not_compatible_with_receiver_state,
		"message not compatible with receiver state" },
	{ CauseProtocol_semantic_error, "semantic error" },
	{ CauseProtocol_unspecified, "unspecified" },
	{ CauseProtocol_abstract_syntax_error_falsely_constructed_message,
		"falsely constructed message" },
	{ 0, NULL }
};

static const struct value_string hnbap_cause_misc_vals[] = {
	{ CauseMisc_processing_overload,	"processing overload" },
	{ CauseMisc_hardware_failure,		"hardware failure" },
	{ CauseMisc_o_and_m_intervention,	"OAM intervention" },
	{ CauseMisc_unspecified, 		"unspecified" },
	{ 0, NULL }
};

char *hnbap_cause_str(Cause_t *cause)
{
	static char buf[100];

	switch (cause->present) {
	case Cause_PR_radioNetwork:
		snprintf(buf, sizeof(buf), "radio(%s)",
			 get_value_string(hnbap_cause_radio_vals,
					 cause->choice.radioNetwork));
		break;
	case Cause_PR_transport:
		snprintf(buf, sizeof(buf), "transport(%s)",
			get_value_string(hnbap_cause_transp_vals,
					cause->choice.transport));
		break;
	case Cause_PR_protocol:
		snprintf(buf, sizeof(buf), "protocol(%s)",
			get_value_string(hnbap_cause_prot_vals,
					cause->choice.protocol));
		break;
	case Cause_PR_misc:
		snprintf(buf, sizeof(buf), "misc(%s)",
			get_value_string(hnbap_cause_misc_vals,
					cause->choice.misc));
		break;
	case Cause_PR_NOTHING:
	default:
		memset(buf, 0, sizeof(buf));
		break;
	}
	return buf;
}


int asn_debug = 0;
int asn1_xer_print = 0;

static struct msgb *hnbap_msgb_alloc(void)
{
	return msgb_alloc(1024, "HNBAP Tx");
}

struct msgb *_hnbap_gen_msg(HNBAP_PDU_t *pdu)
{
	struct msgb *msg = hnbap_msgb_alloc();
	asn_enc_rval_t rval;

	if (!msg)
		return NULL;

	rval = aper_encode_to_buffer(&asn_DEF_HNBAP_PDU, NULL, pdu,
				       msg->data, msgb_tailroom(msg));
	if (rval.encoded < 0) {
		LOGP(DHNBAP, LOGL_ERROR, "Error encoding type: %s\n",
				rval.failed_type->name);

	}

	msgb_put(msg, rval.encoded/8);

	return msg;
}
