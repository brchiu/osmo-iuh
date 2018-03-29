/* high-level RANAP messsage generation code */

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

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>

#include "asn1helpers.h"
#include <osmocom/ranap/iu_helpers.h>

#include <osmocom/ranap/ranap_common.h>
#include <osmocom/ranap/ranap_msg_factory.h>

#define DRANAP _ranap_DRANAP

/*! \brief allocate a new long and assing a value to it */
static long *new_long(long in)
{
	long *out = CALLOC(1, sizeof(long));
	*out = in;
	return out;
}

/*! \brief generate RANAP RESET message */
struct msgb *ranap_new_msg_reset(RANAP_CN_DomainIndicator_t domain,
				 const RANAP_Cause_t *cause)
{
	RANAP_RANAP_PDU_t pdu;
	RANAP_Reset_t *out;
	RANAP_ResetIEs_t *ie;
	struct msgb *msg;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = RANAP_RANAP_PDU_PR_initiatingMessage;
	pdu.choice.initiatingMessage.procedureCode = RANAP_id_Reset;
	pdu.choice.initiatingMessage.criticality = RANAP_Criticality_reject;
	pdu.choice.initiatingMessage.value.present = RANAP_InitiatingMessage__value_PR_Reset;

	out = &pdu.choice.initiatingMessage.value.choice.Reset;

	ie = (RANAP_ResetIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = RANAP_id_Cause;
	ie->criticality = RANAP_Criticality_ignore;
	ie->value.present = RANAP_ResetIEs__value_PR_Cause;
	memcpy(&ie->value.choice.Cause, cause, sizeof(*cause));
	ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

	msg = _ranap_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RANAP_PDU, &pdu);

	return msg;
}

/*! \brief generate RANAP RESET ACK message */
struct msgb *ranap_new_msg_reset_ack(RANAP_CN_DomainIndicator_t domain,
				     RANAP_GlobalRNC_ID_t *rnc_id)
{
	RANAP_RANAP_PDU_t pdu;
	RANAP_ResetAcknowledge_t *out;
	RANAP_ResetAcknowledgeIEs_t *ie;
	struct msgb *msg;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = RANAP_RANAP_PDU_PR_successfulOutcome;
	pdu.choice.successfulOutcome.procedureCode = RANAP_id_Reset;
	pdu.choice.successfulOutcome.criticality = RANAP_Criticality_reject;
	pdu.choice.successfulOutcome.value.present = RANAP_SuccessfulOutcome__value_PR_ResetAcknowledge;

	out = &pdu.choice.successfulOutcome.value.choice.ResetAcknowledge;

	ie = (RANAP_ResetAcknowledgeIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = RANAP_id_CN_DomainIndicator;
	ie->criticality = RANAP_Criticality_reject;
	ie->value.present = RANAP_ResetAcknowledgeIEs__value_PR_CN_DomainIndicator;
	ie->value.choice.CN_DomainIndicator = domain;
	ASN_SEQUENCE_ADD(&(out->protocolIEs.list), ie);

	/* The RNC shall include the globalRNC_ID in the RESET
	 * ACKNOWLEDGE message to the CN */
	if (rnc_id) {
		ie = (RANAP_ResetAcknowledgeIEs_t *)CALLOC(1, sizeof(*ie));
		ie->id = RANAP_id_GlobalRNC_ID;
		ie->criticality = RANAP_Criticality_reject;
		ie->value.present = RANAP_ResetAcknowledgeIEs__value_PR_GlobalRNC_ID;
		OCTET_STRING_noalloc(&ie->value.choice.GlobalRNC_ID.pLMNidentity,
				     rnc_id->pLMNidentity.buf,
				     rnc_id->pLMNidentity.size);
		ie->value.choice.GlobalRNC_ID.rNC_ID = rnc_id->rNC_ID;;
		ASN_SEQUENCE_ADD(&(out->protocolIEs.list), ie);
	}

	msg = _ranap_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RANAP_PDU, &pdu);

	return msg;
}

/*! \brief generate RANAP INITIAL UE message */
struct msgb *ranap_new_msg_initial_ue(uint32_t conn_id, int is_ps,
				     RANAP_GlobalRNC_ID_t *rnc_id,
				     uint8_t *nas_pdu, unsigned int nas_len)
{
	RANAP_RANAP_PDU_t pdu;
	RANAP_InitialUE_Message_t *out;
	RANAP_InitialUE_MessageIEs_t *ie;
	uint32_t ctxidbuf;
	uint16_t buf0 = 0x2342;
	struct msgb *msg;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = RANAP_RANAP_PDU_PR_initiatingMessage;
	pdu.choice.initiatingMessage.procedureCode = RANAP_id_InitialUE_Message;
	pdu.choice.initiatingMessage.criticality = RANAP_Criticality_reject;
	pdu.choice.initiatingMessage.value.present = RANAP_InitiatingMessage__value_PR_InitialUE_Message;

	out = &pdu.choice.initiatingMessage.value.choice.InitialUE_Message;

	ie = (RANAP_InitialUE_MessageIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = RANAP_id_CN_DomainIndicator;
	ie->criticality = RANAP_Criticality_ignore;
	ie->value.present = RANAP_InitialUE_MessageIEs__value_PR_CN_DomainIndicator;
	ie->value.choice.CN_DomainIndicator = is_ps ? RANAP_CN_DomainIndicator_ps_domain :
						      RANAP_CN_DomainIndicator_cs_domain;
	ASN_SEQUENCE_ADD(&(out->protocolIEs.list), ie);

	ie = (RANAP_InitialUE_MessageIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = RANAP_id_LAI;
	ie->criticality = RANAP_Criticality_ignore;
	ie->value.present = RANAP_InitialUE_MessageIEs__value_PR_LAI;
	OCTET_STRING_noalloc(&ie->value.choice.LAI.pLMNidentity, rnc_id->pLMNidentity.buf, rnc_id->pLMNidentity.size);
	OCTET_STRING_noalloc(&ie->value.choice.LAI.lAC, (uint8_t *)&buf0, sizeof(buf0));
	ASN_SEQUENCE_ADD(&(out->protocolIEs.list), ie);

	if (is_ps) {
		ie = (RANAP_InitialUE_MessageIEs_t *)CALLOC(1, sizeof(*ie));
		ie->id = RANAP_id_RAC;
		ie->criticality = RANAP_Criticality_ignore;
		ie->value.present = RANAP_InitialUE_MessageIEs__value_PR_RAC;
		// ie->value.choice.RAC = ;
		ASN_SEQUENCE_ADD(&(out->protocolIEs.list), ie);
	}

	ie = (RANAP_InitialUE_MessageIEs_t *)CALLOC(1, sizeof(RANAP_InitialUE_MessageIEs_t));
	ie->id = RANAP_id_SAI;
	ie->criticality = RANAP_Criticality_ignore;
	ie->value.present = RANAP_InitialUE_MessageIEs__value_PR_SAI;
	OCTET_STRING_noalloc(&ie->value.choice.SAI.pLMNidentity, rnc_id->pLMNidentity.buf, rnc_id->pLMNidentity.size);
	OCTET_STRING_noalloc(&ie->value.choice.SAI.lAC, (uint8_t *)&buf0, sizeof(buf0));
	OCTET_STRING_noalloc(&ie->value.choice.SAI.sAC, (uint8_t *)&buf0, sizeof(buf0));
	ASN_SEQUENCE_ADD(&(out->protocolIEs.list), ie);

	ie = (RANAP_InitialUE_MessageIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = RANAP_id_NAS_PDU;
	ie->criticality = RANAP_Criticality_ignore;
	ie->value.present = RANAP_InitialUE_MessageIEs__value_PR_NAS_PDU;
	OCTET_STRING_noalloc(&ie->value.choice.NAS_PDU, nas_pdu, nas_len);
	ASN_SEQUENCE_ADD(&(out->protocolIEs.list), ie);

	ie = (RANAP_InitialUE_MessageIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = RANAP_id_IuSigConId;
	ie->criticality = RANAP_Criticality_ignore;
	ie->value.present = RANAP_InitialUE_MessageIEs__value_PR_IuSignallingConnectionIdentifier;
	asn1_u24_to_bitstring(&ie->value.choice.IuSignallingConnectionIdentifier, &ctxidbuf, conn_id);
	ASN_SEQUENCE_ADD(&(out->protocolIEs.list), ie);

	ie = (RANAP_InitialUE_MessageIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = RANAP_id_GlobalRNC_ID;
	ie->criticality = RANAP_Criticality_ignore;
	ie->value.present = RANAP_InitialUE_MessageIEs__value_PR_GlobalRNC_ID;
	OCTET_STRING_noalloc(&ie->value.choice.GlobalRNC_ID.pLMNidentity,
			     rnc_id->pLMNidentity.buf,rnc_id->pLMNidentity.size);
	ie->value.choice.GlobalRNC_ID.rNC_ID = rnc_id->rNC_ID;
	ASN_SEQUENCE_ADD(&(out->protocolIEs.list), ie);

	msg = _ranap_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RANAP_PDU, &pdu);

	return msg;
}


/*! \brief generate RANAP DIRECT TRANSFER message */
struct msgb *ranap_new_msg_dt(uint8_t sapi, const uint8_t *nas, unsigned int nas_len)
{
	RANAP_RANAP_PDU_t pdu;
	RANAP_DirectTransfer_t *out;
	RANAP_DirectTransferIEs_t *ie;
	struct msgb *msg;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = RANAP_RANAP_PDU_PR_initiatingMessage;
	pdu.choice.initiatingMessage.procedureCode = RANAP_id_DirectTransfer;
	pdu.choice.initiatingMessage.criticality = RANAP_Criticality_reject;
	pdu.choice.initiatingMessage.value.present = RANAP_InitiatingMessage__value_PR_DirectTransfer;

	out = &pdu.choice.initiatingMessage.value.choice.DirectTransfer;

	ie = (RANAP_DirectTransferIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = RANAP_id_NAS_PDU;
	ie->criticality = RANAP_Criticality_ignore;
	ie->value.present = RANAP_DirectTransferIEs__value_PR_NAS_PDU;
	/* Avoid copying + later freeing of OCTET STRING */
	OCTET_STRING_noalloc(&ie->value.choice.NAS_PDU, nas, nas_len);
	ASN_SEQUENCE_ADD(&(out->protocolIEs.list), ie);

	ie = (RANAP_DirectTransferIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = RANAP_id_SAPI;
	ie->criticality = RANAP_Criticality_ignore;
	ie->value.present = RANAP_DirectTransferIEs__value_PR_SAPI;
	ie->value.choice.SAPI = sapi == 3 ? RANAP_SAPI_sapi_3 : RANAP_SAPI_sapi_0;
	ASN_SEQUENCE_ADD(&(out->protocolIEs.list), ie);

	msg = _ranap_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RANAP_PDU, &pdu);

	return msg;
}

static const enum RANAP_IntegrityProtectionAlgorithm ip_alg[2] = {
	RANAP_IntegrityProtectionAlgorithm_standard_UMTS_integrity_algorithm_UIA1,
	RANAP_IntegrityProtectionAlgorithm_standard_UMTS_integrity_algorithm_UIA2,
};

static const RANAP_EncryptionAlgorithm_t enc_alg[2] = {
	RANAP_EncryptionAlgorithm_standard_UMTS_encryption_algorith_UEA1,
	RANAP_EncryptionAlgorithm_standard_UMTS_encryption_algorithm_UEA2,
};

/*! \brief generate RANAP SECURITY MODE COMMAND message */
struct msgb *ranap_new_msg_sec_mod_cmd(const uint8_t *ik, const uint8_t *ck, enum RANAP_KeyStatus status)
{
	RANAP_RANAP_PDU_t pdu;
	RANAP_SecurityModeCommand_t *out;
	RANAP_SecurityModeCommandIEs_t *ie;
	struct msgb *msg;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = RANAP_RANAP_PDU_PR_initiatingMessage;
	pdu.choice.initiatingMessage.procedureCode = RANAP_id_SecurityModeControl;
	pdu.choice.initiatingMessage.criticality = RANAP_Criticality_reject;
	pdu.choice.initiatingMessage.value.present = RANAP_InitiatingMessage__value_PR_SecurityModeCommand;

	out = &pdu.choice.initiatingMessage.value.choice.SecurityModeCommand;

	ie = (RANAP_SecurityModeCommandIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = RANAP_id_IntegrityProtectionInformation;
	ie->criticality = RANAP_Criticality_reject;
	ie->value.present = RANAP_SecurityModeCommandIEs__value_PR_IntegrityProtectionInformation;

	for (int i = 0; i < ARRAY_SIZE(ip_alg); i++) {
		/* needs to be dynamically allocated, as
		 * SET_OF_free() will call FREEMEM() on it */
		RANAP_IntegrityProtectionAlgorithm_t *alg = CALLOC(1, sizeof(*alg));
		*alg = ip_alg[i];
		ASN_SEQUENCE_ADD(&(ie->value.choice.IntegrityProtectionInformation), alg);
	}
	BIT_STRING_fromBuf(&ie->value.choice.IntegrityProtectionInformation.key, ik, 16*8);

	ASN_SEQUENCE_ADD(&(out->protocolIEs.list), ie);

	if (ck) {
		ie = (RANAP_SecurityModeCommandIEs_t *)CALLOC(1, sizeof(*ie));
		ie->id = RANAP_id_EncryptionInformation;
		ie->criticality = RANAP_Criticality_ignore;
		ie->value.present = RANAP_SecurityModeCommandIEs__value_PR_EncryptionInformation;
		for (int i = 0; i < ARRAY_SIZE(ip_alg); i++) {
			/* needs to be dynamically allocated, as
			 * SET_OF_free() will call FREEMEM() on it */
			RANAP_EncryptionAlgorithm_t *alg = CALLOC(1, sizeof(*alg));
			*alg = enc_alg[i];
			ASN_SEQUENCE_ADD(&(ie->value.choice.EncryptionInformation), alg);
		}
		BIT_STRING_fromBuf(&ie->value.choice.EncryptionInformation.key, ck, 16*8);

		ASN_SEQUENCE_ADD(&(out->protocolIEs.list), ie);
	}

	ie = (RANAP_SecurityModeCommandIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = RANAP_id_KeyStatus;
	ie->criticality = RANAP_Criticality_reject;
	ie->value.present = RANAP_SecurityModeCommandIEs__value_PR_KeyStatus;
	ie->value.choice.KeyStatus = status;
	ASN_SEQUENCE_ADD(&(out->protocolIEs.list), ie);

	msg = _ranap_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RANAP_PDU, &pdu);

	return msg;
}

/*! \brief generate RANAP SECURITY MODE COMPLETE message */
struct msgb *ranap_new_msg_sec_mod_compl(
	RANAP_ChosenIntegrityProtectionAlgorithm_t chosen_ip_alg,
	RANAP_ChosenEncryptionAlgorithm_t chosen_enc_alg)
{
	RANAP_RANAP_PDU_t pdu;
	RANAP_SecurityModeComplete_t *out;
	RANAP_SecurityModeCompleteIEs_t *ie;
	struct msgb *msg;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = RANAP_RANAP_PDU_PR_successfulOutcome;
	pdu.choice.successfulOutcome.procedureCode = RANAP_id_SecurityModeControl;
	pdu.choice.successfulOutcome.criticality = RANAP_Criticality_reject;
	pdu.choice.successfulOutcome.value.present = RANAP_SuccessfulOutcome__value_PR_SecurityModeComplete;

	out = &pdu.choice.successfulOutcome.value.choice.SecurityModeComplete;

	ie = (RANAP_SecurityModeCompleteIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = RANAP_id_ChosenIntegrityProtectionAlgorithm;
	ie->criticality = RANAP_Criticality_reject;
	ie->value.present = RANAP_SecurityModeCompleteIEs__value_PR_ChosenIntegrityProtectionAlgorithm;
	ie->value.choice.ChosenIntegrityProtectionAlgorithm = chosen_ip_alg;
	ASN_SEQUENCE_ADD(&(out->protocolIEs.list), ie);

	ie = (RANAP_SecurityModeCompleteIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = RANAP_id_ChosenEncryptionAlgorithm;
	ie->criticality = RANAP_Criticality_ignore;
	ie->value.present = RANAP_SecurityModeCompleteIEs__value_PR_ChosenEncryptionAlgorithm;
	ie->value.choice.ChosenIntegrityProtectionAlgorithm = chosen_enc_alg;
	ASN_SEQUENCE_ADD(&(out->protocolIEs.list), ie);

	msg = _ranap_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RANAP_PDU, &pdu);

	return msg;
}

/*! \brief generate RANAP COMMON ID message */
struct msgb *ranap_new_msg_common_id(const char *imsi)
{
	RANAP_RANAP_PDU_t pdu;
	RANAP_CommonID_t *out;
	RANAP_CommonID_IEs_t *ie;
	struct msgb *msg;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = RANAP_RANAP_PDU_PR_initiatingMessage;
	pdu.choice.initiatingMessage.procedureCode = RANAP_id_SecurityModeControl;
	pdu.choice.initiatingMessage.criticality = RANAP_Criticality_ignore;
	pdu.choice.initiatingMessage.value.present = RANAP_InitiatingMessage__value_PR_CommonID;

	out = &pdu.choice.initiatingMessage.value.choice.CommonID;

	ie = (RANAP_CommonID_IEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = RANAP_id_PermanentNAS_UE_ID;
	ie->criticality = RANAP_Criticality_ignore;
	ie->value.present = RANAP_CommonID_IEs__value_PR_PermanentNAS_UE_ID;

	if (imsi) {
		uint8_t *imsi_buf = CALLOC(1, 16);
		int rc;
		rc = ranap_imsi_encode(imsi_buf, 16, imsi);
		ie->value.choice.PermanentNAS_UE_ID.present = RANAP_PermanentNAS_UE_ID_PR_iMSI;
		ie->value.choice.PermanentNAS_UE_ID.choice.iMSI.buf = imsi_buf;
		ie->value.choice.PermanentNAS_UE_ID.choice.iMSI.size = rc;
	} else {
		ie->value.choice.PermanentNAS_UE_ID.present = RANAP_PermanentNAS_UE_ID_PR_NOTHING;
	}

	ASN_SEQUENCE_ADD(&(out->protocolIEs.list), ie);

	msg = _ranap_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RANAP_PDU, &pdu);

	return msg;
}

/*! \brief generate RANAP IU RELEASE COMMAND message */
struct msgb *ranap_new_msg_iu_rel_cmd(const RANAP_Cause_t *cause_in)
{
	RANAP_RANAP_PDU_t pdu;
	RANAP_Iu_ReleaseCommand_t *out;
	RANAP_Iu_ReleaseCommandIEs_t *ie;
	struct msgb *msg;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = RANAP_RANAP_PDU_PR_initiatingMessage;
	pdu.choice.initiatingMessage.procedureCode = RANAP_id_Iu_Release;
	pdu.choice.initiatingMessage.criticality = RANAP_Criticality_ignore;
	pdu.choice.initiatingMessage.value.present = RANAP_InitiatingMessage__value_PR_Iu_ReleaseCommand;

	out = &pdu.choice.initiatingMessage.value.choice.Iu_ReleaseCommand;

	ie = (RANAP_Iu_ReleaseCommandIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = RANAP_id_Cause;
	ie->criticality = RANAP_Criticality_ignore;
	ie->value.present = RANAP_Iu_ReleaseCommandIEs__value_PR_Cause;
	memcpy(&ie->value.choice.Cause, cause_in, sizeof(*cause_in));

	ASN_SEQUENCE_ADD(&(out->protocolIEs.list), ie);

	msg = _ranap_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RANAP_PDU, &pdu);

	return msg;
}

/*! \brief generate RAPAP IU RELEASE COMPLETE message */
struct msgb *ranap_new_msg_iu_rel_compl(void)
{
	RANAP_RANAP_PDU_t pdu;
	struct msgb *msg;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = RANAP_RANAP_PDU_PR_successfulOutcome;
	pdu.choice.successfulOutcome.procedureCode = RANAP_id_Iu_Release;
	pdu.choice.successfulOutcome.criticality = RANAP_Criticality_ignore;
	pdu.choice.successfulOutcome.value.present = RANAP_SuccessfulOutcome__value_PR_Iu_ReleaseComplete;

	msg = _ranap_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RANAP_PDU, &pdu);

	return msg;
}

/*! \brief generate RANAP PAGING COMMAND message */
struct msgb *ranap_new_msg_paging_cmd(const char *imsi, const uint32_t *tmsi, int is_ps, uint32_t cause)
{
	RANAP_RANAP_PDU_t pdu;
	RANAP_Paging_t *out;
	RANAP_PagingIEs_t *ie;
	struct msgb *msg;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = RANAP_RANAP_PDU_PR_initiatingMessage;
	pdu.choice.initiatingMessage.procedureCode = RANAP_id_Paging;
	pdu.choice.initiatingMessage.criticality = RANAP_Criticality_ignore;
	pdu.choice.initiatingMessage.value.present = RANAP_InitiatingMessage__value_PR_Paging;

	out = &pdu.choice.initiatingMessage.value.choice.Paging;

	ie = (RANAP_PagingIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = RANAP_id_CN_DomainIndicator;
	ie->criticality = RANAP_Criticality_ignore;
	ie->value.present = RANAP_InitialUE_MessageIEs__value_PR_CN_DomainIndicator;
	ie->value.choice.CN_DomainIndicator = is_ps ? RANAP_CN_DomainIndicator_ps_domain : RANAP_CN_DomainIndicator_cs_domain;
	ASN_SEQUENCE_ADD(&(out->protocolIEs.list), ie);

	ie = (RANAP_PagingIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = RANAP_id_PermanentNAS_UE_ID;
	ie->criticality = RANAP_Criticality_ignore;
	ie->value.present = RANAP_CommonID_IEs__value_PR_PermanentNAS_UE_ID;
	ie->value.choice.PermanentNAS_UE_ID.present = RANAP_PermanentNAS_UE_ID_PR_iMSI;
	ie->value.choice.PermanentNAS_UE_ID.choice.iMSI.buf = CALLOC(1, 16);
	ie->value.choice.PermanentNAS_UE_ID.choice.iMSI.size = 8;
	ranap_imsi_encode(ie->value.choice.PermanentNAS_UE_ID.choice.iMSI.buf, 16, imsi);
	ASN_SEQUENCE_ADD(&(out->protocolIEs.list), ie);

	if (tmsi) {
		uint32_t *tmsi_buf = CALLOC(1, sizeof(*tmsi_buf));

		ie = (RANAP_PagingIEs_t *)CALLOC(1, sizeof(*ie));
		ie->id = RANAP_id_TemporaryUE_ID;
		ie->criticality = RANAP_Criticality_ignore;
		ie->value.present = RANAP_PagingIEs__value_PR_TemporaryUE_ID;

		if (is_ps) {
			ie->value.choice.TemporaryUE_ID.present = RANAP_TemporaryUE_ID_PR_p_TMSI;
			asn1_u32_to_str(&ie->value.choice.TemporaryUE_ID.choice.p_TMSI, tmsi_buf, *tmsi);
		} else {
			ie->value.choice.TemporaryUE_ID.present = RANAP_TemporaryUE_ID_PR_tMSI;
			asn1_u32_to_str(&ie->value.choice.TemporaryUE_ID.choice.tMSI, tmsi_buf, *tmsi);
		}
		ASN_SEQUENCE_ADD(&(out->protocolIEs.list), ie);
	}

	if (cause) {
		ie = (RANAP_PagingIEs_t *)CALLOC(1, sizeof(*ie));
		ie->id = RANAP_id_PermanentNAS_UE_ID;
		ie->criticality = RANAP_Criticality_ignore;
		ie->value.present = RANAP_PagingIEs__value_PR_PagingCause;
		ie->value.choice.PagingCause = cause;
		ASN_SEQUENCE_ADD(&(out->protocolIEs.list), ie);
	}

	msg = _ranap_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RANAP_PDU, &pdu);

	return msg;
}

static RANAP_SDU_ErrorRatio_t *new_sdu_error_ratio(long mantissa, long exponent)
{
	RANAP_SDU_ErrorRatio_t *err = CALLOC(1, sizeof(*err));

	err->mantissa = mantissa;
	err->exponent = exponent;

	return err;
}


static struct RANAP_SDU_FormatInformationParameters__Member *
new_format_info_pars(long sdu_size)
{
	struct RANAP_SDU_FormatInformationParameters__Member *fmti = CALLOC(1, sizeof(*fmti));
	fmti->subflowSDU_Size = new_long(sdu_size);
	return fmti;
}

enum sdu_par_profile {
	SDUPAR_P_VOICE0,
	SDUPAR_P_VOICE1,
	SDUPAR_P_VOICE2,
	SDUPAR_P_DATA,
};

/* See Chapter 5 of TS 26.102 */
static struct RANAP_SDU_Parameters__Member *new_sdu_par_item(enum sdu_par_profile profile)
{
	struct RANAP_SDU_Parameters__Member *sdui = CALLOC(1, sizeof(*sdui));
	RANAP_SDU_FormatInformationParameters_t *fmtip = CALLOC(1, sizeof(*fmtip));
	struct RANAP_SDU_FormatInformationParameters__Member *fmti;

	switch (profile) {
	case SDUPAR_P_VOICE0:
		sdui->sDU_ErrorRatio = new_sdu_error_ratio(1, 5);
		sdui->residualBitErrorRatio.mantissa = 1;
		sdui->residualBitErrorRatio.exponent = 6;
		sdui->deliveryOfErroneousSDU = RANAP_DeliveryOfErroneousSDU_yes;
		sdui->sDU_FormatInformationParameters = fmtip;
		fmti = new_format_info_pars(81);
		ASN_SEQUENCE_ADD(fmtip, fmti);
		fmti = new_format_info_pars(39);
		ASN_SEQUENCE_ADD(&(fmtip->list), fmti);
		/* FIXME: could be 10 SDU descriptors for AMR! */
		break;
	case SDUPAR_P_VOICE1:
		sdui->residualBitErrorRatio.mantissa = 1;
		sdui->residualBitErrorRatio.exponent = 3;
		sdui->deliveryOfErroneousSDU = RANAP_DeliveryOfErroneousSDU_no_error_detection_consideration;
		sdui->sDU_FormatInformationParameters = fmtip;
		fmti = new_format_info_pars(103);
		ASN_SEQUENCE_ADD(fmtip, fmti);
		fmti = new_format_info_pars(0);
		ASN_SEQUENCE_ADD(&(fmtip->list), fmti);
		/* FIXME: could be 10 SDU descriptors for AMR! */
		break;
	case SDUPAR_P_VOICE2:
		sdui->residualBitErrorRatio.mantissa = 5;
		sdui->residualBitErrorRatio.exponent = 3;
		sdui->deliveryOfErroneousSDU = RANAP_DeliveryOfErroneousSDU_no_error_detection_consideration;
		sdui->sDU_FormatInformationParameters = fmtip;
		fmti = new_format_info_pars(60);
		ASN_SEQUENCE_ADD(fmtip, fmti);
		fmti = new_format_info_pars(0);
		ASN_SEQUENCE_ADD(&(fmtip->list), fmti);
		/* FIXME: could be 10 SDU descriptors for AMR! */
		break;
	case SDUPAR_P_DATA:
		sdui->sDU_ErrorRatio = new_sdu_error_ratio(1, 4);
		sdui->residualBitErrorRatio.mantissa = 1;
		sdui->residualBitErrorRatio.exponent = 5;
		sdui->deliveryOfErroneousSDU = RANAP_DeliveryOfErroneousSDU_no;
		FREEMEM(fmtip);
		break;
	}

	return sdui;
}

static RANAP_AllocationOrRetentionPriority_t *
new_alloc_ret_prio(RANAP_PriorityLevel_t level, int capability, int vulnerability,
		   int queueing_allowed)
{
	RANAP_AllocationOrRetentionPriority_t *arp = CALLOC(1, sizeof(*arp));

	arp->priorityLevel = level;

	if (capability)
		arp->pre_emptionCapability = RANAP_Pre_emptionCapability_may_trigger_pre_emption;
	else
		arp->pre_emptionCapability = RANAP_Pre_emptionCapability_shall_not_trigger_pre_emption;

	if (vulnerability)
		arp->pre_emptionVulnerability = RANAP_Pre_emptionVulnerability_pre_emptable;
	else
		arp->pre_emptionVulnerability = RANAP_Pre_emptionVulnerability_not_pre_emptable;

	if (queueing_allowed)
		arp->queuingAllowed = RANAP_QueuingAllowed_queueing_allowed;
	else
		arp->queuingAllowed = RANAP_QueuingAllowed_queueing_not_allowed;

	return arp;
}

/* See Chapter 5 of TS 26.102 */
static RANAP_RAB_Parameters_t *new_rab_par_voice(long bitrate_guaranteed,
						 long bitrate_max)
{
	RANAP_RAB_Parameters_t *rab = CALLOC(1, sizeof(*rab));
	struct RANAP_SDU_Parameters__Member *sdui;

	rab->trafficClass = RANAP_TrafficClass_conversational;
	rab->rAB_AsymmetryIndicator = RANAP_RAB_AsymmetryIndicator_symmetric_bidirectional;

	ASN_SEQUENCE_ADD(&rab->maxBitrate.list, new_long(bitrate_max));
	rab->guaranteedBitRate = CALLOC(1, sizeof(*rab->guaranteedBitRate));
	ASN_SEQUENCE_ADD(rab->guaranteedBitRate, new_long(bitrate_guaranteed));
	rab->deliveryOrder = RANAP_DeliveryOrder_delivery_order_requested;
	rab->maxSDU_Size = 244;

	sdui = new_sdu_par_item(SDUPAR_P_VOICE0);
	ASN_SEQUENCE_ADD(&rab->sDU_Parameters.list, sdui);
	sdui = new_sdu_par_item(SDUPAR_P_VOICE1);
	ASN_SEQUENCE_ADD(&rab->sDU_Parameters.list, sdui);
	sdui = new_sdu_par_item(SDUPAR_P_VOICE2);
	ASN_SEQUENCE_ADD(&rab->sDU_Parameters.list, sdui);

	rab->transferDelay = new_long(80);
	rab->allocationOrRetentionPriority = new_alloc_ret_prio(RANAP_PriorityLevel_no_priority, 0, 1, 0);

	rab->sourceStatisticsDescriptor = new_long(RANAP_SourceStatisticsDescriptor_speech);

	return rab;
}

static RANAP_NAS_SynchronisationIndicator_t *new_rab_nas_sync_ind(int val)
{
	uint8_t val_buf = (val / 10) << 4;
	RANAP_NAS_SynchronisationIndicator_t *nsi = CALLOC(1, sizeof(*nsi));
	BIT_STRING_fromBuf(nsi, &val_buf, 4);
	return nsi;
}

static RANAP_RAB_Parameters_t *new_rab_par_data(uint32_t dl_max_bitrate, uint32_t ul_max_bitrate)
{
	RANAP_RAB_Parameters_t *rab = CALLOC(1, sizeof(*rab));
	struct RANAP_SDU_Parameters__Member *sdui;
	RANAP_RAB_Parameters_ExtIEs_t *ie;

	rab->trafficClass = RANAP_TrafficClass_background;
	rab->rAB_AsymmetryIndicator = RANAP_RAB_AsymmetryIndicator_asymmetric_bidirectional;

	ASN_SEQUENCE_ADD(&rab->maxBitrate.list, new_long(dl_max_bitrate));
	ASN_SEQUENCE_ADD(&rab->maxBitrate.list, new_long(ul_max_bitrate));
	rab->deliveryOrder = RANAP_DeliveryOrder_delivery_order_requested;
	rab->maxSDU_Size = 8000;

	sdui = new_sdu_par_item(SDUPAR_P_DATA);
	ASN_SEQUENCE_ADD(&rab->sDU_Parameters.list, sdui);

	rab->allocationOrRetentionPriority = new_alloc_ret_prio(RANAP_PriorityLevel_no_priority, 0, 0, 0);

	rab->iE_Extensions = (struct RANAP_ProtocolExtensionContainer *)CALLOC(1, sizeof(RANAP_ProtocolExtensionContainer_7796P173_t));

	ie = (RANAP_RAB_Parameters_ExtIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = RANAP_id_RAB_Parameter_ExtendedMaxBitrateList;
	ie->criticality = RANAP_Criticality_ignore;
	ie->extensionValue.present = RANAP_RAB_Parameters_ExtIEs__extensionValue_PR_RAB_Parameter_ExtendedMaxBitrateList;

	RANAP_ExtendedMaxBitrate_t *xmbr = CALLOC(1, sizeof(*xmbr));
	*xmbr = 42000000;
	ASN_SEQUENCE_ADD(&ie->extensionValue.choice.RAB_Parameter_ExtendedMaxBitrateList.list, xmbr);

	ASN_SEQUENCE_ADD(&((RANAP_ProtocolExtensionContainer_7796P173_t *)rab->iE_Extensions)->list, ie);

	return rab;
}

static void new_transp_layer_addr(BIT_STRING_t *out, uint32_t ip, bool use_x213_nsap)
{
	uint8_t *buf;
	unsigned int len;
	uint32_t ip_h = ntohl(ip);

	if (use_x213_nsap) {
		len = 160/8;
		buf = CALLOC(len, sizeof(uint8_t));
		buf[0] = 0x35;	/* AFI For IANA ICP */
		buf[1] = 0x00;	/* See A.5.2.1.2.7 of X.213 */
		buf[2] = 0x01;
		memcpy(&buf[3], &ip_h, sizeof(ip_h));
	} else {
		len = sizeof(ip_h);
		buf = CALLOC(len, sizeof(uint8_t));
		memcpy(buf, &ip_h, sizeof(ip_h));
	}
	out->buf = buf;
	out->size = len;
	out->bits_unused = 0;
}

static RANAP_TransportLayerInformation_t *new_transp_info_rtp(uint32_t ip, uint16_t port,
							      bool use_x213_nsap)
{
	RANAP_TransportLayerInformation_t *tli = CALLOC(1, sizeof(*tli));
	uint8_t binding_id[4];

	binding_id[0] = port >> 8;
	binding_id[1] = port & 0xff;
	binding_id[2] = binding_id[3] = 0;

	new_transp_layer_addr(&tli->transportLayerAddress, ip, use_x213_nsap);
	tli->iuTransportAssociation.present = RANAP_IuTransportAssociation_PR_bindingID;
	OCTET_STRING_fromBuf(&tli->iuTransportAssociation.choice.bindingID,
				(const char *) binding_id, sizeof(binding_id));

	return tli;
}

static RANAP_TransportLayerInformation_t *new_transp_info_gtp(uint32_t ip, uint32_t tei,
							      bool use_x213_nsap)
{
	RANAP_TransportLayerInformation_t *tli = CALLOC(1, sizeof(*tli));
	uint32_t binding_buf = htonl(tei);

	new_transp_layer_addr(&tli->transportLayerAddress, ip, use_x213_nsap);
	tli->iuTransportAssociation.present = RANAP_IuTransportAssociation_PR_gTP_TEI;
	OCTET_STRING_fromBuf(&tli->iuTransportAssociation.choice.gTP_TEI,
			     (const char *) &binding_buf, sizeof(binding_buf));

	return tli;
}

static RANAP_UserPlaneInformation_t *new_upi(long mode, uint8_t mode_versions)
{
	RANAP_UserPlaneInformation_t *upi = CALLOC(1, sizeof(*upi));
	uint16_t *buf = CALLOC(1, sizeof(*buf));

	*buf = ntohs(mode_versions);

	upi->userPlaneMode = mode;
	upi->uP_ModeVersions.buf = (uint8_t *) buf;
	upi->uP_ModeVersions.size = sizeof(*buf);
	upi->uP_ModeVersions.bits_unused = 0;

	return upi;
}


static void assign_new_ra_id(RANAP_RAB_ID_t *id, uint8_t rab_id)
{
	uint8_t *buf = CALLOC(1, sizeof(*buf));
	*buf = rab_id;

	id->buf = buf;
	id->size = 1;
	id->bits_unused = 0;
}

/*! \brief generate RANAP RAB ASSIGNMENT REQUEST message for CS (voice).
 * See 3GPP TS 25.413 8.2.
 * RAB ID: 3GPP TS 25.413 9.2.1.2.
 * \param rtp_ip  MGW's RTP IPv4 address in *network* byte order.
 */
struct msgb *ranap_new_msg_rab_assign_voice(uint8_t rab_id, uint32_t rtp_ip,
					    uint16_t rtp_port,
					    bool use_x213_nsap)
{
	RANAP_RANAP_PDU_t pdu;
	RANAP_RAB_AssignmentRequest_t *out;
	RANAP_RAB_AssignmentRequestIEs_t *ie;
	struct msgb *msg;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = RANAP_RANAP_PDU_PR_initiatingMessage;
	pdu.choice.initiatingMessage.procedureCode = RANAP_id_RAB_Assignment;
	pdu.choice.initiatingMessage.criticality = RANAP_Criticality_reject;
	pdu.choice.initiatingMessage.value.present = RANAP_InitiatingMessage__value_PR_RAB_AssignmentRequest;

	out = &pdu.choice.initiatingMessage.value.choice.RAB_AssignmentRequest;

	ie = (RANAP_RAB_AssignmentRequestIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = RANAP_id_RAB_SetupOrModifyList;
	ie->criticality = RANAP_Criticality_ignore;
	ie->value.present = RANAP_RAB_AssignmentRequestIEs__value_PR_RAB_SetupOrModifyList;

	{
		RANAP_ProtocolIE_ContainerPair_7764P0_t *ie_container = (RANAP_ProtocolIE_ContainerPair_7764P0_t *)CALLOC(1, sizeof(*ie_container));

		for (int i = 0; i < 1; i++) {
			RANAP_RAB_SetupOrModifyItem_IEs_t *setup_itm = (RANAP_RAB_SetupOrModifyItem_IEs_t *)CALLOC(1, sizeof(*setup_itm));

			setup_itm->id = RANAP_id_RAB_SetupOrModifyItem;
			setup_itm->firstCriticality = RANAP_Criticality_reject;
			setup_itm->firstValue.present = RANAP_RAB_SetupOrModifyItem_IEs__firstValue_PR_RAB_SetupOrModifyItemFirst;

			assign_new_ra_id(&setup_itm->firstValue.choice.RAB_SetupOrModifyItemFirst.rAB_ID, 5);
			setup_itm->firstValue.choice.RAB_SetupOrModifyItemFirst.nAS_SynchronisationIndicator = new_rab_nas_sync_ind(60);
			setup_itm->firstValue.choice.RAB_SetupOrModifyItemFirst.rAB_Parameters = new_rab_par_voice(6700, 12200);
			setup_itm->firstValue.choice.RAB_SetupOrModifyItemFirst.userPlaneInformation = new_upi(RANAP_UserPlaneMode_support_mode_for_predefined_SDU_sizes, 1); /* 2? */
			setup_itm->firstValue.choice.RAB_SetupOrModifyItemFirst.transportLayerInformation = new_transp_info_rtp(14304/*rtp_ip*/, 60/*rtp_port*/,
							      1 /*use_x213_nsap*/);

			setup_itm->secondCriticality = RANAP_Criticality_ignore;
			setup_itm->secondValue.present = RANAP_RAB_SetupOrModifyItem_IEs__secondValue_PR_RAB_SetupOrModifyItemSecond;
			memset(&setup_itm->secondValue.choice.RAB_SetupOrModifyItemSecond, 0, sizeof(RANAP_RAB_SetupOrModifyItemSecond_t));

			ASN_SEQUENCE_ADD(&(ie_container->list), setup_itm);
		}

		ASN_SEQUENCE_ADD(&(ie->value.choice.RAB_SetupOrModifyList.list), ie_container);
	}

	ASN_SEQUENCE_ADD(&(out->protocolIEs.list), out);

	msg = _ranap_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RANAP_PDU, &pdu);

	return msg;
}

/*! \brief generate RANAP RAB ASSIGNMENT REQUEST message for PS (data)
 * \param gtp_ip  SGSN's GTP IPv4 address in *network* byte order. */
struct msgb *ranap_new_msg_rab_assign_data(uint8_t rab_id, uint32_t gtp_ip,
					   uint32_t gtp_tei, bool use_x213_nsap)
{
	RANAP_RANAP_PDU_t pdu;
	RANAP_RAB_AssignmentRequest_t *out;
	RANAP_RAB_AssignmentRequestIEs_t *ie;
	struct msgb *msg;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = RANAP_RANAP_PDU_PR_initiatingMessage;
	pdu.choice.initiatingMessage.procedureCode = RANAP_id_RAB_Assignment;
	pdu.choice.initiatingMessage.criticality = RANAP_Criticality_reject;
	pdu.choice.initiatingMessage.value.present = RANAP_InitiatingMessage__value_PR_RAB_AssignmentRequest;

	out = &pdu.choice.initiatingMessage.value.choice.RAB_AssignmentRequest;

	ie = (RANAP_RAB_AssignmentRequestIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = RANAP_id_RAB_SetupOrModifyList;
	ie->criticality = RANAP_Criticality_ignore;
	ie->value.present = RANAP_RAB_AssignmentRequestIEs__value_PR_RAB_SetupOrModifyList;

	{
		RANAP_ProtocolIE_ContainerPair_7764P0_t *ie_container = (RANAP_ProtocolIE_ContainerPair_7764P0_t *)CALLOC(1, sizeof(*ie_container));

		for (int i = 0; i < 1; i++) {
			RANAP_RAB_SetupOrModifyItem_IEs_t *setup_itm = (RANAP_RAB_SetupOrModifyItem_IEs_t *)CALLOC(1, sizeof(*setup_itm));

			setup_itm->id = RANAP_id_RAB_SetupOrModifyItem;
			setup_itm->firstCriticality = RANAP_Criticality_reject;
			setup_itm->firstValue.present = RANAP_RAB_SetupOrModifyItem_IEs__firstValue_PR_RAB_SetupOrModifyItemFirst;

			assign_new_ra_id(&setup_itm->firstValue.choice.RAB_SetupOrModifyItemFirst.rAB_ID, 5);

			setup_itm->firstValue.choice.RAB_SetupOrModifyItemFirst.rAB_Parameters = new_rab_par_data(1600000, 800000);
			setup_itm->firstValue.choice.RAB_SetupOrModifyItemFirst.userPlaneInformation = new_upi(RANAP_UserPlaneMode_transparent_mode, 1); /* 2? */
			setup_itm->firstValue.choice.RAB_SetupOrModifyItemFirst.transportLayerInformation = new_transp_info_gtp(14304/*rtp_ip*/, 60/*rtp_port*/,
							      1 /*use_x213_nsap*/);

			setup_itm->secondCriticality = RANAP_Criticality_ignore;
			setup_itm->secondValue.present = RANAP_RAB_SetupOrModifyItem_IEs__secondValue_PR_RAB_SetupOrModifyItemSecond;
			setup_itm->secondValue.choice.RAB_SetupOrModifyItemSecond.pDP_TypeInformation = CALLOC(1, sizeof(RANAP_PDP_TypeInformation_t));
			ASN_SEQUENCE_ADD(setup_itm->secondValue.choice.RAB_SetupOrModifyItemSecond.pDP_TypeInformation, new_long(RANAP_PDP_Type_ipv4));

			setup_itm->secondValue.choice.RAB_SetupOrModifyItemSecond.dataVolumeReportingIndication = new_long(RANAP_DataVolumeReportingIndication_do_not_report);
			setup_itm->secondValue.choice.RAB_SetupOrModifyItemSecond.dl_GTP_PDU_SequenceNumber = new_long(0);
			setup_itm->secondValue.choice.RAB_SetupOrModifyItemSecond.ul_GTP_PDU_SequenceNumber = new_long(0);

			ASN_SEQUENCE_ADD(&(ie_container->list), setup_itm);
		}

		ASN_SEQUENCE_ADD(&(ie->value.choice.RAB_SetupOrModifyList.list), ie_container);
	}

	ASN_SEQUENCE_ADD(&(out->protocolIEs.list), ie);

	msg = _ranap_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RANAP_PDU, &pdu);

	return msg;
}

struct msgb *ranap_new_msg_iu_rel_req(const RANAP_Cause_t *cause)
{
	RANAP_RANAP_PDU_t pdu;
	RANAP_Iu_ReleaseRequest_t *out;
	RANAP_Iu_ReleaseRequestIEs_t *ie;
	struct msgb *msg;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = RANAP_RANAP_PDU_PR_initiatingMessage;
	pdu.choice.initiatingMessage.procedureCode = RANAP_id_Iu_ReleaseRequest;
	pdu.choice.initiatingMessage.criticality = RANAP_Criticality_ignore;
	pdu.choice.initiatingMessage.value.present = RANAP_InitiatingMessage__value_PR_Iu_ReleaseRequest;

	out = &pdu.choice.initiatingMessage.value.choice.Iu_ReleaseRequest;

	ie = (RANAP_Iu_ReleaseRequestIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = RANAP_id_Cause;
	ie->criticality = RANAP_Criticality_ignore;
	ie->value.present = RANAP_Iu_ReleaseCommandIEs__value_PR_Cause;
	ie->value.choice.Cause.present = RANAP_Cause_PR_transmissionNetwork;
	ie->value.choice.Cause.choice.radioNetwork = RANAP_CauseTransmissionNetwork_signalling_transport_resource_failure;

	ASN_SEQUENCE_ADD(&(out->protocolIEs.list), ie);

	msg = _ranap_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RANAP_PDU, &pdu);

	return msg;
}

struct msgb *ranap_new_msg_rab_rel_req(uint8_t rab_id, const RANAP_Cause_t *cause)
{
	RANAP_RANAP_PDU_t pdu;
	RANAP_RAB_ReleaseRequest_t *out;
	RANAP_RAB_ReleaseRequestIEs_t *ie;
	struct msgb *msg;

	memset(&pdu, 0, sizeof(pdu));

	pdu.present = RANAP_RANAP_PDU_PR_initiatingMessage;
	pdu.choice.initiatingMessage.procedureCode = RANAP_id_RAB_ReleaseRequest;
	pdu.choice.initiatingMessage.criticality = RANAP_Criticality_ignore;
	pdu.choice.initiatingMessage.value.present = RANAP_InitiatingMessage__value_PR_RAB_ReleaseRequest;

	out = &pdu.choice.initiatingMessage.value.choice.RAB_ReleaseRequest;

	ie = (RANAP_RAB_ReleaseRequestIEs_t *)CALLOC(1, sizeof(*ie));
	ie->id = RANAP_id_RAB_ReleaseList;
	ie->criticality = RANAP_Criticality_ignore;
	ie->value.present = RANAP_RAB_ReleaseRequestIEs__value_PR_RAB_ReleaseList;

	{
        	RANAP_ProtocolIE_Container_7748P99_t *ie_container = (RANAP_ProtocolIE_Container_7748P99_t *)CALLOC(1, sizeof(*ie_container));

		for (int i = 0; i < 1; i++) {
			RANAP_RAB_ReleaseItemIEs_t *rls_itm = (RANAP_RAB_ReleaseItemIEs_t *)CALLOC(1, sizeof(*rls_itm));

			rls_itm->id = RANAP_id_RAB_ReleaseItem;
			rls_itm->criticality = RANAP_Criticality_ignore;
			rls_itm->value.present = RANAP_RAB_ReleaseRequestIEs__value_PR_RAB_ReleaseList;

			assign_new_ra_id(&rls_itm->value.choice.RAB_ReleaseItem.rAB_ID, rab_id);

			rls_itm->value.choice.RAB_ReleaseItem.cause.present = cause[i].present;
			rls_itm->value.choice.RAB_ReleaseItem.cause.choice.radioNetwork = cause[i].present;

			ASN_SEQUENCE_ADD(&(ie_container->list), rls_itm);
		}

		ASN_SEQUENCE_ADD(&(ie->value.choice.RAB_ReleaseList.list), ie_container);
	}

	ASN_SEQUENCE_ADD(&(out->protocolIEs.list), ie);

	msg = _ranap_gen_msg(&pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RANAP_PDU, &pdu);

	return msg;
}
