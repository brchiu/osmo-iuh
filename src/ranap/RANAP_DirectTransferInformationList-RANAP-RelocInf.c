/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-PDU-Contents"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#include <osmocom/ranap/RANAP_DirectTransferInformationList-RANAP-RelocInf.h>

int
RANAP_DirectTransferInformationList_RANAP_RelocInf_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	/* Determine the number of elements */
	size = _A_CSEQUENCE_FROM_VOID(sptr)->count;
	
	if((size >= 1 && size <= 15)) {
		/* Perform validation of the inner elements */
		return td->encoding_constraints.general_constraints(td, sptr, ctfailcb, app_key);
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

/*
 * This type is implemented using RANAP_DirectTransfer_IE_ContainerList_1098P0,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_RANAP_DirectTransferInformationList_RANAP_RelocInf_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..15)) */};
static asn_per_constraints_t asn_PER_type_RANAP_DirectTransferInformationList_RANAP_RelocInf_constr_1 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 4,  4,  1,  15 }	/* (SIZE(1..15)) */,
	0, 0	/* No PER value map */
};
static const ber_tlv_tag_t asn_DEF_RANAP_DirectTransferInformationList_RANAP_RelocInf_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_TYPE_descriptor_t asn_DEF_RANAP_DirectTransferInformationList_RANAP_RelocInf = {
	"DirectTransferInformationList-RANAP-RelocInf",
	"DirectTransferInformationList-RANAP-RelocInf",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_RANAP_DirectTransferInformationList_RANAP_RelocInf_tags_1,
	sizeof(asn_DEF_RANAP_DirectTransferInformationList_RANAP_RelocInf_tags_1)
		/sizeof(asn_DEF_RANAP_DirectTransferInformationList_RANAP_RelocInf_tags_1[0]), /* 1 */
	asn_DEF_RANAP_DirectTransferInformationList_RANAP_RelocInf_tags_1,	/* Same as above */
	sizeof(asn_DEF_RANAP_DirectTransferInformationList_RANAP_RelocInf_tags_1)
		/sizeof(asn_DEF_RANAP_DirectTransferInformationList_RANAP_RelocInf_tags_1[0]), /* 1 */
	{ &asn_OER_type_RANAP_DirectTransferInformationList_RANAP_RelocInf_constr_1, &asn_PER_type_RANAP_DirectTransferInformationList_RANAP_RelocInf_constr_1, RANAP_DirectTransferInformationList_RANAP_RelocInf_constraint },
	asn_MBR_RANAP_ProtocolIE_ContainerList_7782P22_45,
	1,	/* Single element */
	&asn_SPC_RANAP_ProtocolIE_ContainerList_7782P22_specs_45	/* Additional specs */
};

