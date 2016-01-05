/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/RANAP-IEs.asn"
 */

#include <osmocom/ranap/RANAP_InformationRequestType.h>

static asn_per_constraints_t asn_PER_type_RANAP_InformationRequestType_constr_1 GCC_NOTUSED = {
	{ APC_CONSTRAINED | APC_EXTENSIBLE,  1,  1,  0l,  1l }	/* (0..1,...) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_RANAP_InformationRequestType_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_InformationRequestType, choice.mBMSIPMulticastAddressandAPNRequest),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_MBMSIPMulticastAddressandAPNRequest,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"mBMSIPMulticastAddressandAPNRequest"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_InformationRequestType, choice.permanentNAS_UE_ID),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_RANAP_PermanentNAS_UE_ID,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"permanentNAS-UE-ID"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_RANAP_InformationRequestType_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* mBMSIPMulticastAddressandAPNRequest */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* permanentNAS-UE-ID */
};
static asn_CHOICE_specifics_t asn_SPC_RANAP_InformationRequestType_specs_1 = {
	sizeof(struct RANAP_InformationRequestType),
	offsetof(struct RANAP_InformationRequestType, _asn_ctx),
	offsetof(struct RANAP_InformationRequestType, present),
	sizeof(((struct RANAP_InformationRequestType *)0)->present),
	asn_MAP_RANAP_InformationRequestType_tag2el_1,
	2,	/* Count of tags in the map */
	0,
	2	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_RANAP_InformationRequestType = {
	"RANAP_InformationRequestType",
	"RANAP_InformationRequestType",
	CHOICE_free,
	CHOICE_print,
	CHOICE_constraint,
	CHOICE_decode_ber,
	CHOICE_encode_der,
	CHOICE_decode_xer,
	CHOICE_encode_xer,
	CHOICE_decode_uper,
	CHOICE_encode_uper,
	CHOICE_decode_aper,
	CHOICE_encode_aper,
	CHOICE_outmost_tag,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	&asn_PER_type_RANAP_InformationRequestType_constr_1,
	asn_MBR_RANAP_InformationRequestType_1,
	2,	/* Elements count */
	&asn_SPC_RANAP_InformationRequestType_specs_1	/* Additional specs */
};

