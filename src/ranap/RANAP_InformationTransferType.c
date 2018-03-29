/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#include <osmocom/ranap/RANAP_InformationTransferType.h>

static asn_oer_constraints_t asn_OER_type_RANAP_InformationTransferType_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_RANAP_InformationTransferType_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED | APC_EXTENSIBLE,  0,  0,  0,  0 }	/* (0..0,...) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_RANAP_InformationTransferType_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_InformationTransferType, choice.rNCTraceInformation),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_RNCTraceInformation,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rNCTraceInformation"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_RANAP_InformationTransferType_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* rNCTraceInformation */
};
static asn_CHOICE_specifics_t asn_SPC_RANAP_InformationTransferType_specs_1 = {
	sizeof(struct RANAP_InformationTransferType),
	offsetof(struct RANAP_InformationTransferType, _asn_ctx),
	offsetof(struct RANAP_InformationTransferType, present),
	sizeof(((struct RANAP_InformationTransferType *)0)->present),
	asn_MAP_RANAP_InformationTransferType_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0,
	1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_RANAP_InformationTransferType = {
	"InformationTransferType",
	"InformationTransferType",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_RANAP_InformationTransferType_constr_1, &asn_PER_type_RANAP_InformationTransferType_constr_1, CHOICE_constraint },
	asn_MBR_RANAP_InformationTransferType_1,
	1,	/* Elements count */
	&asn_SPC_RANAP_InformationTransferType_specs_1	/* Additional specs */
};

