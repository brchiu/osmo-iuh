/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#include <osmocom/ranap/RANAP_M4Report.h>

static asn_oer_constraints_t asn_OER_type_RANAP_M4Report_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_RANAP_M4Report_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED | APC_EXTENSIBLE,  1,  1,  0,  1 }	/* (0..1,...) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_RANAP_M4Report_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_M4Report, choice.all),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"all"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_M4Report, choice.m4_collection_parameters),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_M4_Collection_Parameters,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"m4-collection-parameters"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_RANAP_M4Report_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* all */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* m4-collection-parameters */
};
static asn_CHOICE_specifics_t asn_SPC_RANAP_M4Report_specs_1 = {
	sizeof(struct RANAP_M4Report),
	offsetof(struct RANAP_M4Report, _asn_ctx),
	offsetof(struct RANAP_M4Report, present),
	sizeof(((struct RANAP_M4Report *)0)->present),
	asn_MAP_RANAP_M4Report_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0,
	2	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_RANAP_M4Report = {
	"M4Report",
	"M4Report",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_RANAP_M4Report_constr_1, &asn_PER_type_RANAP_M4Report_constr_1, CHOICE_constraint },
	asn_MBR_RANAP_M4Report_1,
	2,	/* Elements count */
	&asn_SPC_RANAP_M4Report_specs_1	/* Additional specs */
};

