/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-IEs"
 * 	found in "../../asn1/hnbap/hnbap-14.0.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#include <osmocom/hnbap/MacroCellID.h>

static asn_oer_constraints_t asn_OER_type_MacroCellID_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_MacroCellID_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED | APC_EXTENSIBLE,  1,  1,  0,  1 }	/* (0..1,...) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_MacroCellID_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MacroCellID, choice.uTRANCellID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UTRANCellID,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"uTRANCellID"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MacroCellID, choice.gERANCellID),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CGI,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"gERANCellID"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_MacroCellID_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* uTRANCellID */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* gERANCellID */
};
asn_CHOICE_specifics_t asn_SPC_MacroCellID_specs_1 = {
	sizeof(struct MacroCellID),
	offsetof(struct MacroCellID, _asn_ctx),
	offsetof(struct MacroCellID, present),
	sizeof(((struct MacroCellID *)0)->present),
	asn_MAP_MacroCellID_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0,
	2	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_MacroCellID = {
	"MacroCellID",
	"MacroCellID",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_MacroCellID_constr_1, &asn_PER_type_MacroCellID_constr_1, CHOICE_constraint },
	asn_MBR_MacroCellID_1,
	2,	/* Elements count */
	&asn_SPC_MacroCellID_specs_1	/* Additional specs */
};

