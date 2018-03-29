/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#include <osmocom/ranap/RANAP_RIMRoutingAddress.h>

static asn_oer_constraints_t asn_OER_type_RANAP_RIMRoutingAddress_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_RANAP_RIMRoutingAddress_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED | APC_EXTENSIBLE,  1,  1,  0,  1 }	/* (0..1,...) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_RANAP_RIMRoutingAddress_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_RIMRoutingAddress, choice.targetRNC_ID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_TargetRNC_ID,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"targetRNC-ID"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_RIMRoutingAddress, choice.gERAN_Cell_ID),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_GERAN_Cell_ID,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"gERAN-Cell-ID"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_RIMRoutingAddress, choice.targeteNB_ID),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_TargetENB_ID,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"targeteNB-ID"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_RANAP_RIMRoutingAddress_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* targetRNC-ID */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* gERAN-Cell-ID */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* targeteNB-ID */
};
asn_CHOICE_specifics_t asn_SPC_RANAP_RIMRoutingAddress_specs_1 = {
	sizeof(struct RANAP_RIMRoutingAddress),
	offsetof(struct RANAP_RIMRoutingAddress, _asn_ctx),
	offsetof(struct RANAP_RIMRoutingAddress, present),
	sizeof(((struct RANAP_RIMRoutingAddress *)0)->present),
	asn_MAP_RANAP_RIMRoutingAddress_tag2el_1,
	3,	/* Count of tags in the map */
	0, 0,
	2	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_RANAP_RIMRoutingAddress = {
	"RIMRoutingAddress",
	"RIMRoutingAddress",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_RANAP_RIMRoutingAddress_constr_1, &asn_PER_type_RANAP_RIMRoutingAddress_constr_1, CHOICE_constraint },
	asn_MBR_RANAP_RIMRoutingAddress_1,
	3,	/* Elements count */
	&asn_SPC_RANAP_RIMRoutingAddress_specs_1	/* Additional specs */
};

