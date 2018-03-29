/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#include <osmocom/ranap/RANAP_MessageStructure.h>

#include <osmocom/ranap/RANAP_ProtocolExtensionContainer.h>
static asn_oer_constraints_t asn_OER_type_RANAP_MessageStructure_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..256)) */};
static asn_per_constraints_t asn_PER_type_RANAP_MessageStructure_constr_1 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 8,  8,  1,  256 }	/* (SIZE(1..256)) */,
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_RANAP_Member_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_MessageStructure__Member, iE_ID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_ProtocolIE_ID,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"iE-ID"
		},
	{ ATF_POINTER, 2, offsetof(struct RANAP_MessageStructure__Member, repetitionNumber),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_RepetitionNumber1,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"repetitionNumber"
		},
	{ ATF_POINTER, 1, offsetof(struct RANAP_MessageStructure__Member, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_ProtocolExtensionContainer_7796P136,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"iE-Extensions"
		},
};
static const int asn_MAP_RANAP_Member_oms_2[] = { 1, 2 };
static const ber_tlv_tag_t asn_DEF_RANAP_Member_tags_2[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RANAP_Member_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* iE-ID */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* repetitionNumber */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* iE-Extensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_RANAP_Member_specs_2 = {
	sizeof(struct RANAP_MessageStructure__Member),
	offsetof(struct RANAP_MessageStructure__Member, _asn_ctx),
	asn_MAP_RANAP_Member_tag2el_2,
	3,	/* Count of tags in the map */
	asn_MAP_RANAP_Member_oms_2,	/* Optional members */
	2, 0,	/* Root/Additions */
	3,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_RANAP_Member_2 = {
	"SEQUENCE",
	"SEQUENCE",
	&asn_OP_SEQUENCE,
	asn_DEF_RANAP_Member_tags_2,
	sizeof(asn_DEF_RANAP_Member_tags_2)
		/sizeof(asn_DEF_RANAP_Member_tags_2[0]), /* 1 */
	asn_DEF_RANAP_Member_tags_2,	/* Same as above */
	sizeof(asn_DEF_RANAP_Member_tags_2)
		/sizeof(asn_DEF_RANAP_Member_tags_2[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_RANAP_Member_2,
	3,	/* Elements count */
	&asn_SPC_RANAP_Member_specs_2	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_RANAP_MessageStructure_1[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_RANAP_Member_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_RANAP_MessageStructure_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_RANAP_MessageStructure_specs_1 = {
	sizeof(struct RANAP_MessageStructure),
	offsetof(struct RANAP_MessageStructure, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
asn_TYPE_descriptor_t asn_DEF_RANAP_MessageStructure = {
	"MessageStructure",
	"MessageStructure",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_RANAP_MessageStructure_tags_1,
	sizeof(asn_DEF_RANAP_MessageStructure_tags_1)
		/sizeof(asn_DEF_RANAP_MessageStructure_tags_1[0]), /* 1 */
	asn_DEF_RANAP_MessageStructure_tags_1,	/* Same as above */
	sizeof(asn_DEF_RANAP_MessageStructure_tags_1)
		/sizeof(asn_DEF_RANAP_MessageStructure_tags_1[0]), /* 1 */
	{ &asn_OER_type_RANAP_MessageStructure_constr_1, &asn_PER_type_RANAP_MessageStructure_constr_1, SEQUENCE_OF_constraint },
	asn_MBR_RANAP_MessageStructure_1,
	1,	/* Single element */
	&asn_SPC_RANAP_MessageStructure_specs_1	/* Additional specs */
};

