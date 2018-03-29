/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#include <osmocom/ranap/RANAP_RNCTraceInformation.h>

#include <osmocom/ranap/RANAP_EquipmentsToBeTraced.h>
#include <osmocom/ranap/RANAP_ProtocolExtensionContainer.h>
/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_RANAP_traceActivationIndicator_constr_3 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_RANAP_traceActivationIndicator_constr_3 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_RANAP_traceActivationIndicator_value2enum_3[] = {
	{ 0,	9,	"activated" },
	{ 1,	11,	"deactivated" }
};
static const unsigned int asn_MAP_RANAP_traceActivationIndicator_enum2value_3[] = {
	0,	/* activated(0) */
	1	/* deactivated(1) */
};
static const asn_INTEGER_specifics_t asn_SPC_RANAP_traceActivationIndicator_specs_3 = {
	asn_MAP_RANAP_traceActivationIndicator_value2enum_3,	/* "tag" => N; sorted by tag */
	asn_MAP_RANAP_traceActivationIndicator_enum2value_3,	/* N => "tag"; sorted by N */
	2,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_RANAP_traceActivationIndicator_tags_3[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_RANAP_traceActivationIndicator_3 = {
	"traceActivationIndicator",
	"traceActivationIndicator",
	&asn_OP_NativeEnumerated,
	asn_DEF_RANAP_traceActivationIndicator_tags_3,
	sizeof(asn_DEF_RANAP_traceActivationIndicator_tags_3)
		/sizeof(asn_DEF_RANAP_traceActivationIndicator_tags_3[0]) - 1, /* 1 */
	asn_DEF_RANAP_traceActivationIndicator_tags_3,	/* Same as above */
	sizeof(asn_DEF_RANAP_traceActivationIndicator_tags_3)
		/sizeof(asn_DEF_RANAP_traceActivationIndicator_tags_3[0]), /* 2 */
	{ &asn_OER_type_RANAP_traceActivationIndicator_constr_3, &asn_PER_type_RANAP_traceActivationIndicator_constr_3, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_RANAP_traceActivationIndicator_specs_3	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_RANAP_RNCTraceInformation_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_RNCTraceInformation, traceReference),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_TraceReference,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"traceReference"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_RNCTraceInformation, traceActivationIndicator),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_traceActivationIndicator_3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"traceActivationIndicator"
		},
	{ ATF_POINTER, 2, offsetof(struct RANAP_RNCTraceInformation, equipmentsToBeTraced),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_RANAP_EquipmentsToBeTraced,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"equipmentsToBeTraced"
		},
	{ ATF_POINTER, 1, offsetof(struct RANAP_RNCTraceInformation, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_ProtocolExtensionContainer_7796P182,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"iE-Extensions"
		},
};
static const int asn_MAP_RANAP_RNCTraceInformation_oms_1[] = { 2, 3 };
static const ber_tlv_tag_t asn_DEF_RANAP_RNCTraceInformation_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RANAP_RNCTraceInformation_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* traceReference */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* traceActivationIndicator */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* equipmentsToBeTraced */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* iE-Extensions */
};
asn_SEQUENCE_specifics_t asn_SPC_RANAP_RNCTraceInformation_specs_1 = {
	sizeof(struct RANAP_RNCTraceInformation),
	offsetof(struct RANAP_RNCTraceInformation, _asn_ctx),
	asn_MAP_RANAP_RNCTraceInformation_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_RANAP_RNCTraceInformation_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_RANAP_RNCTraceInformation = {
	"RNCTraceInformation",
	"RNCTraceInformation",
	&asn_OP_SEQUENCE,
	asn_DEF_RANAP_RNCTraceInformation_tags_1,
	sizeof(asn_DEF_RANAP_RNCTraceInformation_tags_1)
		/sizeof(asn_DEF_RANAP_RNCTraceInformation_tags_1[0]), /* 1 */
	asn_DEF_RANAP_RNCTraceInformation_tags_1,	/* Same as above */
	sizeof(asn_DEF_RANAP_RNCTraceInformation_tags_1)
		/sizeof(asn_DEF_RANAP_RNCTraceInformation_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_RANAP_RNCTraceInformation_1,
	4,	/* Elements count */
	&asn_SPC_RANAP_RNCTraceInformation_specs_1	/* Additional specs */
};

