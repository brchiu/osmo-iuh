/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#include <osmocom/ranap/RANAP_TracePropagationParameters.h>

#include <osmocom/ranap/RANAP_ListOfInterfacesToTrace.h>
#include <osmocom/ranap/RANAP_ProtocolExtensionContainer.h>
asn_TYPE_member_t asn_MBR_RANAP_TracePropagationParameters_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_TracePropagationParameters, traceRecordingSessionReference),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_TraceRecordingSessionReference,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"traceRecordingSessionReference"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_TracePropagationParameters, traceDepth),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_TraceDepth,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"traceDepth"
		},
	{ ATF_POINTER, 2, offsetof(struct RANAP_TracePropagationParameters, listOfInterfacesToTrace),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_ListOfInterfacesToTrace,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"listOfInterfacesToTrace"
		},
	{ ATF_POINTER, 1, offsetof(struct RANAP_TracePropagationParameters, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_ProtocolExtensionContainer_7796P205,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"iE-Extensions"
		},
};
static const int asn_MAP_RANAP_TracePropagationParameters_oms_1[] = { 2, 3 };
static const ber_tlv_tag_t asn_DEF_RANAP_TracePropagationParameters_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RANAP_TracePropagationParameters_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* traceRecordingSessionReference */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* traceDepth */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* listOfInterfacesToTrace */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* iE-Extensions */
};
asn_SEQUENCE_specifics_t asn_SPC_RANAP_TracePropagationParameters_specs_1 = {
	sizeof(struct RANAP_TracePropagationParameters),
	offsetof(struct RANAP_TracePropagationParameters, _asn_ctx),
	asn_MAP_RANAP_TracePropagationParameters_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_RANAP_TracePropagationParameters_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	4,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_RANAP_TracePropagationParameters = {
	"TracePropagationParameters",
	"TracePropagationParameters",
	&asn_OP_SEQUENCE,
	asn_DEF_RANAP_TracePropagationParameters_tags_1,
	sizeof(asn_DEF_RANAP_TracePropagationParameters_tags_1)
		/sizeof(asn_DEF_RANAP_TracePropagationParameters_tags_1[0]), /* 1 */
	asn_DEF_RANAP_TracePropagationParameters_tags_1,	/* Same as above */
	sizeof(asn_DEF_RANAP_TracePropagationParameters_tags_1)
		/sizeof(asn_DEF_RANAP_TracePropagationParameters_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_RANAP_TracePropagationParameters_1,
	4,	/* Elements count */
	&asn_SPC_RANAP_TracePropagationParameters_specs_1	/* Additional specs */
};

