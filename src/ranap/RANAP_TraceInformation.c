/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#include <osmocom/ranap/RANAP_TraceInformation.h>

#include <osmocom/ranap/RANAP_TracePropagationParameters.h>
#include <osmocom/ranap/RANAP_ProtocolExtensionContainer.h>
asn_TYPE_member_t asn_MBR_RANAP_TraceInformation_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_TraceInformation, traceReference),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_TraceReference,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"traceReference"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_TraceInformation, ue_identity),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_RANAP_UE_ID,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ue-identity"
		},
	{ ATF_POINTER, 2, offsetof(struct RANAP_TraceInformation, tracePropagationParameters),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_TracePropagationParameters,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tracePropagationParameters"
		},
	{ ATF_POINTER, 1, offsetof(struct RANAP_TraceInformation, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_ProtocolExtensionContainer_7796P204,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"iE-Extensions"
		},
};
static const int asn_MAP_RANAP_TraceInformation_oms_1[] = { 2, 3 };
static const ber_tlv_tag_t asn_DEF_RANAP_TraceInformation_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RANAP_TraceInformation_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* traceReference */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* ue-identity */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* tracePropagationParameters */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* iE-Extensions */
};
asn_SEQUENCE_specifics_t asn_SPC_RANAP_TraceInformation_specs_1 = {
	sizeof(struct RANAP_TraceInformation),
	offsetof(struct RANAP_TraceInformation, _asn_ctx),
	asn_MAP_RANAP_TraceInformation_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_RANAP_TraceInformation_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	4,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_RANAP_TraceInformation = {
	"TraceInformation",
	"TraceInformation",
	&asn_OP_SEQUENCE,
	asn_DEF_RANAP_TraceInformation_tags_1,
	sizeof(asn_DEF_RANAP_TraceInformation_tags_1)
		/sizeof(asn_DEF_RANAP_TraceInformation_tags_1[0]), /* 1 */
	asn_DEF_RANAP_TraceInformation_tags_1,	/* Same as above */
	sizeof(asn_DEF_RANAP_TraceInformation_tags_1)
		/sizeof(asn_DEF_RANAP_TraceInformation_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_RANAP_TraceInformation_1,
	4,	/* Elements count */
	&asn_SPC_RANAP_TraceInformation_specs_1	/* Additional specs */
};

