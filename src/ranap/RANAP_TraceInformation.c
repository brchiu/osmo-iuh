/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/RANAP-IEs.asn"
 */

#include <osmocom/ranap/RANAP_TraceInformation.h>

static asn_TYPE_member_t asn_MBR_RANAP_TraceInformation_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_TraceInformation, traceReference),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_TraceReference,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"traceReference"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_TraceInformation, ue_identity),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_RANAP_UE_ID,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ue-identity"
		},
	{ ATF_POINTER, 2, offsetof(struct RANAP_TraceInformation, tracePropagationParameters),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_TracePropagationParameters,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"tracePropagationParameters"
		},
	{ ATF_POINTER, 1, offsetof(struct RANAP_TraceInformation, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_IE_Extensions,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
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
static asn_SEQUENCE_specifics_t asn_SPC_RANAP_TraceInformation_specs_1 = {
	sizeof(struct RANAP_TraceInformation),
	offsetof(struct RANAP_TraceInformation, _asn_ctx),
	asn_MAP_RANAP_TraceInformation_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_RANAP_TraceInformation_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	3,	/* Start extensions */
	5	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_RANAP_TraceInformation = {
	"RANAP_TraceInformation",
	"RANAP_TraceInformation",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	SEQUENCE_decode_uper,
	SEQUENCE_encode_uper,
	SEQUENCE_decode_aper,
	SEQUENCE_encode_aper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_RANAP_TraceInformation_tags_1,
	sizeof(asn_DEF_RANAP_TraceInformation_tags_1)
		/sizeof(asn_DEF_RANAP_TraceInformation_tags_1[0]), /* 1 */
	asn_DEF_RANAP_TraceInformation_tags_1,	/* Same as above */
	sizeof(asn_DEF_RANAP_TraceInformation_tags_1)
		/sizeof(asn_DEF_RANAP_TraceInformation_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_RANAP_TraceInformation_1,
	4,	/* Elements count */
	&asn_SPC_RANAP_TraceInformation_specs_1	/* Additional specs */
};

