/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-IEs"
 * 	found in "../../asn1/hnbap/HNBAP-IEs.asn"
 * 	`asn1c -gen-PER -fnative-types`
 */

#include "UTRANCellID.h"

static asn_TYPE_member_t asn_MBR_UTRANCellID_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UTRANCellID, lAC),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LAC,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"lAC"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UTRANCellID, rAC),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RAC,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"rAC"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UTRANCellID, pLMNidentity),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PLMNidentity,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"pLMNidentity"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UTRANCellID, uTRANcellID),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellIdentity,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"uTRANcellID"
		},
	{ ATF_POINTER, 1, offsetof(struct UTRANCellID, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IE_Extensions,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"iE-Extensions"
		},
};
static const int asn_MAP_UTRANCellID_oms_1[] = { 4 };
static const ber_tlv_tag_t asn_DEF_UTRANCellID_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_UTRANCellID_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* lAC */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* rAC */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* pLMNidentity */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* uTRANcellID */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* iE-Extensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_UTRANCellID_specs_1 = {
	sizeof(struct UTRANCellID),
	offsetof(struct UTRANCellID, _asn_ctx),
	asn_MAP_UTRANCellID_tag2el_1,
	5,	/* Count of tags in the map */
	asn_MAP_UTRANCellID_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_UTRANCellID = {
	"UTRANCellID",
	"UTRANCellID",
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
	asn_DEF_UTRANCellID_tags_1,
	sizeof(asn_DEF_UTRANCellID_tags_1)
		/sizeof(asn_DEF_UTRANCellID_tags_1[0]), /* 1 */
	asn_DEF_UTRANCellID_tags_1,	/* Same as above */
	sizeof(asn_DEF_UTRANCellID_tags_1)
		/sizeof(asn_DEF_UTRANCellID_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_UTRANCellID_1,
	5,	/* Elements count */
	&asn_SPC_UTRANCellID_specs_1	/* Additional specs */
};

