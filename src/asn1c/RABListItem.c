/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-IEs"
 * 	found in "../../asn1/hnbap/HNBAP-IEs.asn"
 * 	`asn1c -gen-PER -fnative-types`
 */

#include "RABListItem.h"

static asn_TYPE_member_t asn_MBR_RABListItem_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RABListItem, rAB_ID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RAB_ID,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"rAB-ID"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RABListItem, old_transport_Info),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TransportInfo,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"old-transport-Info"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RABListItem, new_transport_Info),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TransportInfo,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"new-transport-Info"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RABListItem, cn_domain_indicator),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CN_DomainIndicator,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"cn-domain-indicator"
		},
	{ ATF_POINTER, 1, offsetof(struct RABListItem, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IE_Extensions,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"iE-Extensions"
		},
};
static const int asn_MAP_RABListItem_oms_1[] = { 4 };
static const ber_tlv_tag_t asn_DEF_RABListItem_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RABListItem_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rAB-ID */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* old-transport-Info */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* new-transport-Info */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* cn-domain-indicator */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* iE-Extensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_RABListItem_specs_1 = {
	sizeof(struct RABListItem),
	offsetof(struct RABListItem, _asn_ctx),
	asn_MAP_RABListItem_tag2el_1,
	5,	/* Count of tags in the map */
	asn_MAP_RABListItem_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	4,	/* Start extensions */
	6	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_RABListItem = {
	"RABListItem",
	"RABListItem",
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
	asn_DEF_RABListItem_tags_1,
	sizeof(asn_DEF_RABListItem_tags_1)
		/sizeof(asn_DEF_RABListItem_tags_1[0]), /* 1 */
	asn_DEF_RABListItem_tags_1,	/* Same as above */
	sizeof(asn_DEF_RABListItem_tags_1)
		/sizeof(asn_DEF_RABListItem_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_RABListItem_1,
	5,	/* Elements count */
	&asn_SPC_RABListItem_specs_1	/* Additional specs */
};

