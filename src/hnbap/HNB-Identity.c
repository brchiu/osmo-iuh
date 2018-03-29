/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-IEs"
 * 	found in "../../asn1/hnbap/hnbap-14.0.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#include <osmocom/hnbap/HNB-Identity.h>

#include <osmocom/hnbap/ProtocolExtensionContainer.h>
static asn_TYPE_member_t asn_MBR_HNB_Identity_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HNB_Identity, hNB_Identity_Info),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_HNB_Identity_Info,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"hNB-Identity-Info"
		},
	{ ATF_POINTER, 1, offsetof(struct HNB_Identity, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ProtocolExtensionContainer_1637P28,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"iE-Extensions"
		},
};
static const int asn_MAP_HNB_Identity_oms_1[] = { 1 };
static const ber_tlv_tag_t asn_DEF_HNB_Identity_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_HNB_Identity_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* hNB-Identity-Info */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* iE-Extensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_HNB_Identity_specs_1 = {
	sizeof(struct HNB_Identity),
	offsetof(struct HNB_Identity, _asn_ctx),
	asn_MAP_HNB_Identity_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_HNB_Identity_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	2,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_HNB_Identity = {
	"HNB-Identity",
	"HNB-Identity",
	&asn_OP_SEQUENCE,
	asn_DEF_HNB_Identity_tags_1,
	sizeof(asn_DEF_HNB_Identity_tags_1)
		/sizeof(asn_DEF_HNB_Identity_tags_1[0]), /* 1 */
	asn_DEF_HNB_Identity_tags_1,	/* Same as above */
	sizeof(asn_DEF_HNB_Identity_tags_1)
		/sizeof(asn_DEF_HNB_Identity_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_HNB_Identity_1,
	2,	/* Elements count */
	&asn_SPC_HNB_Identity_specs_1	/* Additional specs */
};

