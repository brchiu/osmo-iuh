/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#include <osmocom/ranap/RANAP_HorizontalWithVerticalVelocity.h>

#include <osmocom/ranap/RANAP_ProtocolExtensionContainer.h>
asn_TYPE_member_t asn_MBR_RANAP_HorizontalWithVerticalVelocity_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_HorizontalWithVerticalVelocity, horizontalSpeedAndBearing),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_HorizontalSpeedAndBearing,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"horizontalSpeedAndBearing"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_HorizontalWithVerticalVelocity, veritcalVelocity),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_VerticalVelocity,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"veritcalVelocity"
		},
	{ ATF_POINTER, 1, offsetof(struct RANAP_HorizontalWithVerticalVelocity, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_ProtocolExtensionContainer_7796P215,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"iE-Extensions"
		},
};
static const int asn_MAP_RANAP_HorizontalWithVerticalVelocity_oms_1[] = { 2 };
static const ber_tlv_tag_t asn_DEF_RANAP_HorizontalWithVerticalVelocity_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RANAP_HorizontalWithVerticalVelocity_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* horizontalSpeedAndBearing */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* veritcalVelocity */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* iE-Extensions */
};
asn_SEQUENCE_specifics_t asn_SPC_RANAP_HorizontalWithVerticalVelocity_specs_1 = {
	sizeof(struct RANAP_HorizontalWithVerticalVelocity),
	offsetof(struct RANAP_HorizontalWithVerticalVelocity, _asn_ctx),
	asn_MAP_RANAP_HorizontalWithVerticalVelocity_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_RANAP_HorizontalWithVerticalVelocity_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	3,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_RANAP_HorizontalWithVerticalVelocity = {
	"HorizontalWithVerticalVelocity",
	"HorizontalWithVerticalVelocity",
	&asn_OP_SEQUENCE,
	asn_DEF_RANAP_HorizontalWithVerticalVelocity_tags_1,
	sizeof(asn_DEF_RANAP_HorizontalWithVerticalVelocity_tags_1)
		/sizeof(asn_DEF_RANAP_HorizontalWithVerticalVelocity_tags_1[0]), /* 1 */
	asn_DEF_RANAP_HorizontalWithVerticalVelocity_tags_1,	/* Same as above */
	sizeof(asn_DEF_RANAP_HorizontalWithVerticalVelocity_tags_1)
		/sizeof(asn_DEF_RANAP_HorizontalWithVerticalVelocity_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_RANAP_HorizontalWithVerticalVelocity_1,
	3,	/* Elements count */
	&asn_SPC_RANAP_HorizontalWithVerticalVelocity_specs_1	/* Additional specs */
};

