/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-IEs"
 * 	found in "../../asn1/hnbap/hnbap-14.0.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#include <osmocom/hnbap/Tunnel-Information.h>

#include <osmocom/hnbap/ProtocolExtensionContainer.h>
static asn_TYPE_member_t asn_MBR_Tunnel_Information_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct Tunnel_Information, iP_Address),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IP_Address,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"iP-Address"
		},
	{ ATF_POINTER, 2, offsetof(struct Tunnel_Information, uDP_Port_Number),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UDP_Port_Number,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"uDP-Port-Number"
		},
	{ ATF_POINTER, 1, offsetof(struct Tunnel_Information, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ProtocolExtensionContainer_1637P34,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"iE-Extensions"
		},
};
static const int asn_MAP_Tunnel_Information_oms_1[] = { 1, 2 };
static const ber_tlv_tag_t asn_DEF_Tunnel_Information_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_Tunnel_Information_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* iP-Address */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* uDP-Port-Number */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* iE-Extensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_Tunnel_Information_specs_1 = {
	sizeof(struct Tunnel_Information),
	offsetof(struct Tunnel_Information, _asn_ctx),
	asn_MAP_Tunnel_Information_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_Tunnel_Information_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	3,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_Tunnel_Information = {
	"Tunnel-Information",
	"Tunnel-Information",
	&asn_OP_SEQUENCE,
	asn_DEF_Tunnel_Information_tags_1,
	sizeof(asn_DEF_Tunnel_Information_tags_1)
		/sizeof(asn_DEF_Tunnel_Information_tags_1[0]), /* 1 */
	asn_DEF_Tunnel_Information_tags_1,	/* Same as above */
	sizeof(asn_DEF_Tunnel_Information_tags_1)
		/sizeof(asn_DEF_Tunnel_Information_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_Tunnel_Information_1,
	3,	/* Elements count */
	&asn_SPC_Tunnel_Information_specs_1	/* Additional specs */
};

