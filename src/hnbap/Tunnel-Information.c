/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-IEs"
 * 	found in "../../asn1/hnbap/HNBAP-IEs.asn"
 * 	`asn1c -gen-PER`
 */

#include <osmocom/hnbap/Tunnel-Information.h>

static asn_TYPE_member_t asn_MBR_Tunnel_Information_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct Tunnel_Information, iP_Address),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IP_Address,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"iP-Address"
		},
	{ ATF_POINTER, 2, offsetof(struct Tunnel_Information, uDP_Port_Number),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UDP_Port_Number,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"uDP-Port-Number"
		},
	{ ATF_POINTER, 1, offsetof(struct Tunnel_Information, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IE_Extensions,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
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
	2,	/* Start extensions */
	4	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_Tunnel_Information = {
	"Tunnel-Information",
	"Tunnel-Information",
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
	asn_DEF_Tunnel_Information_tags_1,
	sizeof(asn_DEF_Tunnel_Information_tags_1)
		/sizeof(asn_DEF_Tunnel_Information_tags_1[0]), /* 1 */
	asn_DEF_Tunnel_Information_tags_1,	/* Same as above */
	sizeof(asn_DEF_Tunnel_Information_tags_1)
		/sizeof(asn_DEF_Tunnel_Information_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_Tunnel_Information_1,
	3,	/* Elements count */
	&asn_SPC_Tunnel_Information_specs_1	/* Additional specs */
};

