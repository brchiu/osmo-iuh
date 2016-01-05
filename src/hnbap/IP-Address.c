/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-IEs"
 * 	found in "../../asn1/hnbap/HNBAP-IEs.asn"
 * 	`asn1c -gen-PER`
 */

#include <osmocom/hnbap/IP-Address.h>

static asn_per_constraints_t asn_PER_type_ipaddress_constr_2 GCC_NOTUSED = {
	{ APC_CONSTRAINED | APC_EXTENSIBLE,  1,  1,  0l,  1l }	/* (0..1,...) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_ipaddress_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct ipaddress, choice.ipv4info),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Ipv4Address,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ipv4info"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct ipaddress, choice.ipv6info),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Ipv6Address,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ipv6info"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_ipaddress_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ipv4info */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* ipv6info */
};
static asn_CHOICE_specifics_t asn_SPC_ipaddress_specs_2 = {
	sizeof(struct ipaddress),
	offsetof(struct ipaddress, _asn_ctx),
	offsetof(struct ipaddress, present),
	sizeof(((struct ipaddress *)0)->present),
	asn_MAP_ipaddress_tag2el_2,
	2,	/* Count of tags in the map */
	0,
	2	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_ipaddress_2 = {
	"ipaddress",
	"ipaddress",
	CHOICE_free,
	CHOICE_print,
	CHOICE_constraint,
	CHOICE_decode_ber,
	CHOICE_encode_der,
	CHOICE_decode_xer,
	CHOICE_encode_xer,
	CHOICE_decode_uper,
	CHOICE_encode_uper,
	CHOICE_decode_aper,
	CHOICE_encode_aper,
	CHOICE_outmost_tag,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	&asn_PER_type_ipaddress_constr_2,
	asn_MBR_ipaddress_2,
	2,	/* Elements count */
	&asn_SPC_ipaddress_specs_2	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_IP_Address_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct IP_Address, ipaddress),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_ipaddress_2,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ipaddress"
		},
	{ ATF_POINTER, 1, offsetof(struct IP_Address, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IE_Extensions,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"iE-Extensions"
		},
};
static const int asn_MAP_IP_Address_oms_1[] = { 1 };
static const ber_tlv_tag_t asn_DEF_IP_Address_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_IP_Address_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ipaddress */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* iE-Extensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_IP_Address_specs_1 = {
	sizeof(struct IP_Address),
	offsetof(struct IP_Address, _asn_ctx),
	asn_MAP_IP_Address_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_IP_Address_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	1,	/* Start extensions */
	3	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_IP_Address = {
	"IP-Address",
	"IP-Address",
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
	asn_DEF_IP_Address_tags_1,
	sizeof(asn_DEF_IP_Address_tags_1)
		/sizeof(asn_DEF_IP_Address_tags_1[0]), /* 1 */
	asn_DEF_IP_Address_tags_1,	/* Same as above */
	sizeof(asn_DEF_IP_Address_tags_1)
		/sizeof(asn_DEF_IP_Address_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_IP_Address_1,
	2,	/* Elements count */
	&asn_SPC_IP_Address_specs_1	/* Additional specs */
};

