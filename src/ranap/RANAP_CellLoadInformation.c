/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/RANAP-IEs.asn"
 */

#include <osmocom/ranap/RANAP_CellLoadInformation.h>

static asn_TYPE_member_t asn_MBR_RANAP_CellLoadInformation_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_CellLoadInformation, cell_Capacity_Class_Value),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_Cell_Capacity_Class_Value,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"cell-Capacity-Class-Value"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_CellLoadInformation, loadValue),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_LoadValue,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"loadValue"
		},
	{ ATF_POINTER, 3, offsetof(struct RANAP_CellLoadInformation, rTLoadValue),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_RTLoadValue,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"rTLoadValue"
		},
	{ ATF_POINTER, 2, offsetof(struct RANAP_CellLoadInformation, nRTLoadInformationValue),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_NRTLoadInformationValue,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"nRTLoadInformationValue"
		},
	{ ATF_POINTER, 1, offsetof(struct RANAP_CellLoadInformation, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_IE_Extensions,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"iE-Extensions"
		},
};
static const int asn_MAP_RANAP_CellLoadInformation_oms_1[] = { 2, 3, 4 };
static const ber_tlv_tag_t asn_DEF_RANAP_CellLoadInformation_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RANAP_CellLoadInformation_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* cell-Capacity-Class-Value */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* loadValue */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* rTLoadValue */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* nRTLoadInformationValue */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* iE-Extensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_RANAP_CellLoadInformation_specs_1 = {
	sizeof(struct RANAP_CellLoadInformation),
	offsetof(struct RANAP_CellLoadInformation, _asn_ctx),
	asn_MAP_RANAP_CellLoadInformation_tag2el_1,
	5,	/* Count of tags in the map */
	asn_MAP_RANAP_CellLoadInformation_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	4,	/* Start extensions */
	6	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_RANAP_CellLoadInformation = {
	"RANAP_CellLoadInformation",
	"RANAP_CellLoadInformation",
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
	asn_DEF_RANAP_CellLoadInformation_tags_1,
	sizeof(asn_DEF_RANAP_CellLoadInformation_tags_1)
		/sizeof(asn_DEF_RANAP_CellLoadInformation_tags_1[0]), /* 1 */
	asn_DEF_RANAP_CellLoadInformation_tags_1,	/* Same as above */
	sizeof(asn_DEF_RANAP_CellLoadInformation_tags_1)
		/sizeof(asn_DEF_RANAP_CellLoadInformation_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_RANAP_CellLoadInformation_1,
	5,	/* Elements count */
	&asn_SPC_RANAP_CellLoadInformation_specs_1	/* Additional specs */
};

