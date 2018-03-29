/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#include <osmocom/ranap/RANAP_M5-Period.h>

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_RANAP_M5_Period_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_RANAP_M5_Period_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED | APC_EXTENSIBLE,  3,  3,  0,  7 }	/* (0..7,...) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_RANAP_M5_Period_value2enum_1[] = {
	{ 0,	5,	"ms100" },
	{ 1,	5,	"ms250" },
	{ 2,	5,	"ms500" },
	{ 3,	6,	"ms1000" },
	{ 4,	6,	"ms2000" },
	{ 5,	6,	"ms3000" },
	{ 6,	6,	"ms4000" },
	{ 7,	6,	"ms6000" }
	/* This list is extensible */
};
static const unsigned int asn_MAP_RANAP_M5_Period_enum2value_1[] = {
	0,	/* ms100(0) */
	3,	/* ms1000(3) */
	4,	/* ms2000(4) */
	1,	/* ms250(1) */
	5,	/* ms3000(5) */
	6,	/* ms4000(6) */
	2,	/* ms500(2) */
	7	/* ms6000(7) */
	/* This list is extensible */
};
const asn_INTEGER_specifics_t asn_SPC_RANAP_M5_Period_specs_1 = {
	asn_MAP_RANAP_M5_Period_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_RANAP_M5_Period_enum2value_1,	/* N => "tag"; sorted by N */
	8,	/* Number of elements in the maps */
	9,	/* Extensions before this member */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_RANAP_M5_Period_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_RANAP_M5_Period = {
	"M5-Period",
	"M5-Period",
	&asn_OP_NativeEnumerated,
	asn_DEF_RANAP_M5_Period_tags_1,
	sizeof(asn_DEF_RANAP_M5_Period_tags_1)
		/sizeof(asn_DEF_RANAP_M5_Period_tags_1[0]), /* 1 */
	asn_DEF_RANAP_M5_Period_tags_1,	/* Same as above */
	sizeof(asn_DEF_RANAP_M5_Period_tags_1)
		/sizeof(asn_DEF_RANAP_M5_Period_tags_1[0]), /* 1 */
	{ &asn_OER_type_RANAP_M5_Period_constr_1, &asn_PER_type_RANAP_M5_Period_constr_1, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_RANAP_M5_Period_specs_1	/* Additional specs */
};

