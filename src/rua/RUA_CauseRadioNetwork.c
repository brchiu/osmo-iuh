/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RUA-IEs"
 * 	found in "../../asn1/rua/rua-14.0.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#include <osmocom/rua/RUA_CauseRadioNetwork.h>

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_RUA_CauseRadioNetwork_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_RUA_CauseRadioNetwork_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED | APC_EXTENSIBLE,  2,  2,  0,  3 }	/* (0..3,...) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_RUA_CauseRadioNetwork_value2enum_1[] = {
	{ 0,	6,	"normal" },
	{ 1,	14,	"connect-failed" },
	{ 2,	15,	"network-release" },
	{ 3,	11,	"unspecified" }
	/* This list is extensible */
};
static const unsigned int asn_MAP_RUA_CauseRadioNetwork_enum2value_1[] = {
	1,	/* connect-failed(1) */
	2,	/* network-release(2) */
	0,	/* normal(0) */
	3	/* unspecified(3) */
	/* This list is extensible */
};
const asn_INTEGER_specifics_t asn_SPC_RUA_CauseRadioNetwork_specs_1 = {
	asn_MAP_RUA_CauseRadioNetwork_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_RUA_CauseRadioNetwork_enum2value_1,	/* N => "tag"; sorted by N */
	4,	/* Number of elements in the maps */
	5,	/* Extensions before this member */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_RUA_CauseRadioNetwork_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_RUA_CauseRadioNetwork = {
	"CauseRadioNetwork",
	"CauseRadioNetwork",
	&asn_OP_NativeEnumerated,
	asn_DEF_RUA_CauseRadioNetwork_tags_1,
	sizeof(asn_DEF_RUA_CauseRadioNetwork_tags_1)
		/sizeof(asn_DEF_RUA_CauseRadioNetwork_tags_1[0]), /* 1 */
	asn_DEF_RUA_CauseRadioNetwork_tags_1,	/* Same as above */
	sizeof(asn_DEF_RUA_CauseRadioNetwork_tags_1)
		/sizeof(asn_DEF_RUA_CauseRadioNetwork_tags_1[0]), /* 1 */
	{ &asn_OER_type_RUA_CauseRadioNetwork_constr_1, &asn_PER_type_RUA_CauseRadioNetwork_constr_1, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_RUA_CauseRadioNetwork_specs_1	/* Additional specs */
};

