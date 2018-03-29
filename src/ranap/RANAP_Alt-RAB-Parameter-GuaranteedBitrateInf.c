/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#include <osmocom/ranap/RANAP_Alt-RAB-Parameter-GuaranteedBitrateInf.h>

#include <osmocom/ranap/RANAP_Alt-RAB-Parameter-GuaranteedBitrates.h>
asn_TYPE_member_t asn_MBR_RANAP_Alt_RAB_Parameter_GuaranteedBitrateInf_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_Alt_RAB_Parameter_GuaranteedBitrateInf, altGuaranteedBitrateType),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_Alt_RAB_Parameter_GuaranteedBitrateType,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"altGuaranteedBitrateType"
		},
	{ ATF_POINTER, 1, offsetof(struct RANAP_Alt_RAB_Parameter_GuaranteedBitrateInf, altGuaranteedBitrates),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_Alt_RAB_Parameter_GuaranteedBitrates,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"altGuaranteedBitrates"
		},
};
static const int asn_MAP_RANAP_Alt_RAB_Parameter_GuaranteedBitrateInf_oms_1[] = { 1 };
static const ber_tlv_tag_t asn_DEF_RANAP_Alt_RAB_Parameter_GuaranteedBitrateInf_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RANAP_Alt_RAB_Parameter_GuaranteedBitrateInf_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* altGuaranteedBitrateType */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* altGuaranteedBitrates */
};
asn_SEQUENCE_specifics_t asn_SPC_RANAP_Alt_RAB_Parameter_GuaranteedBitrateInf_specs_1 = {
	sizeof(struct RANAP_Alt_RAB_Parameter_GuaranteedBitrateInf),
	offsetof(struct RANAP_Alt_RAB_Parameter_GuaranteedBitrateInf, _asn_ctx),
	asn_MAP_RANAP_Alt_RAB_Parameter_GuaranteedBitrateInf_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_RANAP_Alt_RAB_Parameter_GuaranteedBitrateInf_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	2,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_RANAP_Alt_RAB_Parameter_GuaranteedBitrateInf = {
	"Alt-RAB-Parameter-GuaranteedBitrateInf",
	"Alt-RAB-Parameter-GuaranteedBitrateInf",
	&asn_OP_SEQUENCE,
	asn_DEF_RANAP_Alt_RAB_Parameter_GuaranteedBitrateInf_tags_1,
	sizeof(asn_DEF_RANAP_Alt_RAB_Parameter_GuaranteedBitrateInf_tags_1)
		/sizeof(asn_DEF_RANAP_Alt_RAB_Parameter_GuaranteedBitrateInf_tags_1[0]), /* 1 */
	asn_DEF_RANAP_Alt_RAB_Parameter_GuaranteedBitrateInf_tags_1,	/* Same as above */
	sizeof(asn_DEF_RANAP_Alt_RAB_Parameter_GuaranteedBitrateInf_tags_1)
		/sizeof(asn_DEF_RANAP_Alt_RAB_Parameter_GuaranteedBitrateInf_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_RANAP_Alt_RAB_Parameter_GuaranteedBitrateInf_1,
	2,	/* Elements count */
	&asn_SPC_RANAP_Alt_RAB_Parameter_GuaranteedBitrateInf_specs_1	/* Additional specs */
};

