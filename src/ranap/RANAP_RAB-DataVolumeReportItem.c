/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-PDU-Contents"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#include <osmocom/ranap/RANAP_RAB-DataVolumeReportItem.h>

#include <osmocom/ranap/RANAP_DataVolumeList.h>
#include <osmocom/ranap/RANAP_ProtocolExtensionContainer.h>
static asn_TYPE_member_t asn_MBR_RANAP_RAB_DataVolumeReportItem_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_RAB_DataVolumeReportItem, rAB_ID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_RAB_ID,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rAB-ID"
		},
	{ ATF_POINTER, 2, offsetof(struct RANAP_RAB_DataVolumeReportItem, dl_UnsuccessfullyTransmittedDataVolume),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_DataVolumeList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-UnsuccessfullyTransmittedDataVolume"
		},
	{ ATF_POINTER, 1, offsetof(struct RANAP_RAB_DataVolumeReportItem, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_ProtocolExtensionContainer_7796P2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"iE-Extensions"
		},
};
static const int asn_MAP_RANAP_RAB_DataVolumeReportItem_oms_1[] = { 1, 2 };
static const ber_tlv_tag_t asn_DEF_RANAP_RAB_DataVolumeReportItem_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RANAP_RAB_DataVolumeReportItem_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rAB-ID */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* dl-UnsuccessfullyTransmittedDataVolume */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* iE-Extensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_RANAP_RAB_DataVolumeReportItem_specs_1 = {
	sizeof(struct RANAP_RAB_DataVolumeReportItem),
	offsetof(struct RANAP_RAB_DataVolumeReportItem, _asn_ctx),
	asn_MAP_RANAP_RAB_DataVolumeReportItem_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_RANAP_RAB_DataVolumeReportItem_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	3,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_RANAP_RAB_DataVolumeReportItem = {
	"RAB-DataVolumeReportItem",
	"RAB-DataVolumeReportItem",
	&asn_OP_SEQUENCE,
	asn_DEF_RANAP_RAB_DataVolumeReportItem_tags_1,
	sizeof(asn_DEF_RANAP_RAB_DataVolumeReportItem_tags_1)
		/sizeof(asn_DEF_RANAP_RAB_DataVolumeReportItem_tags_1[0]), /* 1 */
	asn_DEF_RANAP_RAB_DataVolumeReportItem_tags_1,	/* Same as above */
	sizeof(asn_DEF_RANAP_RAB_DataVolumeReportItem_tags_1)
		/sizeof(asn_DEF_RANAP_RAB_DataVolumeReportItem_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_RANAP_RAB_DataVolumeReportItem_1,
	3,	/* Elements count */
	&asn_SPC_RANAP_RAB_DataVolumeReportItem_specs_1	/* Additional specs */
};

