/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/RANAP-IEs.asn"
 */

#include <osmocom/ranap/RANAP_UPInformation.h>

static asn_TYPE_member_t asn_MBR_RANAP_UPInformation_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_UPInformation, frameSeqNoUL),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_FrameSequenceNumber,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"frameSeqNoUL"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_UPInformation, frameSeqNoDL),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_FrameSequenceNumber,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"frameSeqNoDL"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_UPInformation, pdu14FrameSeqNoUL),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_PDUType14FrameSequenceNumber,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"pdu14FrameSeqNoUL"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_UPInformation, pdu14FrameSeqNoDL),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_PDUType14FrameSequenceNumber,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"pdu14FrameSeqNoDL"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_UPInformation, dataPDUType),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_DataPDUType,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"dataPDUType"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_UPInformation, upinitialisationFrame),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_UPInitialisationFrame,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"upinitialisationFrame"
		},
	{ ATF_POINTER, 1, offsetof(struct RANAP_UPInformation, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_IE_Extensions,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"iE-Extensions"
		},
};
static const int asn_MAP_RANAP_UPInformation_oms_1[] = { 6 };
static const ber_tlv_tag_t asn_DEF_RANAP_UPInformation_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RANAP_UPInformation_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* frameSeqNoUL */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* frameSeqNoDL */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* pdu14FrameSeqNoUL */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* pdu14FrameSeqNoDL */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* dataPDUType */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* upinitialisationFrame */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 } /* iE-Extensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_RANAP_UPInformation_specs_1 = {
	sizeof(struct RANAP_UPInformation),
	offsetof(struct RANAP_UPInformation, _asn_ctx),
	asn_MAP_RANAP_UPInformation_tag2el_1,
	7,	/* Count of tags in the map */
	asn_MAP_RANAP_UPInformation_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	6,	/* Start extensions */
	8	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_RANAP_UPInformation = {
	"RANAP_UPInformation",
	"RANAP_UPInformation",
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
	asn_DEF_RANAP_UPInformation_tags_1,
	sizeof(asn_DEF_RANAP_UPInformation_tags_1)
		/sizeof(asn_DEF_RANAP_UPInformation_tags_1[0]), /* 1 */
	asn_DEF_RANAP_UPInformation_tags_1,	/* Same as above */
	sizeof(asn_DEF_RANAP_UPInformation_tags_1)
		/sizeof(asn_DEF_RANAP_UPInformation_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_RANAP_UPInformation_1,
	7,	/* Elements count */
	&asn_SPC_RANAP_UPInformation_specs_1	/* Additional specs */
};

