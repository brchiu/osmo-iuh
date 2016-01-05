/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/RANAP-IEs.asn"
 */

#include <osmocom/ranap/RANAP_IRAT-Measurement-Configuration.h>

static int
memb_rSRP_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0l && value <= 97l)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_rSRQ_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0l && value <= 34l)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_memb_rSRP_constr_2 GCC_NOTUSED = {
	{ APC_CONSTRAINED,	 7,  7,  0l,  97l }	/* (0..97) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_rSRQ_constr_3 GCC_NOTUSED = {
	{ APC_CONSTRAINED,	 6,  6,  0l,  34l }	/* (0..34) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_RANAP_IRAT_Measurement_Configuration_1[] = {
	{ ATF_POINTER, 2, offsetof(struct RANAP_IRAT_Measurement_Configuration, rSRP),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_rSRP_constraint_1,
		&asn_PER_memb_rSRP_constr_2,
		0,
		"rSRP"
		},
	{ ATF_POINTER, 1, offsetof(struct RANAP_IRAT_Measurement_Configuration, rSRQ),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_rSRQ_constraint_1,
		&asn_PER_memb_rSRQ_constr_3,
		0,
		"rSRQ"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_IRAT_Measurement_Configuration, iRATmeasurementParameters),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_IRATmeasurementParameters,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"iRATmeasurementParameters"
		},
	{ ATF_POINTER, 1, offsetof(struct RANAP_IRAT_Measurement_Configuration, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_IE_Extensions,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"iE-Extensions"
		},
};
static const int asn_MAP_RANAP_IRAT_Measurement_Configuration_oms_1[] = { 0, 1, 3 };
static const ber_tlv_tag_t asn_DEF_RANAP_IRAT_Measurement_Configuration_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RANAP_IRAT_Measurement_Configuration_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rSRP */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* rSRQ */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* iRATmeasurementParameters */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* iE-Extensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_RANAP_IRAT_Measurement_Configuration_specs_1 = {
	sizeof(struct RANAP_IRAT_Measurement_Configuration),
	offsetof(struct RANAP_IRAT_Measurement_Configuration, _asn_ctx),
	asn_MAP_RANAP_IRAT_Measurement_Configuration_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_RANAP_IRAT_Measurement_Configuration_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_RANAP_IRAT_Measurement_Configuration = {
	"RANAP_IRAT-Measurement-Configuration",
	"RANAP_IRAT-Measurement-Configuration",
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
	asn_DEF_RANAP_IRAT_Measurement_Configuration_tags_1,
	sizeof(asn_DEF_RANAP_IRAT_Measurement_Configuration_tags_1)
		/sizeof(asn_DEF_RANAP_IRAT_Measurement_Configuration_tags_1[0]), /* 1 */
	asn_DEF_RANAP_IRAT_Measurement_Configuration_tags_1,	/* Same as above */
	sizeof(asn_DEF_RANAP_IRAT_Measurement_Configuration_tags_1)
		/sizeof(asn_DEF_RANAP_IRAT_Measurement_Configuration_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_RANAP_IRAT_Measurement_Configuration_1,
	4,	/* Elements count */
	&asn_SPC_RANAP_IRAT_Measurement_Configuration_specs_1	/* Additional specs */
};

