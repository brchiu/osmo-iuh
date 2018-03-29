/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#include <osmocom/ranap/RANAP_GA-UncertaintyEllipse.h>

static int
memb_RANAP_uncertaintySemi_major_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 127)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_RANAP_uncertaintySemi_minor_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 127)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_RANAP_orientationOfMajorAxis_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 179)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_oer_constraints_t asn_OER_memb_RANAP_uncertaintySemi_major_constr_2 CC_NOTUSED = {
	{ 1, 1 }	/* (0..127) */,
	-1};
static asn_per_constraints_t asn_PER_memb_RANAP_uncertaintySemi_major_constr_2 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 7,  7,  0,  127 }	/* (0..127) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_RANAP_uncertaintySemi_minor_constr_3 CC_NOTUSED = {
	{ 1, 1 }	/* (0..127) */,
	-1};
static asn_per_constraints_t asn_PER_memb_RANAP_uncertaintySemi_minor_constr_3 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 7,  7,  0,  127 }	/* (0..127) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_RANAP_orientationOfMajorAxis_constr_4 CC_NOTUSED = {
	{ 1, 1 }	/* (0..179) */,
	-1};
static asn_per_constraints_t asn_PER_memb_RANAP_orientationOfMajorAxis_constr_4 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 8,  8,  0,  179 }	/* (0..179) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_RANAP_GA_UncertaintyEllipse_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_GA_UncertaintyEllipse, uncertaintySemi_major),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_RANAP_uncertaintySemi_major_constr_2, &asn_PER_memb_RANAP_uncertaintySemi_major_constr_2,  memb_RANAP_uncertaintySemi_major_constraint_1 },
		0, 0, /* No default value */
		"uncertaintySemi-major"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_GA_UncertaintyEllipse, uncertaintySemi_minor),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_RANAP_uncertaintySemi_minor_constr_3, &asn_PER_memb_RANAP_uncertaintySemi_minor_constr_3,  memb_RANAP_uncertaintySemi_minor_constraint_1 },
		0, 0, /* No default value */
		"uncertaintySemi-minor"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_GA_UncertaintyEllipse, orientationOfMajorAxis),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_RANAP_orientationOfMajorAxis_constr_4, &asn_PER_memb_RANAP_orientationOfMajorAxis_constr_4,  memb_RANAP_orientationOfMajorAxis_constraint_1 },
		0, 0, /* No default value */
		"orientationOfMajorAxis"
		},
};
static const ber_tlv_tag_t asn_DEF_RANAP_GA_UncertaintyEllipse_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RANAP_GA_UncertaintyEllipse_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* uncertaintySemi-major */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* uncertaintySemi-minor */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* orientationOfMajorAxis */
};
asn_SEQUENCE_specifics_t asn_SPC_RANAP_GA_UncertaintyEllipse_specs_1 = {
	sizeof(struct RANAP_GA_UncertaintyEllipse),
	offsetof(struct RANAP_GA_UncertaintyEllipse, _asn_ctx),
	asn_MAP_RANAP_GA_UncertaintyEllipse_tag2el_1,
	3,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	3,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_RANAP_GA_UncertaintyEllipse = {
	"GA-UncertaintyEllipse",
	"GA-UncertaintyEllipse",
	&asn_OP_SEQUENCE,
	asn_DEF_RANAP_GA_UncertaintyEllipse_tags_1,
	sizeof(asn_DEF_RANAP_GA_UncertaintyEllipse_tags_1)
		/sizeof(asn_DEF_RANAP_GA_UncertaintyEllipse_tags_1[0]), /* 1 */
	asn_DEF_RANAP_GA_UncertaintyEllipse_tags_1,	/* Same as above */
	sizeof(asn_DEF_RANAP_GA_UncertaintyEllipse_tags_1)
		/sizeof(asn_DEF_RANAP_GA_UncertaintyEllipse_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_RANAP_GA_UncertaintyEllipse_1,
	3,	/* Elements count */
	&asn_SPC_RANAP_GA_UncertaintyEllipse_specs_1	/* Additional specs */
};

