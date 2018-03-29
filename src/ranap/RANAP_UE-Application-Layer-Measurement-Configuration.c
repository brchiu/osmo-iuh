/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#include <osmocom/ranap/RANAP_UE-Application-Layer-Measurement-Configuration.h>

static int
memb_RANAP_applicationLayerContainerForMeasurementConfiguration_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	size = st->size;
	
	if((size >= 1 && size <= 1000)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_oer_constraints_t asn_OER_memb_RANAP_applicationLayerContainerForMeasurementConfiguration_constr_2 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..1000)) */};
static asn_per_constraints_t asn_PER_memb_RANAP_applicationLayerContainerForMeasurementConfiguration_constr_2 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 10,  10,  1,  1000 }	/* (SIZE(1..1000)) */,
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_RANAP_UE_Application_Layer_Measurement_Configuration_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_UE_Application_Layer_Measurement_Configuration, applicationLayerContainerForMeasurementConfiguration),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_OCTET_STRING,
		0,
		{ &asn_OER_memb_RANAP_applicationLayerContainerForMeasurementConfiguration_constr_2, &asn_PER_memb_RANAP_applicationLayerContainerForMeasurementConfiguration_constr_2,  memb_RANAP_applicationLayerContainerForMeasurementConfiguration_constraint_1 },
		0, 0, /* No default value */
		"applicationLayerContainerForMeasurementConfiguration"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_UE_Application_Layer_Measurement_Configuration, areaScopeForUEApplicationLayerMeasurementConfiguration),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_RANAP_AreaScopeForUEApplicationLayerMeasurementConfiguration,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"areaScopeForUEApplicationLayerMeasurementConfiguration"
		},
};
static const ber_tlv_tag_t asn_DEF_RANAP_UE_Application_Layer_Measurement_Configuration_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RANAP_UE_Application_Layer_Measurement_Configuration_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* applicationLayerContainerForMeasurementConfiguration */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* areaScopeForUEApplicationLayerMeasurementConfiguration */
};
static asn_SEQUENCE_specifics_t asn_SPC_RANAP_UE_Application_Layer_Measurement_Configuration_specs_1 = {
	sizeof(struct RANAP_UE_Application_Layer_Measurement_Configuration),
	offsetof(struct RANAP_UE_Application_Layer_Measurement_Configuration, _asn_ctx),
	asn_MAP_RANAP_UE_Application_Layer_Measurement_Configuration_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	2,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_RANAP_UE_Application_Layer_Measurement_Configuration = {
	"UE-Application-Layer-Measurement-Configuration",
	"UE-Application-Layer-Measurement-Configuration",
	&asn_OP_SEQUENCE,
	asn_DEF_RANAP_UE_Application_Layer_Measurement_Configuration_tags_1,
	sizeof(asn_DEF_RANAP_UE_Application_Layer_Measurement_Configuration_tags_1)
		/sizeof(asn_DEF_RANAP_UE_Application_Layer_Measurement_Configuration_tags_1[0]), /* 1 */
	asn_DEF_RANAP_UE_Application_Layer_Measurement_Configuration_tags_1,	/* Same as above */
	sizeof(asn_DEF_RANAP_UE_Application_Layer_Measurement_Configuration_tags_1)
		/sizeof(asn_DEF_RANAP_UE_Application_Layer_Measurement_Configuration_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_RANAP_UE_Application_Layer_Measurement_Configuration_1,
	2,	/* Elements count */
	&asn_SPC_RANAP_UE_Application_Layer_Measurement_Configuration_specs_1	/* Additional specs */
};

