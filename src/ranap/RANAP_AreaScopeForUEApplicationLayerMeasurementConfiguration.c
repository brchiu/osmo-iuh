/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#include <osmocom/ranap/RANAP_AreaScopeForUEApplicationLayerMeasurementConfiguration.h>

static asn_oer_constraints_t asn_OER_type_RANAP_AreaScopeForUEApplicationLayerMeasurementConfiguration_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_RANAP_AreaScopeForUEApplicationLayerMeasurementConfiguration_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED | APC_EXTENSIBLE,  2,  2,  0,  3 }	/* (0..3,...) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_RANAP_AreaScopeForUEApplicationLayerMeasurementConfiguration_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_AreaScopeForUEApplicationLayerMeasurementConfiguration, choice.cellbased),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_CellBased,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cellbased"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_AreaScopeForUEApplicationLayerMeasurementConfiguration, choice.labased),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_LABased,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"labased"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_AreaScopeForUEApplicationLayerMeasurementConfiguration, choice.rabased),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_RABased,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rabased"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_AreaScopeForUEApplicationLayerMeasurementConfiguration, choice.plmn_area_based),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_PLMNBased,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"plmn-area-based"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_RANAP_AreaScopeForUEApplicationLayerMeasurementConfiguration_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* cellbased */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* labased */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* rabased */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* plmn-area-based */
};
asn_CHOICE_specifics_t asn_SPC_RANAP_AreaScopeForUEApplicationLayerMeasurementConfiguration_specs_1 = {
	sizeof(struct RANAP_AreaScopeForUEApplicationLayerMeasurementConfiguration),
	offsetof(struct RANAP_AreaScopeForUEApplicationLayerMeasurementConfiguration, _asn_ctx),
	offsetof(struct RANAP_AreaScopeForUEApplicationLayerMeasurementConfiguration, present),
	sizeof(((struct RANAP_AreaScopeForUEApplicationLayerMeasurementConfiguration *)0)->present),
	asn_MAP_RANAP_AreaScopeForUEApplicationLayerMeasurementConfiguration_tag2el_1,
	4,	/* Count of tags in the map */
	0, 0,
	4	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_RANAP_AreaScopeForUEApplicationLayerMeasurementConfiguration = {
	"AreaScopeForUEApplicationLayerMeasurementConfiguration",
	"AreaScopeForUEApplicationLayerMeasurementConfiguration",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_RANAP_AreaScopeForUEApplicationLayerMeasurementConfiguration_constr_1, &asn_PER_type_RANAP_AreaScopeForUEApplicationLayerMeasurementConfiguration_constr_1, CHOICE_constraint },
	asn_MBR_RANAP_AreaScopeForUEApplicationLayerMeasurementConfiguration_1,
	4,	/* Elements count */
	&asn_SPC_RANAP_AreaScopeForUEApplicationLayerMeasurementConfiguration_specs_1	/* Additional specs */
};
