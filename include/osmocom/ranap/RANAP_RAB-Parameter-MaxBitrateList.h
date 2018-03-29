/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RANAP_RAB_Parameter_MaxBitrateList_H_
#define	_RANAP_RAB_Parameter_MaxBitrateList_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/ranap/RANAP_MaxBitrate.h>
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RANAP_RAB-Parameter-MaxBitrateList */
typedef struct RANAP_RAB_Parameter_MaxBitrateList {
	A_SEQUENCE_OF(RANAP_MaxBitrate_t) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RANAP_RAB_Parameter_MaxBitrateList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_RAB_Parameter_MaxBitrateList;
extern asn_SET_OF_specifics_t asn_SPC_RANAP_RAB_Parameter_MaxBitrateList_specs_1;
extern asn_TYPE_member_t asn_MBR_RANAP_RAB_Parameter_MaxBitrateList_1[1];
extern asn_per_constraints_t asn_PER_type_RANAP_RAB_Parameter_MaxBitrateList_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_RAB_Parameter_MaxBitrateList_H_ */
#include <asn_internal.h>
