/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RANAP_RAB_Parameter_ExtendedMaxBitrateList_H_
#define	_RANAP_RAB_Parameter_ExtendedMaxBitrateList_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/ranap/RANAP_ExtendedMaxBitrate.h>
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RANAP_RAB-Parameter-ExtendedMaxBitrateList */
typedef struct RANAP_RAB_Parameter_ExtendedMaxBitrateList {
	A_SEQUENCE_OF(RANAP_ExtendedMaxBitrate_t) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RANAP_RAB_Parameter_ExtendedMaxBitrateList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_RAB_Parameter_ExtendedMaxBitrateList;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_RAB_Parameter_ExtendedMaxBitrateList_H_ */
#include <asn_internal.h>
