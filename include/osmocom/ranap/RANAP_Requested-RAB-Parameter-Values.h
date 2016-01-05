/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/RANAP-IEs.asn"
 */

#ifndef	_RANAP_Requested_RAB_Parameter_Values_H_
#define	_RANAP_Requested_RAB_Parameter_Values_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/ranap/RANAP_Requested-RAB-Parameter-MaxBitrateList.h>
#include <osmocom/ranap/RANAP_Requested-RAB-Parameter-GuaranteedBitrateList.h>
#include <osmocom/ranap/RANAP_IE-Extensions.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RANAP_Requested-RAB-Parameter-Values */
typedef struct RANAP_Requested_RAB_Parameter_Values {
	RANAP_Requested_RAB_Parameter_MaxBitrateList_t	*requestedMaxBitrates	/* OPTIONAL */;
	RANAP_Requested_RAB_Parameter_GuaranteedBitrateList_t	*requestedGuaranteedBitrates	/* OPTIONAL */;
	RANAP_IE_Extensions_t	*iE_Extensions	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RANAP_Requested_RAB_Parameter_Values_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_Requested_RAB_Parameter_Values;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_Requested_RAB_Parameter_Values_H_ */
#include <asn_internal.h>
