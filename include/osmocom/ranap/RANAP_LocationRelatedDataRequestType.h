/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/RANAP-IEs.asn"
 */

#ifndef	_RANAP_LocationRelatedDataRequestType_H_
#define	_RANAP_LocationRelatedDataRequestType_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/ranap/RANAP_RequestedLocationRelatedDataType.h>
#include <osmocom/ranap/RANAP_RequestedGPSAssistanceData.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RANAP_LocationRelatedDataRequestType */
typedef struct RANAP_LocationRelatedDataRequestType {
	RANAP_RequestedLocationRelatedDataType_t	 requestedLocationRelatedDataType;
	RANAP_RequestedGPSAssistanceData_t	*requestedGPSAssistanceData	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RANAP_LocationRelatedDataRequestType_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_LocationRelatedDataRequestType;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_LocationRelatedDataRequestType_H_ */
#include <asn_internal.h>
