/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-IEs"
 * 	found in "../../asn1/hnbap/HNBAP-IEs.asn"
 * 	`asn1c -gen-PER -fnative-types`
 */

#ifndef	_LAI_H_
#define	_LAI_H_


#include <asn_application.h>

/* Including external dependencies */
#include "PLMNidentity.h"
#include "LAC.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* LAI */
typedef struct LAI {
	PLMNidentity_t	 pLMNID;
	LAC_t	 lAC;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LAI_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LAI;

#ifdef __cplusplus
}
#endif

#endif	/* _LAI_H_ */
#include <asn_internal.h>
