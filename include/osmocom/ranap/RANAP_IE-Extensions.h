/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/RANAP-IEs.asn"
 */

#ifndef	_RANAP_IE_Extensions_H_
#define	_RANAP_IE_Extensions_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/ranap/RANAP_IE.h>
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RANAP_IE-Extensions */
typedef struct RANAP_IE_Extensions {
	A_SEQUENCE_OF(RANAP_IE_t) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RANAP_IE_Extensions_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_IE_Extensions;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_IE_Extensions_H_ */
#include <asn_internal.h>
