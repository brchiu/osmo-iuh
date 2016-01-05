/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-PDU"
 * 	found in "../../asn1/ranap/RANAP-PDU.asn"
 */

#ifndef	_RANAP_SRNS_ContextResponse_H_
#define	_RANAP_SRNS_ContextResponse_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/ranap/RANAP_IE.h>
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RANAP_SRNS-ContextResponse */
typedef struct RANAP_SRNS_ContextResponse {
	struct srnS_ContextResponse_ies {
		A_SEQUENCE_OF(RANAP_IE_t) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} srnS_ContextResponse_ies;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RANAP_SRNS_ContextResponse_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_SRNS_ContextResponse;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_SRNS_ContextResponse_H_ */
#include <asn_internal.h>