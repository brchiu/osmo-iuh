/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-PDU"
 * 	found in "../../asn1/hnbap/HNBAP-PDU.asn"
 * 	`asn1c -gen-PER -fnative-types`
 */

#ifndef	_UERegisterReject_H_
#define	_UERegisterReject_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct IE;

/* UERegisterReject */
typedef struct UERegisterReject {
	struct ueRegisterReject_ies {
		A_SEQUENCE_OF(struct IE) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} ueRegisterReject_ies;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UERegisterReject_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UERegisterReject;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "IE.h"

#endif	/* _UERegisterReject_H_ */
#include <asn_internal.h>
