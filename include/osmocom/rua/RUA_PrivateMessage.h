/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "RUA-PDU"
 * 	found in "../../asn1/rua/RUA-PDU.asn"
 */

#ifndef	_RUA_PrivateMessage_H_
#define	_RUA_PrivateMessage_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/rua/RUA_IE.h>
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RUA_PrivateMessage */
typedef struct RUA_PrivateMessage {
	struct privateMessage_ies {
		A_SEQUENCE_OF(RUA_IE_t) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} privateMessage_ies;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RUA_PrivateMessage_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RUA_PrivateMessage;

#ifdef __cplusplus
}
#endif

#endif	/* _RUA_PrivateMessage_H_ */
#include <asn_internal.h>
