/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-PDU"
 * 	found in "../../asn1/ranap/RANAP-PDU.asn"
 */

#ifndef	_RANAP_ProtocolIE_FieldPair_H_
#define	_RANAP_ProtocolIE_FieldPair_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/ranap/RANAP_ProtocolIE-ID.h>
#include <osmocom/ranap/RANAP_Criticality.h>
#include <ANY.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RANAP_ProtocolIE-FieldPair */
typedef struct RANAP_ProtocolIE_FieldPair {
	RANAP_ProtocolIE_ID_t	 id;
	RANAP_Criticality_t	 firstCriticality;
	ANY_t	 firstValue;
	RANAP_Criticality_t	 secondCriticality;
	ANY_t	 secondValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RANAP_ProtocolIE_FieldPair_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_ProtocolIE_FieldPair;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_ProtocolIE_FieldPair_H_ */
#include <asn_internal.h>
