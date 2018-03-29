/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-PDU-Contents"
 * 	found in "../../asn1/hnbap/hnbap-14.0.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_U_RNTIQueryResponse_H_
#define	_U_RNTIQueryResponse_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/hnbap/ProtocolIE-Container.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ProtocolExtensionContainer;

/* U-RNTIQueryResponse */
typedef struct U_RNTIQueryResponse {
	ProtocolIE_Container_1608P17_t	 protocolIEs;
	struct ProtocolExtensionContainer	*protocolExtensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} U_RNTIQueryResponse_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_U_RNTIQueryResponse;
extern asn_SEQUENCE_specifics_t asn_SPC_U_RNTIQueryResponse_specs_1;
extern asn_TYPE_member_t asn_MBR_U_RNTIQueryResponse_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _U_RNTIQueryResponse_H_ */
#include <asn_internal.h>
