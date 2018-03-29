/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-PDU-Contents"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RANAP_RAB_ModifyItem_H_
#define	_RANAP_RAB_ModifyItem_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/ranap/RANAP_RAB-ID.h>
#include <osmocom/ranap/RANAP_Requested-RAB-Parameter-Values.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct RANAP_ProtocolExtensionContainer;

/* RANAP_RAB-ModifyItem */
typedef struct RANAP_RAB_ModifyItem {
	RANAP_RAB_ID_t	 rAB_ID;
	RANAP_Requested_RAB_Parameter_Values_t	 requested_RAB_Parameter_Values;
	struct RANAP_ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RANAP_RAB_ModifyItem_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_RAB_ModifyItem;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_RAB_ModifyItem_H_ */
#include <asn_internal.h>
