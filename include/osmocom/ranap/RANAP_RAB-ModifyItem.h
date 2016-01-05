/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-PDU"
 * 	found in "../../asn1/ranap/RANAP-PDU.asn"
 */

#ifndef	_RANAP_RAB_ModifyItem_H_
#define	_RANAP_RAB_ModifyItem_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/ranap/RANAP_RAB-ID.h>
#include <osmocom/ranap/RANAP_Requested-RAB-Parameter-Values.h>
#include <osmocom/ranap/RANAP_ProtocolExtensionContainer.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RANAP_RAB-ModifyItem */
typedef struct RANAP_RAB_ModifyItem {
	RANAP_RAB_ID_t	 rAB_ID;
	RANAP_Requested_RAB_Parameter_Values_t	 requested_RAB_Parameter_Values;
	RANAP_ProtocolExtensionContainer_t	*iE_Extensions	/* OPTIONAL */;
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
