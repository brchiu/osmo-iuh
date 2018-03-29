/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RANAP_GERAN_Cell_ID_H_
#define	_RANAP_GERAN_Cell_ID_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/ranap/RANAP_LAI.h>
#include <osmocom/ranap/RANAP_RAC.h>
#include <osmocom/ranap/RANAP_CI.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct RANAP_ProtocolExtensionContainer;

/* RANAP_GERAN-Cell-ID */
typedef struct RANAP_GERAN_Cell_ID {
	RANAP_LAI_t	 lAI;
	RANAP_RAC_t	 rAC;
	RANAP_CI_t	 cI;
	struct RANAP_ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RANAP_GERAN_Cell_ID_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_GERAN_Cell_ID;
extern asn_SEQUENCE_specifics_t asn_SPC_RANAP_GERAN_Cell_ID_specs_1;
extern asn_TYPE_member_t asn_MBR_RANAP_GERAN_Cell_ID_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_GERAN_Cell_ID_H_ */
#include <asn_internal.h>
