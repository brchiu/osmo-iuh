/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RANAP_RAI_H_
#define	_RANAP_RAI_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/ranap/RANAP_LAI.h>
#include <osmocom/ranap/RANAP_RAC.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct RANAP_ProtocolExtensionContainer;

/* RANAP_RAI */
typedef struct RANAP_RAI {
	RANAP_LAI_t	 lAI;
	RANAP_RAC_t	 rAC;
	struct RANAP_ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RANAP_RAI_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_RAI;
extern asn_SEQUENCE_specifics_t asn_SPC_RANAP_RAI_specs_1;
extern asn_TYPE_member_t asn_MBR_RANAP_RAI_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_RAI_H_ */
#include <asn_internal.h>
