/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RANAP_RNCTraceInformation_H_
#define	_RANAP_RNCTraceInformation_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/ranap/RANAP_TraceReference.h>
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RANAP_RNCTraceInformation__traceActivationIndicator {
	RANAP_RNCTraceInformation__traceActivationIndicator_activated	= 0,
	RANAP_RNCTraceInformation__traceActivationIndicator_deactivated	= 1
} e_RANAP_RNCTraceInformation__traceActivationIndicator;

/* Forward declarations */
struct RANAP_EquipmentsToBeTraced;
struct RANAP_ProtocolExtensionContainer;

/* RANAP_RNCTraceInformation */
typedef struct RANAP_RNCTraceInformation {
	RANAP_TraceReference_t	 traceReference;
	long	 traceActivationIndicator;
	struct RANAP_EquipmentsToBeTraced	*equipmentsToBeTraced;	/* OPTIONAL */
	struct RANAP_ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RANAP_RNCTraceInformation_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_RANAP_traceActivationIndicator_3;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_RNCTraceInformation;
extern asn_SEQUENCE_specifics_t asn_SPC_RANAP_RNCTraceInformation_specs_1;
extern asn_TYPE_member_t asn_MBR_RANAP_RNCTraceInformation_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_RNCTraceInformation_H_ */
#include <asn_internal.h>
