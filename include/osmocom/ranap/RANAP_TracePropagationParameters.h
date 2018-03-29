/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RANAP_TracePropagationParameters_H_
#define	_RANAP_TracePropagationParameters_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/ranap/RANAP_TraceRecordingSessionReference.h>
#include <osmocom/ranap/RANAP_TraceDepth.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct RANAP_ListOfInterfacesToTrace;
struct RANAP_ProtocolExtensionContainer;

/* RANAP_TracePropagationParameters */
typedef struct RANAP_TracePropagationParameters {
	RANAP_TraceRecordingSessionReference_t	 traceRecordingSessionReference;
	RANAP_TraceDepth_t	 traceDepth;
	struct RANAP_ListOfInterfacesToTrace	*listOfInterfacesToTrace;	/* OPTIONAL */
	struct RANAP_ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RANAP_TracePropagationParameters_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_TracePropagationParameters;
extern asn_SEQUENCE_specifics_t asn_SPC_RANAP_TracePropagationParameters_specs_1;
extern asn_TYPE_member_t asn_MBR_RANAP_TracePropagationParameters_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_TracePropagationParameters_H_ */
#include <asn_internal.h>
