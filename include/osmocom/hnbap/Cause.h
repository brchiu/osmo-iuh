/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-IEs"
 * 	found in "../../asn1/hnbap/HNBAP-IEs.asn"
 * 	`asn1c -gen-PER`
 */

#ifndef	_Cause_H_
#define	_Cause_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/hnbap/CauseRadioNetwork.h>
#include <osmocom/hnbap/CauseTransport.h>
#include <osmocom/hnbap/CauseProtocol.h>
#include <osmocom/hnbap/CauseMisc.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Cause_PR {
	Cause_PR_NOTHING,	/* No components present */
	Cause_PR_radioNetwork,
	Cause_PR_transport,
	Cause_PR_protocol,
	Cause_PR_misc,
	/* Extensions may appear below */
	
} Cause_PR;

/* Cause */
typedef struct Cause {
	Cause_PR present;
	union Cause_u {
		CauseRadioNetwork_t	 radioNetwork;
		CauseTransport_t	 transport;
		CauseProtocol_t	 protocol;
		CauseMisc_t	 misc;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Cause_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Cause;

#ifdef __cplusplus
}
#endif

#endif	/* _Cause_H_ */
#include <asn_internal.h>
