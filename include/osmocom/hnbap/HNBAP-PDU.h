/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-PDU"
 * 	found in "../../asn1/hnbap/HNBAP-PDU.asn"
 * 	`asn1c -gen-PER`
 */

#ifndef	_HNBAP_PDU_H_
#define	_HNBAP_PDU_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/hnbap/InitiatingMessage.h>
#include <osmocom/hnbap/SuccessfulOutcome.h>
#include <osmocom/hnbap/UnsuccessfulOutcome.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum HNBAP_PDU_PR {
	HNBAP_PDU_PR_NOTHING,	/* No components present */
	HNBAP_PDU_PR_initiatingMessage,
	HNBAP_PDU_PR_successfulOutcome,
	HNBAP_PDU_PR_unsuccessfulOutcome,
	/* Extensions may appear below */
	
} HNBAP_PDU_PR;

/* HNBAP-PDU */
typedef struct HNBAP_PDU {
	HNBAP_PDU_PR present;
	union HNBAP_PDU_u {
		InitiatingMessage_t	 initiatingMessage;
		SuccessfulOutcome_t	 successfulOutcome;
		UnsuccessfulOutcome_t	 unsuccessfulOutcome;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} HNBAP_PDU_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_HNBAP_PDU;

#ifdef __cplusplus
}
#endif

#endif	/* _HNBAP_PDU_H_ */
#include <asn_internal.h>
