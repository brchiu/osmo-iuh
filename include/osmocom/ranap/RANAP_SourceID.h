/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RANAP_SourceID_H_
#define	_RANAP_SourceID_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/ranap/RANAP_SourceRNC-ID.h>
#include <osmocom/ranap/RANAP_SAI.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RANAP_SourceID_PR {
	RANAP_SourceID_PR_NOTHING,	/* No components present */
	RANAP_SourceID_PR_sourceRNC_ID,
	RANAP_SourceID_PR_sAI
	/* Extensions may appear below */
	
} RANAP_SourceID_PR;

/* RANAP_SourceID */
typedef struct RANAP_SourceID {
	RANAP_SourceID_PR present;
	union RANAP_SourceID_u {
		RANAP_SourceRNC_ID_t	 sourceRNC_ID;
		RANAP_SAI_t	 sAI;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RANAP_SourceID_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_SourceID;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_SourceID_H_ */
#include <asn_internal.h>
