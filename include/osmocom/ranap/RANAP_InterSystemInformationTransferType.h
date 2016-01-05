/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/RANAP-IEs.asn"
 */

#ifndef	_RANAP_InterSystemInformationTransferType_H_
#define	_RANAP_InterSystemInformationTransferType_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/ranap/RANAP_RIM-Transfer.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RANAP_InterSystemInformationTransferType_PR {
	RANAP_InterSystemInformationTransferType_PR_NOTHING,	/* No components present */
	RANAP_InterSystemInformationTransferType_PR_rIM_Transfer,
	/* Extensions may appear below */
	
} RANAP_InterSystemInformationTransferType_PR;

/* RANAP_InterSystemInformationTransferType */
typedef struct RANAP_InterSystemInformationTransferType {
	RANAP_InterSystemInformationTransferType_PR present;
	union RANAP_InterSystemInformationTransferType_u {
		RANAP_RIM_Transfer_t	 rIM_Transfer;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RANAP_InterSystemInformationTransferType_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_InterSystemInformationTransferType;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_InterSystemInformationTransferType_H_ */
#include <asn_internal.h>
