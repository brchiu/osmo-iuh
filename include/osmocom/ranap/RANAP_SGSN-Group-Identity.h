/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RANAP_SGSN_Group_Identity_H_
#define	_RANAP_SGSN_Group_Identity_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/ranap/RANAP_Null-NRI.h>
#include <osmocom/ranap/RANAP_SGSN-Group-ID.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RANAP_SGSN_Group_Identity_PR {
	RANAP_SGSN_Group_Identity_PR_NOTHING,	/* No components present */
	RANAP_SGSN_Group_Identity_PR_null_NRI,
	RANAP_SGSN_Group_Identity_PR_sGSN_Group_ID
} RANAP_SGSN_Group_Identity_PR;

/* RANAP_SGSN-Group-Identity */
typedef struct RANAP_SGSN_Group_Identity {
	RANAP_SGSN_Group_Identity_PR present;
	union RANAP_SGSN_Group_Identity_u {
		RANAP_Null_NRI_t	 null_NRI;
		RANAP_SGSN_Group_ID_t	 sGSN_Group_ID;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RANAP_SGSN_Group_Identity_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_SGSN_Group_Identity;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_SGSN_Group_Identity_H_ */
#include <asn_internal.h>
