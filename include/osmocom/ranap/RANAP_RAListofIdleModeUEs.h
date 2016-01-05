/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/RANAP-IEs.asn"
 */

#ifndef	_RANAP_RAListofIdleModeUEs_H_
#define	_RANAP_RAListofIdleModeUEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/ranap/RANAP_NotEmptyRAListofIdleModeUEs.h>
#include <NativeEnumerated.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RANAP_RAListofIdleModeUEs_PR {
	RANAP_RAListofIdleModeUEs_PR_NOTHING,	/* No components present */
	RANAP_RAListofIdleModeUEs_PR_notEmptyRAListofIdleModeUEs,
	RANAP_RAListofIdleModeUEs_PR_emptyFullRAListofIdleModeUEs,
	/* Extensions may appear below */
	
} RANAP_RAListofIdleModeUEs_PR;
typedef enum emptyFullRAListofIdleModeUEs {
	emptyFullRAListofIdleModeUEs_emptylist	= 0,
	emptyFullRAListofIdleModeUEs_fulllist	= 1
	/*
	 * Enumeration is extensible
	 */
} e_emptyFullRAListofIdleModeUEs;

/* RANAP_RAListofIdleModeUEs */
typedef struct RANAP_RAListofIdleModeUEs {
	RANAP_RAListofIdleModeUEs_PR present;
	union RANAP_RAListofIdleModeUEs_u {
		RANAP_NotEmptyRAListofIdleModeUEs_t	 notEmptyRAListofIdleModeUEs;
		long	 emptyFullRAListofIdleModeUEs;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RANAP_RAListofIdleModeUEs_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_emptyFullRAListofIdleModeUEs_3;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_RAListofIdleModeUEs;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_RAListofIdleModeUEs_H_ */
#include <asn_internal.h>
