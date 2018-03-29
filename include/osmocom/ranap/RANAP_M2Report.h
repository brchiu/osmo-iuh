/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RANAP_M2Report_H_
#define	_RANAP_M2Report_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/ranap/RANAP_MDT-Report-Parameters.h>
#include <osmocom/ranap/RANAP_Event1I-Parameters.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RANAP_M2Report_PR {
	RANAP_M2Report_PR_NOTHING,	/* No components present */
	RANAP_M2Report_PR_periodic,
	RANAP_M2Report_PR_event1I
	/* Extensions may appear below */
	
} RANAP_M2Report_PR;

/* RANAP_M2Report */
typedef struct RANAP_M2Report {
	RANAP_M2Report_PR present;
	union RANAP_M2Report_u {
		RANAP_MDT_Report_Parameters_t	 periodic;
		RANAP_Event1I_Parameters_t	 event1I;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RANAP_M2Report_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_M2Report;
extern asn_CHOICE_specifics_t asn_SPC_RANAP_M2Report_specs_1;
extern asn_TYPE_member_t asn_MBR_RANAP_M2Report_1[2];
extern asn_per_constraints_t asn_PER_type_RANAP_M2Report_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_M2Report_H_ */
#include <asn_internal.h>
