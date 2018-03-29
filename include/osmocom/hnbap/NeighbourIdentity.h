/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-IEs"
 * 	found in "../../asn1/hnbap/hnbap-14.0.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_NeighbourIdentity_H_
#define	_NeighbourIdentity_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/hnbap/HNB-RNL-Identity.h>
#include <osmocom/hnbap/CellIdentity.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum NeighbourIdentity_PR {
	NeighbourIdentity_PR_NOTHING,	/* No components present */
	NeighbourIdentity_PR_hNB_RNL_Identity,
	NeighbourIdentity_PR_cell_ID
	/* Extensions may appear below */
	
} NeighbourIdentity_PR;

/* NeighbourIdentity */
typedef struct NeighbourIdentity {
	NeighbourIdentity_PR present;
	union NeighbourIdentity_u {
		HNB_RNL_Identity_t	 hNB_RNL_Identity;
		CellIdentity_t	 cell_ID;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NeighbourIdentity_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NeighbourIdentity;
extern asn_CHOICE_specifics_t asn_SPC_NeighbourIdentity_specs_1;
extern asn_TYPE_member_t asn_MBR_NeighbourIdentity_1[2];
extern asn_per_constraints_t asn_PER_type_NeighbourIdentity_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _NeighbourIdentity_H_ */
#include <asn_internal.h>
