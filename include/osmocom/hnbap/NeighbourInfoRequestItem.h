/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-IEs"
 * 	found in "../../asn1/hnbap/hnbap-14.0.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_NeighbourInfoRequestItem_H_
#define	_NeighbourInfoRequestItem_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/hnbap/HNB-RNL-Identity.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ProtocolExtensionContainer;

/* NeighbourInfoRequestItem */
typedef struct NeighbourInfoRequestItem {
	HNB_RNL_Identity_t	 hnb_RNL_Identity;
	struct ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NeighbourInfoRequestItem_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NeighbourInfoRequestItem;
extern asn_SEQUENCE_specifics_t asn_SPC_NeighbourInfoRequestItem_specs_1;
extern asn_TYPE_member_t asn_MBR_NeighbourInfoRequestItem_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _NeighbourInfoRequestItem_H_ */
#include <asn_internal.h>
