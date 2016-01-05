/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-IEs"
 * 	found in "../../asn1/hnbap/HNBAP-IEs.asn"
 * 	`asn1c -gen-PER`
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
struct IE_Extensions;

/* NeighbourInfoRequestItem */
typedef struct NeighbourInfoRequestItem {
	HNB_RNL_Identity_t	 hnb_RNL_Identity;
	struct IE_Extensions	*iE_Extensions	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NeighbourInfoRequestItem_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NeighbourInfoRequestItem;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include <osmocom/hnbap/IE-Extensions.h>

#endif	/* _NeighbourInfoRequestItem_H_ */
#include <asn_internal.h>
