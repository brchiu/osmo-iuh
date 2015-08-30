/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-IEs"
 * 	found in "../../asn1/hnbap/HNBAP-IEs.asn"
 * 	`asn1c -gen-PER -fnative-types`
 */

#ifndef	_NeighbourInfoList_H_
#define	_NeighbourInfoList_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct HNBConfigInfo;

/* NeighbourInfoList */
typedef struct NeighbourInfoList {
	A_SEQUENCE_OF(struct HNBConfigInfo) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NeighbourInfoList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NeighbourInfoList;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "HNBConfigInfo.h"

#endif	/* _NeighbourInfoList_H_ */
#include <asn_internal.h>
