/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RANAP_SRB_TrCH_Mapping_H_
#define	_RANAP_SRB_TrCH_Mapping_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct RANAP_SRB_TrCH_MappingItem;

/* RANAP_SRB-TrCH-Mapping */
typedef struct RANAP_SRB_TrCH_Mapping {
	A_SEQUENCE_OF(struct RANAP_SRB_TrCH_MappingItem) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RANAP_SRB_TrCH_Mapping_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_SRB_TrCH_Mapping;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_SRB_TrCH_Mapping_H_ */
#include <asn_internal.h>
