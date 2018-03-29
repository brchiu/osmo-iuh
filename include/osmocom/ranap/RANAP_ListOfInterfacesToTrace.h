/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RANAP_ListOfInterfacesToTrace_H_
#define	_RANAP_ListOfInterfacesToTrace_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct RANAP_InterfacesToTraceItem;

/* RANAP_ListOfInterfacesToTrace */
typedef struct RANAP_ListOfInterfacesToTrace {
	A_SEQUENCE_OF(struct RANAP_InterfacesToTraceItem) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RANAP_ListOfInterfacesToTrace_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_ListOfInterfacesToTrace;
extern asn_SET_OF_specifics_t asn_SPC_RANAP_ListOfInterfacesToTrace_specs_1;
extern asn_TYPE_member_t asn_MBR_RANAP_ListOfInterfacesToTrace_1[1];
extern asn_per_constraints_t asn_PER_type_RANAP_ListOfInterfacesToTrace_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_ListOfInterfacesToTrace_H_ */
#include <asn_internal.h>
