/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RUA-CommonDataTypes"
 * 	found in "../../asn1/rua/rua-14.0.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RUA_PrivateIE_ID_H_
#define	_RUA_PrivateIE_ID_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include <OBJECT_IDENTIFIER.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RUA_PrivateIE_ID_PR {
	RUA_PrivateIE_ID_PR_NOTHING,	/* No components present */
	RUA_PrivateIE_ID_PR_local,
	RUA_PrivateIE_ID_PR_global
} RUA_PrivateIE_ID_PR;

/* RUA_PrivateIE-ID */
typedef struct RUA_PrivateIE_ID {
	RUA_PrivateIE_ID_PR present;
	union RUA_PrivateIE_ID_u {
		long	 local;
		OBJECT_IDENTIFIER_t	 global;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RUA_PrivateIE_ID_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RUA_PrivateIE_ID;
extern asn_CHOICE_specifics_t asn_SPC_RUA_PrivateIE_ID_specs_1;
extern asn_TYPE_member_t asn_MBR_RUA_PrivateIE_ID_1[2];
extern asn_per_constraints_t asn_PER_type_RUA_PrivateIE_ID_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _RUA_PrivateIE_ID_H_ */
#include <asn_internal.h>
