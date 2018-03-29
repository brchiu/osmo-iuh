/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RUA-Containers"
 * 	found in "../../asn1/rua/rua-14.0.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RUA_ProtocolExtensionContainer_H_
#define	_RUA_ProtocolExtensionContainer_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct RUA_ConnectExtensions;
struct RUA_DirectTransferExtensions;
struct RUA_DisconnectExtensions;
struct RUA_ConnectionlessTransferExtensions;
struct RUA_ErrorIndicationExtensions;
struct RUA_CriticalityDiagnostics_ExtIEs;
struct RUA_CriticalityDiagnostics_IE_List_ExtIEs;

/* RUA_ProtocolExtensionContainer */
typedef struct RUA_ProtocolExtensionContainer_798P0 {
	A_SEQUENCE_OF(struct RUA_ConnectExtensions) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RUA_ProtocolExtensionContainer_798P0_t;
typedef struct RUA_ProtocolExtensionContainer_798P1 {
	A_SEQUENCE_OF(struct RUA_DirectTransferExtensions) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RUA_ProtocolExtensionContainer_798P1_t;
typedef struct RUA_ProtocolExtensionContainer_798P2 {
	A_SEQUENCE_OF(struct RUA_DisconnectExtensions) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RUA_ProtocolExtensionContainer_798P2_t;
typedef struct RUA_ProtocolExtensionContainer_798P3 {
	A_SEQUENCE_OF(struct RUA_ConnectionlessTransferExtensions) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RUA_ProtocolExtensionContainer_798P3_t;
typedef struct RUA_ProtocolExtensionContainer_798P4 {
	A_SEQUENCE_OF(struct RUA_ErrorIndicationExtensions) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RUA_ProtocolExtensionContainer_798P4_t;
typedef struct RUA_ProtocolExtensionContainer_798P5 {
	A_SEQUENCE_OF(struct RUA_CriticalityDiagnostics_ExtIEs) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RUA_ProtocolExtensionContainer_798P5_t;
typedef struct RUA_ProtocolExtensionContainer_798P6 {
	A_SEQUENCE_OF(struct RUA_CriticalityDiagnostics_IE_List_ExtIEs) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RUA_ProtocolExtensionContainer_798P6_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RUA_ProtocolExtensionContainer_798P0;
extern asn_SET_OF_specifics_t asn_SPC_RUA_ProtocolExtensionContainer_798P0_specs_1;
extern asn_TYPE_member_t asn_MBR_RUA_ProtocolExtensionContainer_798P0_1[1];
extern asn_per_constraints_t asn_PER_type_RUA_ProtocolExtensionContainer_798P0_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_RUA_ProtocolExtensionContainer_798P1;
extern asn_SET_OF_specifics_t asn_SPC_RUA_ProtocolExtensionContainer_798P1_specs_3;
extern asn_TYPE_member_t asn_MBR_RUA_ProtocolExtensionContainer_798P1_3[1];
extern asn_per_constraints_t asn_PER_type_RUA_ProtocolExtensionContainer_798P1_constr_3;
extern asn_TYPE_descriptor_t asn_DEF_RUA_ProtocolExtensionContainer_798P2;
extern asn_SET_OF_specifics_t asn_SPC_RUA_ProtocolExtensionContainer_798P2_specs_5;
extern asn_TYPE_member_t asn_MBR_RUA_ProtocolExtensionContainer_798P2_5[1];
extern asn_per_constraints_t asn_PER_type_RUA_ProtocolExtensionContainer_798P2_constr_5;
extern asn_TYPE_descriptor_t asn_DEF_RUA_ProtocolExtensionContainer_798P3;
extern asn_SET_OF_specifics_t asn_SPC_RUA_ProtocolExtensionContainer_798P3_specs_7;
extern asn_TYPE_member_t asn_MBR_RUA_ProtocolExtensionContainer_798P3_7[1];
extern asn_per_constraints_t asn_PER_type_RUA_ProtocolExtensionContainer_798P3_constr_7;
extern asn_TYPE_descriptor_t asn_DEF_RUA_ProtocolExtensionContainer_798P4;
extern asn_SET_OF_specifics_t asn_SPC_RUA_ProtocolExtensionContainer_798P4_specs_9;
extern asn_TYPE_member_t asn_MBR_RUA_ProtocolExtensionContainer_798P4_9[1];
extern asn_per_constraints_t asn_PER_type_RUA_ProtocolExtensionContainer_798P4_constr_9;
extern asn_TYPE_descriptor_t asn_DEF_RUA_ProtocolExtensionContainer_798P5;
extern asn_SET_OF_specifics_t asn_SPC_RUA_ProtocolExtensionContainer_798P5_specs_11;
extern asn_TYPE_member_t asn_MBR_RUA_ProtocolExtensionContainer_798P5_11[1];
extern asn_per_constraints_t asn_PER_type_RUA_ProtocolExtensionContainer_798P5_constr_11;
extern asn_TYPE_descriptor_t asn_DEF_RUA_ProtocolExtensionContainer_798P6;
extern asn_SET_OF_specifics_t asn_SPC_RUA_ProtocolExtensionContainer_798P6_specs_13;
extern asn_TYPE_member_t asn_MBR_RUA_ProtocolExtensionContainer_798P6_13[1];
extern asn_per_constraints_t asn_PER_type_RUA_ProtocolExtensionContainer_798P6_constr_13;

#ifdef __cplusplus
}
#endif

#endif	/* _RUA_ProtocolExtensionContainer_H_ */
#include <asn_internal.h>