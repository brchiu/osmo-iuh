/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-Containers"
 * 	found in "../../asn1/hnbap/hnbap-14.0.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_ProtocolIE_Container_H_
#define	_ProtocolIE_Container_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct HNBRegisterRequestIEs;
struct HNBRegisterResponseIEs;
struct HNBRegisterRejectIEs;
struct HNBDe_RegisterIEs;
struct UERegisterRequestIEs;
struct UERegisterAcceptIEs;
struct UERegisterRejectIEs;
struct UEDe_RegisterIEs;
struct CSGMembershipUpdateIEs;
struct TNLUpdateRequestIEs;
struct TNLUpdateResponseIEs;
struct TNLUpdateFailureIEs;
struct HNBConfigTransferRequestIEs;
struct HNBConfigTransferResponseIEs;
struct RelocationCompleteIEs;
struct ErrorIndicationIEs;
struct U_RNTIQueryRequestIEs;
struct U_RNTIQueryResponseIEs;

/* ProtocolIE-Container */
typedef struct ProtocolIE_Container_1608P0 {
	A_SEQUENCE_OF(struct HNBRegisterRequestIEs) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ProtocolIE_Container_1608P0_t;
typedef struct ProtocolIE_Container_1608P1 {
	A_SEQUENCE_OF(struct HNBRegisterResponseIEs) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ProtocolIE_Container_1608P1_t;
typedef struct ProtocolIE_Container_1608P2 {
	A_SEQUENCE_OF(struct HNBRegisterRejectIEs) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ProtocolIE_Container_1608P2_t;
typedef struct ProtocolIE_Container_1608P3 {
	A_SEQUENCE_OF(struct HNBDe_RegisterIEs) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ProtocolIE_Container_1608P3_t;
typedef struct ProtocolIE_Container_1608P4 {
	A_SEQUENCE_OF(struct UERegisterRequestIEs) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ProtocolIE_Container_1608P4_t;
typedef struct ProtocolIE_Container_1608P5 {
	A_SEQUENCE_OF(struct UERegisterAcceptIEs) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ProtocolIE_Container_1608P5_t;
typedef struct ProtocolIE_Container_1608P6 {
	A_SEQUENCE_OF(struct UERegisterRejectIEs) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ProtocolIE_Container_1608P6_t;
typedef struct ProtocolIE_Container_1608P7 {
	A_SEQUENCE_OF(struct UEDe_RegisterIEs) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ProtocolIE_Container_1608P7_t;
typedef struct ProtocolIE_Container_1608P8 {
	A_SEQUENCE_OF(struct CSGMembershipUpdateIEs) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ProtocolIE_Container_1608P8_t;
typedef struct ProtocolIE_Container_1608P9 {
	A_SEQUENCE_OF(struct TNLUpdateRequestIEs) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ProtocolIE_Container_1608P9_t;
typedef struct ProtocolIE_Container_1608P10 {
	A_SEQUENCE_OF(struct TNLUpdateResponseIEs) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ProtocolIE_Container_1608P10_t;
typedef struct ProtocolIE_Container_1608P11 {
	A_SEQUENCE_OF(struct TNLUpdateFailureIEs) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ProtocolIE_Container_1608P11_t;
typedef struct ProtocolIE_Container_1608P12 {
	A_SEQUENCE_OF(struct HNBConfigTransferRequestIEs) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ProtocolIE_Container_1608P12_t;
typedef struct ProtocolIE_Container_1608P13 {
	A_SEQUENCE_OF(struct HNBConfigTransferResponseIEs) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ProtocolIE_Container_1608P13_t;
typedef struct ProtocolIE_Container_1608P14 {
	A_SEQUENCE_OF(struct RelocationCompleteIEs) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ProtocolIE_Container_1608P14_t;
typedef struct ProtocolIE_Container_1608P15 {
	A_SEQUENCE_OF(struct ErrorIndicationIEs) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ProtocolIE_Container_1608P15_t;
typedef struct ProtocolIE_Container_1608P16 {
	A_SEQUENCE_OF(struct U_RNTIQueryRequestIEs) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ProtocolIE_Container_1608P16_t;
typedef struct ProtocolIE_Container_1608P17 {
	A_SEQUENCE_OF(struct U_RNTIQueryResponseIEs) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ProtocolIE_Container_1608P17_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ProtocolIE_Container_1608P0;
extern asn_SET_OF_specifics_t asn_SPC_ProtocolIE_Container_1608P0_specs_1;
extern asn_TYPE_member_t asn_MBR_ProtocolIE_Container_1608P0_1[1];
extern asn_per_constraints_t asn_PER_type_ProtocolIE_Container_1608P0_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_ProtocolIE_Container_1608P1;
extern asn_SET_OF_specifics_t asn_SPC_ProtocolIE_Container_1608P1_specs_3;
extern asn_TYPE_member_t asn_MBR_ProtocolIE_Container_1608P1_3[1];
extern asn_per_constraints_t asn_PER_type_ProtocolIE_Container_1608P1_constr_3;
extern asn_TYPE_descriptor_t asn_DEF_ProtocolIE_Container_1608P2;
extern asn_SET_OF_specifics_t asn_SPC_ProtocolIE_Container_1608P2_specs_5;
extern asn_TYPE_member_t asn_MBR_ProtocolIE_Container_1608P2_5[1];
extern asn_per_constraints_t asn_PER_type_ProtocolIE_Container_1608P2_constr_5;
extern asn_TYPE_descriptor_t asn_DEF_ProtocolIE_Container_1608P3;
extern asn_SET_OF_specifics_t asn_SPC_ProtocolIE_Container_1608P3_specs_7;
extern asn_TYPE_member_t asn_MBR_ProtocolIE_Container_1608P3_7[1];
extern asn_per_constraints_t asn_PER_type_ProtocolIE_Container_1608P3_constr_7;
extern asn_TYPE_descriptor_t asn_DEF_ProtocolIE_Container_1608P4;
extern asn_SET_OF_specifics_t asn_SPC_ProtocolIE_Container_1608P4_specs_9;
extern asn_TYPE_member_t asn_MBR_ProtocolIE_Container_1608P4_9[1];
extern asn_per_constraints_t asn_PER_type_ProtocolIE_Container_1608P4_constr_9;
extern asn_TYPE_descriptor_t asn_DEF_ProtocolIE_Container_1608P5;
extern asn_SET_OF_specifics_t asn_SPC_ProtocolIE_Container_1608P5_specs_11;
extern asn_TYPE_member_t asn_MBR_ProtocolIE_Container_1608P5_11[1];
extern asn_per_constraints_t asn_PER_type_ProtocolIE_Container_1608P5_constr_11;
extern asn_TYPE_descriptor_t asn_DEF_ProtocolIE_Container_1608P6;
extern asn_SET_OF_specifics_t asn_SPC_ProtocolIE_Container_1608P6_specs_13;
extern asn_TYPE_member_t asn_MBR_ProtocolIE_Container_1608P6_13[1];
extern asn_per_constraints_t asn_PER_type_ProtocolIE_Container_1608P6_constr_13;
extern asn_TYPE_descriptor_t asn_DEF_ProtocolIE_Container_1608P7;
extern asn_SET_OF_specifics_t asn_SPC_ProtocolIE_Container_1608P7_specs_15;
extern asn_TYPE_member_t asn_MBR_ProtocolIE_Container_1608P7_15[1];
extern asn_per_constraints_t asn_PER_type_ProtocolIE_Container_1608P7_constr_15;
extern asn_TYPE_descriptor_t asn_DEF_ProtocolIE_Container_1608P8;
extern asn_SET_OF_specifics_t asn_SPC_ProtocolIE_Container_1608P8_specs_17;
extern asn_TYPE_member_t asn_MBR_ProtocolIE_Container_1608P8_17[1];
extern asn_per_constraints_t asn_PER_type_ProtocolIE_Container_1608P8_constr_17;
extern asn_TYPE_descriptor_t asn_DEF_ProtocolIE_Container_1608P9;
extern asn_SET_OF_specifics_t asn_SPC_ProtocolIE_Container_1608P9_specs_19;
extern asn_TYPE_member_t asn_MBR_ProtocolIE_Container_1608P9_19[1];
extern asn_per_constraints_t asn_PER_type_ProtocolIE_Container_1608P9_constr_19;
extern asn_TYPE_descriptor_t asn_DEF_ProtocolIE_Container_1608P10;
extern asn_SET_OF_specifics_t asn_SPC_ProtocolIE_Container_1608P10_specs_21;
extern asn_TYPE_member_t asn_MBR_ProtocolIE_Container_1608P10_21[1];
extern asn_per_constraints_t asn_PER_type_ProtocolIE_Container_1608P10_constr_21;
extern asn_TYPE_descriptor_t asn_DEF_ProtocolIE_Container_1608P11;
extern asn_SET_OF_specifics_t asn_SPC_ProtocolIE_Container_1608P11_specs_23;
extern asn_TYPE_member_t asn_MBR_ProtocolIE_Container_1608P11_23[1];
extern asn_per_constraints_t asn_PER_type_ProtocolIE_Container_1608P11_constr_23;
extern asn_TYPE_descriptor_t asn_DEF_ProtocolIE_Container_1608P12;
extern asn_SET_OF_specifics_t asn_SPC_ProtocolIE_Container_1608P12_specs_25;
extern asn_TYPE_member_t asn_MBR_ProtocolIE_Container_1608P12_25[1];
extern asn_per_constraints_t asn_PER_type_ProtocolIE_Container_1608P12_constr_25;
extern asn_TYPE_descriptor_t asn_DEF_ProtocolIE_Container_1608P13;
extern asn_SET_OF_specifics_t asn_SPC_ProtocolIE_Container_1608P13_specs_27;
extern asn_TYPE_member_t asn_MBR_ProtocolIE_Container_1608P13_27[1];
extern asn_per_constraints_t asn_PER_type_ProtocolIE_Container_1608P13_constr_27;
extern asn_TYPE_descriptor_t asn_DEF_ProtocolIE_Container_1608P14;
extern asn_SET_OF_specifics_t asn_SPC_ProtocolIE_Container_1608P14_specs_29;
extern asn_TYPE_member_t asn_MBR_ProtocolIE_Container_1608P14_29[1];
extern asn_per_constraints_t asn_PER_type_ProtocolIE_Container_1608P14_constr_29;
extern asn_TYPE_descriptor_t asn_DEF_ProtocolIE_Container_1608P15;
extern asn_SET_OF_specifics_t asn_SPC_ProtocolIE_Container_1608P15_specs_31;
extern asn_TYPE_member_t asn_MBR_ProtocolIE_Container_1608P15_31[1];
extern asn_per_constraints_t asn_PER_type_ProtocolIE_Container_1608P15_constr_31;
extern asn_TYPE_descriptor_t asn_DEF_ProtocolIE_Container_1608P16;
extern asn_SET_OF_specifics_t asn_SPC_ProtocolIE_Container_1608P16_specs_33;
extern asn_TYPE_member_t asn_MBR_ProtocolIE_Container_1608P16_33[1];
extern asn_per_constraints_t asn_PER_type_ProtocolIE_Container_1608P16_constr_33;
extern asn_TYPE_descriptor_t asn_DEF_ProtocolIE_Container_1608P17;
extern asn_SET_OF_specifics_t asn_SPC_ProtocolIE_Container_1608P17_specs_35;
extern asn_TYPE_member_t asn_MBR_ProtocolIE_Container_1608P17_35[1];
extern asn_per_constraints_t asn_PER_type_ProtocolIE_Container_1608P17_constr_35;

#ifdef __cplusplus
}
#endif

#endif	/* _ProtocolIE_Container_H_ */
#include <asn_internal.h>