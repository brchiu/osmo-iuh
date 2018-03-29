/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RUA-PDU-Descriptions"
 * 	found in "../../asn1/rua/rua-14.0.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RUA_SuccessfulOutcome_H_
#define	_RUA_SuccessfulOutcome_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/rua/RUA_ProcedureCode.h>
#include <osmocom/rua/RUA_Criticality.h>
#include <ANY.h>
#include <asn_ioc.h>
#include <osmocom/rua/RUA_Connect.h>
#include <osmocom/rua/RUA_DirectTransfer.h>
#include <osmocom/rua/RUA_Disconnect.h>
#include <osmocom/rua/RUA_ConnectionlessTransfer.h>
#include <osmocom/rua/RUA_ErrorIndication.h>
#include <osmocom/rua/RUA_PrivateMessage.h>
#include <OPEN_TYPE.h>
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RUA_SuccessfulOutcome__value_PR {
	RUA_SuccessfulOutcome__value_PR_NOTHING	/* No components present */
	
} RUA_SuccessfulOutcome__value_PR;

/* RUA_SuccessfulOutcome */
typedef struct RUA_SuccessfulOutcome {
	RUA_ProcedureCode_t	 procedureCode;
	RUA_Criticality_t	 criticality;
	struct RUA_SuccessfulOutcome__value {
		RUA_SuccessfulOutcome__value_PR present;
		union RUA_SuccessfulOutcome__RUA_value_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} value;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RUA_SuccessfulOutcome_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RUA_SuccessfulOutcome;
extern asn_SEQUENCE_specifics_t asn_SPC_RUA_SuccessfulOutcome_specs_1;
extern asn_TYPE_member_t asn_MBR_RUA_SuccessfulOutcome_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _RUA_SuccessfulOutcome_H_ */
#include <asn_internal.h>
