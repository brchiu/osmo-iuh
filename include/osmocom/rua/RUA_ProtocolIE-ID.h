/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RUA-CommonDataTypes"
 * 	found in "../../asn1/rua/rua-14.0.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RUA_ProtocolIE_ID_H_
#define	_RUA_ProtocolIE_ID_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RUA_ProtocolIE-ID */
typedef long	 RUA_ProtocolIE_ID_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_RUA_ProtocolIE_ID_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_RUA_ProtocolIE_ID;
asn_struct_free_f RUA_ProtocolIE_ID_free;
asn_struct_print_f RUA_ProtocolIE_ID_print;
asn_constr_check_f RUA_ProtocolIE_ID_constraint;
ber_type_decoder_f RUA_ProtocolIE_ID_decode_ber;
der_type_encoder_f RUA_ProtocolIE_ID_encode_der;
xer_type_decoder_f RUA_ProtocolIE_ID_decode_xer;
xer_type_encoder_f RUA_ProtocolIE_ID_encode_xer;
oer_type_decoder_f RUA_ProtocolIE_ID_decode_oer;
oer_type_encoder_f RUA_ProtocolIE_ID_encode_oer;
per_type_decoder_f RUA_ProtocolIE_ID_decode_uper;
per_type_encoder_f RUA_ProtocolIE_ID_encode_uper;
per_type_decoder_f RUA_ProtocolIE_ID_decode_aper;
per_type_encoder_f RUA_ProtocolIE_ID_encode_aper;
#define RUA_ProtocolIE_ID_id_Cause	((RUA_ProtocolIE_ID_t)1)
#define RUA_ProtocolIE_ID_id_CriticalityDiagnostics	((RUA_ProtocolIE_ID_t)2)
#define RUA_ProtocolIE_ID_id_Context_ID	((RUA_ProtocolIE_ID_t)3)
#define RUA_ProtocolIE_ID_id_RANAP_Message	((RUA_ProtocolIE_ID_t)4)
#define RUA_ProtocolIE_ID_id_IntraDomainNasNodeSelector	((RUA_ProtocolIE_ID_t)5)
#define RUA_ProtocolIE_ID_id_Establishment_Cause	((RUA_ProtocolIE_ID_t)6)
#define RUA_ProtocolIE_ID_id_CN_DomainIndicator	((RUA_ProtocolIE_ID_t)7)
#define RUA_ProtocolIE_ID_id_CSGMembershipStatus	((RUA_ProtocolIE_ID_t)9)

#ifdef __cplusplus
}
#endif

#endif	/* _RUA_ProtocolIE_ID_H_ */
#include <asn_internal.h>
