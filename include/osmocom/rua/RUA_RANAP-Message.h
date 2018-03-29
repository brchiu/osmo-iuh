/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RUA-IEs"
 * 	found in "../../asn1/rua/rua-14.0.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RUA_RANAP_Message_H_
#define	_RUA_RANAP_Message_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RUA_RANAP-Message */
typedef OCTET_STRING_t	 RUA_RANAP_Message_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RUA_RANAP_Message;
asn_struct_free_f RUA_RANAP_Message_free;
asn_struct_print_f RUA_RANAP_Message_print;
asn_constr_check_f RUA_RANAP_Message_constraint;
ber_type_decoder_f RUA_RANAP_Message_decode_ber;
der_type_encoder_f RUA_RANAP_Message_encode_der;
xer_type_decoder_f RUA_RANAP_Message_decode_xer;
xer_type_encoder_f RUA_RANAP_Message_encode_xer;
oer_type_decoder_f RUA_RANAP_Message_decode_oer;
oer_type_encoder_f RUA_RANAP_Message_encode_oer;
per_type_decoder_f RUA_RANAP_Message_decode_uper;
per_type_encoder_f RUA_RANAP_Message_encode_uper;
per_type_decoder_f RUA_RANAP_Message_decode_aper;
per_type_encoder_f RUA_RANAP_Message_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _RUA_RANAP_Message_H_ */
#include <asn_internal.h>
