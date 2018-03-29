/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RANAP_GERAN_Classmark_H_
#define	_RANAP_GERAN_Classmark_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RANAP_GERAN-Classmark */
typedef OCTET_STRING_t	 RANAP_GERAN_Classmark_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_GERAN_Classmark;
asn_struct_free_f RANAP_GERAN_Classmark_free;
asn_struct_print_f RANAP_GERAN_Classmark_print;
asn_constr_check_f RANAP_GERAN_Classmark_constraint;
ber_type_decoder_f RANAP_GERAN_Classmark_decode_ber;
der_type_encoder_f RANAP_GERAN_Classmark_encode_der;
xer_type_decoder_f RANAP_GERAN_Classmark_decode_xer;
xer_type_encoder_f RANAP_GERAN_Classmark_encode_xer;
oer_type_decoder_f RANAP_GERAN_Classmark_decode_oer;
oer_type_encoder_f RANAP_GERAN_Classmark_encode_oer;
per_type_decoder_f RANAP_GERAN_Classmark_decode_uper;
per_type_encoder_f RANAP_GERAN_Classmark_encode_uper;
per_type_decoder_f RANAP_GERAN_Classmark_decode_aper;
per_type_encoder_f RANAP_GERAN_Classmark_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_GERAN_Classmark_H_ */
#include <asn_internal.h>
