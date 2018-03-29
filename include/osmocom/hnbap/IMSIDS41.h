/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-IEs"
 * 	found in "../../asn1/hnbap/hnbap-14.0.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_IMSIDS41_H_
#define	_IMSIDS41_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* IMSIDS41 */
typedef OCTET_STRING_t	 IMSIDS41_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_IMSIDS41_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_IMSIDS41;
asn_struct_free_f IMSIDS41_free;
asn_struct_print_f IMSIDS41_print;
asn_constr_check_f IMSIDS41_constraint;
ber_type_decoder_f IMSIDS41_decode_ber;
der_type_encoder_f IMSIDS41_encode_der;
xer_type_decoder_f IMSIDS41_decode_xer;
xer_type_encoder_f IMSIDS41_encode_xer;
oer_type_decoder_f IMSIDS41_decode_oer;
oer_type_encoder_f IMSIDS41_encode_oer;
per_type_decoder_f IMSIDS41_decode_uper;
per_type_encoder_f IMSIDS41_encode_uper;
per_type_decoder_f IMSIDS41_decode_aper;
per_type_encoder_f IMSIDS41_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _IMSIDS41_H_ */
#include <asn_internal.h>
