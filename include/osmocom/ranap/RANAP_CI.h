/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RANAP_CI_H_
#define	_RANAP_CI_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RANAP_CI */
typedef OCTET_STRING_t	 RANAP_CI_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_RANAP_CI_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_RANAP_CI;
asn_struct_free_f RANAP_CI_free;
asn_struct_print_f RANAP_CI_print;
asn_constr_check_f RANAP_CI_constraint;
ber_type_decoder_f RANAP_CI_decode_ber;
der_type_encoder_f RANAP_CI_encode_der;
xer_type_decoder_f RANAP_CI_decode_xer;
xer_type_encoder_f RANAP_CI_encode_xer;
oer_type_decoder_f RANAP_CI_decode_oer;
oer_type_encoder_f RANAP_CI_encode_oer;
per_type_decoder_f RANAP_CI_decode_uper;
per_type_encoder_f RANAP_CI_encode_uper;
per_type_decoder_f RANAP_CI_decode_aper;
per_type_encoder_f RANAP_CI_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_CI_H_ */
#include <asn_internal.h>
