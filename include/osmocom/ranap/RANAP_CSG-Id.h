/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RANAP_CSG_Id_H_
#define	_RANAP_CSG_Id_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RANAP_CSG-Id */
typedef BIT_STRING_t	 RANAP_CSG_Id_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_RANAP_CSG_Id_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_RANAP_CSG_Id;
asn_struct_free_f RANAP_CSG_Id_free;
asn_struct_print_f RANAP_CSG_Id_print;
asn_constr_check_f RANAP_CSG_Id_constraint;
ber_type_decoder_f RANAP_CSG_Id_decode_ber;
der_type_encoder_f RANAP_CSG_Id_encode_der;
xer_type_decoder_f RANAP_CSG_Id_decode_xer;
xer_type_encoder_f RANAP_CSG_Id_encode_xer;
oer_type_decoder_f RANAP_CSG_Id_decode_oer;
oer_type_encoder_f RANAP_CSG_Id_encode_oer;
per_type_decoder_f RANAP_CSG_Id_decode_uper;
per_type_encoder_f RANAP_CSG_Id_encode_uper;
per_type_decoder_f RANAP_CSG_Id_decode_aper;
per_type_encoder_f RANAP_CSG_Id_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_CSG_Id_H_ */
#include <asn_internal.h>
