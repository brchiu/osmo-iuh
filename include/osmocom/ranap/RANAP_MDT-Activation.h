/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RANAP_MDT_Activation_H_
#define	_RANAP_MDT_Activation_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RANAP_MDT_Activation {
	RANAP_MDT_Activation_immediateMDTonly	= 0,
	RANAP_MDT_Activation_loggedMDTonly	= 1,
	RANAP_MDT_Activation_immediateMDTandTrace	= 2
	/*
	 * Enumeration is extensible
	 */
} e_RANAP_MDT_Activation;

/* RANAP_MDT-Activation */
typedef long	 RANAP_MDT_Activation_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_RANAP_MDT_Activation_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_RANAP_MDT_Activation;
extern const asn_INTEGER_specifics_t asn_SPC_MDT_Activation_specs_1;
asn_struct_free_f MDT_Activation_free;
asn_struct_print_f MDT_Activation_print;
asn_constr_check_f MDT_Activation_constraint;
ber_type_decoder_f MDT_Activation_decode_ber;
der_type_encoder_f MDT_Activation_encode_der;
xer_type_decoder_f MDT_Activation_decode_xer;
xer_type_encoder_f MDT_Activation_encode_xer;
oer_type_decoder_f MDT_Activation_decode_oer;
oer_type_encoder_f MDT_Activation_encode_oer;
per_type_decoder_f MDT_Activation_decode_uper;
per_type_encoder_f MDT_Activation_encode_uper;
per_type_decoder_f MDT_Activation_decode_aper;
per_type_encoder_f MDT_Activation_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_MDT_Activation_H_ */
#include <asn_internal.h>
