/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-CommonDataTypes"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RANAP_Criticality_H_
#define	_RANAP_Criticality_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RANAP_Criticality {
	RANAP_Criticality_reject	= 0,
	RANAP_Criticality_ignore	= 1,
	RANAP_Criticality_notify	= 2
} e_RANAP_Criticality;

/* RANAP_Criticality */
typedef long	 RANAP_Criticality_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_RANAP_Criticality_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_RANAP_Criticality;
extern const asn_INTEGER_specifics_t asn_SPC_Criticality_specs_1;
asn_struct_free_f Criticality_free;
asn_struct_print_f Criticality_print;
asn_constr_check_f Criticality_constraint;
ber_type_decoder_f Criticality_decode_ber;
der_type_encoder_f Criticality_encode_der;
xer_type_decoder_f Criticality_decode_xer;
xer_type_encoder_f Criticality_encode_xer;
oer_type_decoder_f Criticality_decode_oer;
oer_type_encoder_f Criticality_encode_oer;
per_type_decoder_f Criticality_decode_uper;
per_type_encoder_f Criticality_encode_uper;
per_type_decoder_f Criticality_decode_aper;
per_type_encoder_f Criticality_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_Criticality_H_ */
#include <asn_internal.h>
