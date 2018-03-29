/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RANAP_MBMSHCIndicator_H_
#define	_RANAP_MBMSHCIndicator_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RANAP_MBMSHCIndicator {
	RANAP_MBMSHCIndicator_uncompressed_header	= 0,
	RANAP_MBMSHCIndicator_compressed_header	= 1
	/*
	 * Enumeration is extensible
	 */
} e_RANAP_MBMSHCIndicator;

/* RANAP_MBMSHCIndicator */
typedef long	 RANAP_MBMSHCIndicator_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_RANAP_MBMSHCIndicator_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_RANAP_MBMSHCIndicator;
extern const asn_INTEGER_specifics_t asn_SPC_MBMSHCIndicator_specs_1;
asn_struct_free_f MBMSHCIndicator_free;
asn_struct_print_f MBMSHCIndicator_print;
asn_constr_check_f MBMSHCIndicator_constraint;
ber_type_decoder_f MBMSHCIndicator_decode_ber;
der_type_encoder_f MBMSHCIndicator_encode_der;
xer_type_decoder_f MBMSHCIndicator_decode_xer;
xer_type_encoder_f MBMSHCIndicator_encode_xer;
oer_type_decoder_f MBMSHCIndicator_decode_oer;
oer_type_encoder_f MBMSHCIndicator_encode_oer;
per_type_decoder_f MBMSHCIndicator_decode_uper;
per_type_encoder_f MBMSHCIndicator_encode_uper;
per_type_decoder_f MBMSHCIndicator_decode_aper;
per_type_encoder_f MBMSHCIndicator_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_MBMSHCIndicator_H_ */
#include <asn_internal.h>
