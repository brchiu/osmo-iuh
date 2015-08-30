/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-IEs"
 * 	found in "../../asn1/hnbap/HNBAP-IEs.asn"
 * 	`asn1c -gen-PER -fnative-types`
 */

#ifndef	_Update_cause_H_
#define	_Update_cause_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Update_cause {
	Update_cause_relocation_preparation	= 0
	/*
	 * Enumeration is extensible
	 */
} e_Update_cause;

/* Update-cause */
typedef long	 Update_cause_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Update_cause;
asn_struct_free_f Update_cause_free;
asn_struct_print_f Update_cause_print;
asn_constr_check_f Update_cause_constraint;
ber_type_decoder_f Update_cause_decode_ber;
der_type_encoder_f Update_cause_encode_der;
xer_type_decoder_f Update_cause_decode_xer;
xer_type_encoder_f Update_cause_encode_xer;
per_type_decoder_f Update_cause_decode_uper;
per_type_encoder_f Update_cause_encode_uper;
per_type_decoder_f Update_cause_decode_aper;
per_type_encoder_f Update_cause_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _Update_cause_H_ */
#include <asn_internal.h>
