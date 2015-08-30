/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-IEs"
 * 	found in "../../asn1/hnbap/HNBAP-IEs.asn"
 * 	`asn1c -gen-PER -fnative-types`
 */

#ifndef	_Registration_Cause_H_
#define	_Registration_Cause_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Registration_Cause {
	Registration_Cause_emergency_call	= 0,
	Registration_Cause_normal	= 1,
	/*
	 * Enumeration is extensible
	 */
	Registration_Cause_ue_relocation	= 2
} e_Registration_Cause;

/* Registration-Cause */
typedef long	 Registration_Cause_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Registration_Cause;
asn_struct_free_f Registration_Cause_free;
asn_struct_print_f Registration_Cause_print;
asn_constr_check_f Registration_Cause_constraint;
ber_type_decoder_f Registration_Cause_decode_ber;
der_type_encoder_f Registration_Cause_encode_der;
xer_type_decoder_f Registration_Cause_decode_xer;
xer_type_encoder_f Registration_Cause_encode_xer;
per_type_decoder_f Registration_Cause_decode_uper;
per_type_encoder_f Registration_Cause_encode_uper;
per_type_decoder_f Registration_Cause_decode_aper;
per_type_encoder_f Registration_Cause_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _Registration_Cause_H_ */
#include <asn_internal.h>
