/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RANAP_ReportChangeOfSAI_H_
#define	_RANAP_ReportChangeOfSAI_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RANAP_ReportChangeOfSAI {
	RANAP_ReportChangeOfSAI_requested	= 0
	/*
	 * Enumeration is extensible
	 */
} e_RANAP_ReportChangeOfSAI;

/* RANAP_ReportChangeOfSAI */
typedef long	 RANAP_ReportChangeOfSAI_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_RANAP_ReportChangeOfSAI_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_RANAP_ReportChangeOfSAI;
extern const asn_INTEGER_specifics_t asn_SPC_ReportChangeOfSAI_specs_1;
asn_struct_free_f ReportChangeOfSAI_free;
asn_struct_print_f ReportChangeOfSAI_print;
asn_constr_check_f ReportChangeOfSAI_constraint;
ber_type_decoder_f ReportChangeOfSAI_decode_ber;
der_type_encoder_f ReportChangeOfSAI_encode_der;
xer_type_decoder_f ReportChangeOfSAI_decode_xer;
xer_type_encoder_f ReportChangeOfSAI_encode_xer;
oer_type_decoder_f ReportChangeOfSAI_decode_oer;
oer_type_encoder_f ReportChangeOfSAI_encode_oer;
per_type_decoder_f ReportChangeOfSAI_decode_uper;
per_type_encoder_f ReportChangeOfSAI_encode_uper;
per_type_decoder_f ReportChangeOfSAI_decode_aper;
per_type_encoder_f ReportChangeOfSAI_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_ReportChangeOfSAI_H_ */
#include <asn_internal.h>
