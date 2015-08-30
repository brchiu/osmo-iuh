/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-IEs"
 * 	found in "../../asn1/hnbap/HNBAP-IEs.asn"
 * 	`asn1c -gen-PER -fnative-types`
 */

#ifndef	_HNB_Cell_Access_Mode_H_
#define	_HNB_Cell_Access_Mode_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum HNB_Cell_Access_Mode {
	HNB_Cell_Access_Mode_closed	= 0,
	HNB_Cell_Access_Mode_hybrid	= 1,
	HNB_Cell_Access_Mode_open	= 2
	/*
	 * Enumeration is extensible
	 */
} e_HNB_Cell_Access_Mode;

/* HNB-Cell-Access-Mode */
typedef long	 HNB_Cell_Access_Mode_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_HNB_Cell_Access_Mode;
asn_struct_free_f HNB_Cell_Access_Mode_free;
asn_struct_print_f HNB_Cell_Access_Mode_print;
asn_constr_check_f HNB_Cell_Access_Mode_constraint;
ber_type_decoder_f HNB_Cell_Access_Mode_decode_ber;
der_type_encoder_f HNB_Cell_Access_Mode_encode_der;
xer_type_decoder_f HNB_Cell_Access_Mode_decode_xer;
xer_type_encoder_f HNB_Cell_Access_Mode_encode_xer;
per_type_decoder_f HNB_Cell_Access_Mode_decode_uper;
per_type_encoder_f HNB_Cell_Access_Mode_encode_uper;
per_type_decoder_f HNB_Cell_Access_Mode_decode_aper;
per_type_encoder_f HNB_Cell_Access_Mode_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _HNB_Cell_Access_Mode_H_ */
#include <asn_internal.h>
