/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-IEs"
 * 	found in "../../asn1/hnbap/HNBAP-IEs.asn"
 * 	`asn1c -gen-PER -fnative-types`
 */

#ifndef	_HNB_Identity_Info_H_
#define	_HNB_Identity_Info_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* HNB-Identity-Info */
typedef OCTET_STRING_t	 HNB_Identity_Info_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_HNB_Identity_Info;
asn_struct_free_f HNB_Identity_Info_free;
asn_struct_print_f HNB_Identity_Info_print;
asn_constr_check_f HNB_Identity_Info_constraint;
ber_type_decoder_f HNB_Identity_Info_decode_ber;
der_type_encoder_f HNB_Identity_Info_encode_der;
xer_type_decoder_f HNB_Identity_Info_decode_xer;
xer_type_encoder_f HNB_Identity_Info_encode_xer;
per_type_decoder_f HNB_Identity_Info_decode_uper;
per_type_encoder_f HNB_Identity_Info_encode_uper;
per_type_decoder_f HNB_Identity_Info_decode_aper;
per_type_encoder_f HNB_Identity_Info_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _HNB_Identity_Info_H_ */
#include <asn_internal.h>
