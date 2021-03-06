/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-IEs"
 * 	found in "../../asn1/hnbap/HNBAP-IEs.asn"
 * 	`asn1c -gen-PER`
 */

#ifndef	_Access_stratum_release_indicator_H_
#define	_Access_stratum_release_indicator_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Access_stratum_release_indicator {
	Access_stratum_release_indicator_r99	= 0,
	Access_stratum_release_indicator_rel_4	= 1,
	Access_stratum_release_indicator_rel_5	= 2,
	Access_stratum_release_indicator_rel_6	= 3,
	Access_stratum_release_indicator_rel_7	= 4,
	Access_stratum_release_indicator_rel_8_and_beyond	= 5
	/*
	 * Enumeration is extensible
	 */
} e_Access_stratum_release_indicator;

/* Access-stratum-release-indicator */
typedef long	 Access_stratum_release_indicator_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Access_stratum_release_indicator;
asn_struct_free_f Access_stratum_release_indicator_free;
asn_struct_print_f Access_stratum_release_indicator_print;
asn_constr_check_f Access_stratum_release_indicator_constraint;
ber_type_decoder_f Access_stratum_release_indicator_decode_ber;
der_type_encoder_f Access_stratum_release_indicator_encode_der;
xer_type_decoder_f Access_stratum_release_indicator_decode_xer;
xer_type_encoder_f Access_stratum_release_indicator_encode_xer;
per_type_decoder_f Access_stratum_release_indicator_decode_uper;
per_type_encoder_f Access_stratum_release_indicator_encode_uper;
per_type_decoder_f Access_stratum_release_indicator_decode_aper;
per_type_encoder_f Access_stratum_release_indicator_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _Access_stratum_release_indicator_H_ */
#include <asn_internal.h>
