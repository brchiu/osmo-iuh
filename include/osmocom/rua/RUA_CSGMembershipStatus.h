/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RUA-IEs"
 * 	found in "../../asn1/rua/rua-14.0.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RUA_CSGMembershipStatus_H_
#define	_RUA_CSGMembershipStatus_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RUA_CSGMembershipStatus {
	RUA_CSGMembershipStatus_member	= 0,
	RUA_CSGMembershipStatus_non_member	= 1
	/*
	 * Enumeration is extensible
	 */
} e_RUA_CSGMembershipStatus;

/* RUA_CSGMembershipStatus */
typedef long	 RUA_CSGMembershipStatus_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RUA_CSGMembershipStatus;
asn_struct_free_f RUA_CSGMembershipStatus_free;
asn_struct_print_f RUA_CSGMembershipStatus_print;
asn_constr_check_f RUA_CSGMembershipStatus_constraint;
ber_type_decoder_f RUA_CSGMembershipStatus_decode_ber;
der_type_encoder_f RUA_CSGMembershipStatus_encode_der;
xer_type_decoder_f RUA_CSGMembershipStatus_decode_xer;
xer_type_encoder_f RUA_CSGMembershipStatus_encode_xer;
oer_type_decoder_f RUA_CSGMembershipStatus_decode_oer;
oer_type_encoder_f RUA_CSGMembershipStatus_encode_oer;
per_type_decoder_f RUA_CSGMembershipStatus_decode_uper;
per_type_encoder_f RUA_CSGMembershipStatus_encode_uper;
per_type_decoder_f RUA_CSGMembershipStatus_decode_aper;
per_type_encoder_f RUA_CSGMembershipStatus_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _RUA_CSGMembershipStatus_H_ */
#include <asn_internal.h>
