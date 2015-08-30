/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-IEs"
 * 	found in "../../asn1/hnbap/HNBAP-IEs.asn"
 * 	`asn1c -gen-PER -fnative-types`
 */

#ifndef	_CSGMembershipStatus_H_
#define	_CSGMembershipStatus_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CSGMembershipStatus {
	CSGMembershipStatus_member	= 0,
	CSGMembershipStatus_non_member	= 1
	/*
	 * Enumeration is extensible
	 */
} e_CSGMembershipStatus;

/* CSGMembershipStatus */
typedef long	 CSGMembershipStatus_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CSGMembershipStatus;
asn_struct_free_f CSGMembershipStatus_free;
asn_struct_print_f CSGMembershipStatus_print;
asn_constr_check_f CSGMembershipStatus_constraint;
ber_type_decoder_f CSGMembershipStatus_decode_ber;
der_type_encoder_f CSGMembershipStatus_encode_der;
xer_type_decoder_f CSGMembershipStatus_decode_xer;
xer_type_encoder_f CSGMembershipStatus_encode_xer;
per_type_decoder_f CSGMembershipStatus_decode_uper;
per_type_encoder_f CSGMembershipStatus_encode_uper;
per_type_decoder_f CSGMembershipStatus_decode_aper;
per_type_encoder_f CSGMembershipStatus_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _CSGMembershipStatus_H_ */
#include <asn_internal.h>
