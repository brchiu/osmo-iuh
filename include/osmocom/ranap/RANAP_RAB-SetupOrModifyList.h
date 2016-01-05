/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-PDU"
 * 	found in "../../asn1/ranap/RANAP-PDU.asn"
 */

#ifndef	_RANAP_RAB_SetupOrModifyList_H_
#define	_RANAP_RAB_SetupOrModifyList_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/ranap/RANAP_RAB-IE-ContainerPairList.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RANAP_RAB-SetupOrModifyList */
typedef RANAP_RAB_IE_ContainerPairList_t	 RANAP_RAB_SetupOrModifyList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_RAB_SetupOrModifyList;
asn_struct_free_f RANAP_RAB_SetupOrModifyList_free;
asn_struct_print_f RANAP_RAB_SetupOrModifyList_print;
asn_constr_check_f RANAP_RAB_SetupOrModifyList_constraint;
ber_type_decoder_f RANAP_RAB_SetupOrModifyList_decode_ber;
der_type_encoder_f RANAP_RAB_SetupOrModifyList_encode_der;
xer_type_decoder_f RANAP_RAB_SetupOrModifyList_decode_xer;
xer_type_encoder_f RANAP_RAB_SetupOrModifyList_encode_xer;
per_type_decoder_f RANAP_RAB_SetupOrModifyList_decode_uper;
per_type_encoder_f RANAP_RAB_SetupOrModifyList_encode_uper;
per_type_decoder_f RANAP_RAB_SetupOrModifyList_decode_aper;
per_type_encoder_f RANAP_RAB_SetupOrModifyList_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_RAB_SetupOrModifyList_H_ */
#include <asn_internal.h>
