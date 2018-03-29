/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-PDU-Contents"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RANAP_RAB_SetupList_RelocReq_H_
#define	_RANAP_RAB_SetupList_RelocReq_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/ranap/RANAP_RAB-IE-ContainerList.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RANAP_RAB-SetupList-RelocReq */
typedef RANAP_RAB_IE_ContainerList_1094P4_t	 RANAP_RAB_SetupList_RelocReq_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_RAB_SetupList_RelocReq;
asn_struct_free_f RANAP_RAB_SetupList_RelocReq_free;
asn_struct_print_f RANAP_RAB_SetupList_RelocReq_print;
asn_constr_check_f RANAP_RAB_SetupList_RelocReq_constraint;
ber_type_decoder_f RANAP_RAB_SetupList_RelocReq_decode_ber;
der_type_encoder_f RANAP_RAB_SetupList_RelocReq_encode_der;
xer_type_decoder_f RANAP_RAB_SetupList_RelocReq_decode_xer;
xer_type_encoder_f RANAP_RAB_SetupList_RelocReq_encode_xer;
oer_type_decoder_f RANAP_RAB_SetupList_RelocReq_decode_oer;
oer_type_encoder_f RANAP_RAB_SetupList_RelocReq_encode_oer;
per_type_decoder_f RANAP_RAB_SetupList_RelocReq_decode_uper;
per_type_encoder_f RANAP_RAB_SetupList_RelocReq_encode_uper;
per_type_decoder_f RANAP_RAB_SetupList_RelocReq_decode_aper;
per_type_encoder_f RANAP_RAB_SetupList_RelocReq_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_RAB_SetupList_RelocReq_H_ */
#include <asn_internal.h>
