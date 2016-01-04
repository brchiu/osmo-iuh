/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/RANAP-IEs.asn"
 */

#ifndef	_RANAP_Alt_RAB_Parameter_MaxBitrateType_H_
#define	_RANAP_Alt_RAB_Parameter_MaxBitrateType_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RANAP_Alt_RAB_Parameter_MaxBitrateType {
	RANAP_Alt_RAB_Parameter_MaxBitrateType_unspecified	= 0,
	RANAP_Alt_RAB_Parameter_MaxBitrateType_value_range	= 1,
	RANAP_Alt_RAB_Parameter_MaxBitrateType_discrete_values	= 2
	/*
	 * Enumeration is extensible
	 */
} e_RANAP_Alt_RAB_Parameter_MaxBitrateType;

/* RANAP_Alt-RAB-Parameter-MaxBitrateType */
typedef long	 RANAP_Alt_RAB_Parameter_MaxBitrateType_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_Alt_RAB_Parameter_MaxBitrateType;
asn_struct_free_f RANAP_Alt_RAB_Parameter_MaxBitrateType_free;
asn_struct_print_f RANAP_Alt_RAB_Parameter_MaxBitrateType_print;
asn_constr_check_f RANAP_Alt_RAB_Parameter_MaxBitrateType_constraint;
ber_type_decoder_f RANAP_Alt_RAB_Parameter_MaxBitrateType_decode_ber;
der_type_encoder_f RANAP_Alt_RAB_Parameter_MaxBitrateType_encode_der;
xer_type_decoder_f RANAP_Alt_RAB_Parameter_MaxBitrateType_decode_xer;
xer_type_encoder_f RANAP_Alt_RAB_Parameter_MaxBitrateType_encode_xer;
per_type_decoder_f RANAP_Alt_RAB_Parameter_MaxBitrateType_decode_uper;
per_type_encoder_f RANAP_Alt_RAB_Parameter_MaxBitrateType_encode_uper;
per_type_decoder_f RANAP_Alt_RAB_Parameter_MaxBitrateType_decode_aper;
per_type_encoder_f RANAP_Alt_RAB_Parameter_MaxBitrateType_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_Alt_RAB_Parameter_MaxBitrateType_H_ */
#include <asn_internal.h>