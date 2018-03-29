/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RANAP_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf_H_
#define	_RANAP_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/ranap/RANAP_Alt-RAB-Parameter-GuaranteedBitrateType.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct RANAP_Alt_RAB_Parameter_ExtendedGuaranteedBitrates;

/* RANAP_Alt-RAB-Parameter-ExtendedGuaranteedBitrateInf */
typedef struct RANAP_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf {
	RANAP_Alt_RAB_Parameter_GuaranteedBitrateType_t	 altExtendedGuaranteedBitrateType;
	struct RANAP_Alt_RAB_Parameter_ExtendedGuaranteedBitrates	*altExtendedGuaranteedBitrates;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RANAP_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf_H_ */
#include <asn_internal.h>
