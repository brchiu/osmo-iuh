/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/RANAP-IEs.asn"
 */

#ifndef	_RANAP_TargetRNC_ToSourceRNC_TransparentContainer_H_
#define	_RANAP_TargetRNC_ToSourceRNC_TransparentContainer_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/ranap/RANAP_RRC-Container.h>
#include <osmocom/ranap/RANAP_D-RNTI.h>
#include <osmocom/ranap/RANAP_IE-Extensions.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RANAP_TargetRNC-ToSourceRNC-TransparentContainer */
typedef struct RANAP_TargetRNC_ToSourceRNC_TransparentContainer {
	RANAP_RRC_Container_t	 rRC_Container;
	RANAP_D_RNTI_t	*d_RNTI	/* OPTIONAL */;
	RANAP_IE_Extensions_t	*iE_Extensions	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RANAP_TargetRNC_ToSourceRNC_TransparentContainer_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_TargetRNC_ToSourceRNC_TransparentContainer;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_TargetRNC_ToSourceRNC_TransparentContainer_H_ */
#include <asn_internal.h>
