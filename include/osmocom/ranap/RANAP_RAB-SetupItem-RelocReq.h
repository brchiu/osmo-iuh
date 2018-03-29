/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-PDU-Contents"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RANAP_RAB_SetupItem_RelocReq_H_
#define	_RANAP_RAB_SetupItem_RelocReq_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/ranap/RANAP_RAB-ID.h>
#include <osmocom/ranap/RANAP_NAS-SynchronisationIndicator.h>
#include <osmocom/ranap/RANAP_RAB-Parameters.h>
#include <osmocom/ranap/RANAP_DataVolumeReportingIndication.h>
#include <osmocom/ranap/RANAP_UserPlaneInformation.h>
#include <osmocom/ranap/RANAP_TransportLayerAddress.h>
#include <osmocom/ranap/RANAP_IuTransportAssociation.h>
#include <osmocom/ranap/RANAP_Service-Handover.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct RANAP_PDP_TypeInformation;
struct RANAP_ProtocolExtensionContainer;

/* RANAP_RAB-SetupItem-RelocReq */
typedef struct RANAP_RAB_SetupItem_RelocReq {
	RANAP_RAB_ID_t	 rAB_ID;
	RANAP_NAS_SynchronisationIndicator_t	*nAS_SynchronisationIndicator;	/* OPTIONAL */
	RANAP_RAB_Parameters_t	 rAB_Parameters;
	RANAP_DataVolumeReportingIndication_t	*dataVolumeReportingIndication;	/* OPTIONAL */
	struct RANAP_PDP_TypeInformation	*pDP_TypeInformation;	/* OPTIONAL */
	RANAP_UserPlaneInformation_t	 userPlaneInformation;
	RANAP_TransportLayerAddress_t	 transportLayerAddress;
	RANAP_IuTransportAssociation_t	 iuTransportAssociation;
	RANAP_Service_Handover_t	*service_Handover;	/* OPTIONAL */
	struct RANAP_ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RANAP_RAB_SetupItem_RelocReq_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_RAB_SetupItem_RelocReq;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_RAB_SetupItem_RelocReq_H_ */
#include <asn_internal.h>
