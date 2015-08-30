/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-IEs"
 * 	found in "../../asn1/hnbap/HNBAP-IEs.asn"
 * 	`asn1c -gen-PER -fnative-types`
 */

#ifndef	_UE_Capabilities_H_
#define	_UE_Capabilities_H_


#include <asn_application.h>

/* Including external dependencies */
#include "Access-stratum-release-indicator.h"
#include "CSG-Capability.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct IE_Extensions;

/* UE-Capabilities */
typedef struct UE_Capabilities {
	Access_stratum_release_indicator_t	 access_stratum_release_indicator;
	CSG_Capability_t	 csg_capability;
	struct IE_Extensions	*iE_Extensions	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UE_Capabilities_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UE_Capabilities;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "IE-Extensions.h"

#endif	/* _UE_Capabilities_H_ */
#include <asn_internal.h>
