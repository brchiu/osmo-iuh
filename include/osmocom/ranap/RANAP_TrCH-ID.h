/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/RANAP-IEs.asn"
 */

#ifndef	_RANAP_TrCH_ID_H_
#define	_RANAP_TrCH_ID_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/ranap/RANAP_DCH-ID.h>
#include <osmocom/ranap/RANAP_DSCH-ID.h>
#include <osmocom/ranap/RANAP_USCH-ID.h>
#include <osmocom/ranap/RANAP_IE-Extensions.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RANAP_TrCH-ID */
typedef struct RANAP_TrCH_ID {
	RANAP_DCH_ID_t	*dCH_ID	/* OPTIONAL */;
	RANAP_DSCH_ID_t	*dSCH_ID	/* OPTIONAL */;
	RANAP_USCH_ID_t	*uSCH_ID	/* OPTIONAL */;
	RANAP_IE_Extensions_t	*iE_Extensions	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RANAP_TrCH_ID_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RANAP_TrCH_ID;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_TrCH_ID_H_ */
#include <asn_internal.h>
