/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-IEs"
 * 	found in "../../asn1/hnbap/HNBAP-IEs.asn"
 * 	`asn1c -gen-PER`
 */

#ifndef	_CGI_H_
#define	_CGI_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/hnbap/PLMNidentity.h>
#include <osmocom/hnbap/LAC.h>
#include <osmocom/hnbap/CI.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct IE_Extensions;

/* CGI */
typedef struct CGI {
	PLMNidentity_t	 pLMNidentity;
	LAC_t	 lAC;
	CI_t	 cI;
	struct IE_Extensions	*iE_Extensions	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CGI_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CGI;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include <osmocom/hnbap/IE-Extensions.h>

#endif	/* _CGI_H_ */
#include <asn_internal.h>
