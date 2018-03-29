#pragma once

#include <asn1c/asn_application.h>

/* for f in ranap/RANAP_*.h; printf "#include \"$f\"\n" */
#include <osmocom/ranap/RANAP_asn_constant.h>
#include <osmocom/ranap/RANAP_RANAP-PDU.h>
#include <osmocom/ranap/RANAP_ProtocolIE-Field.h>
#include <osmocom/ranap/RANAP_ProtocolIE-FieldPair.h>
#include <osmocom/ranap/RANAP_ProtocolIE-ContainerPair.h>
#include <osmocom/ranap/RANAP_ProtocolExtensionField.h>
#include <osmocom/ranap/RANAP_ProtocolExtensionContainer.h>
#include <osmocom/ranap/RANAP_SDU-ErrorRatio.h>
#include <osmocom/ranap/RANAP_SDU-FormatInformationParameters.h>
#include <osmocom/ranap/RANAP_RAB-Parameter-ExtendedMaxBitrateList.h>
#include <osmocom/ranap/RANAP_AllocationOrRetentionPriority.h>
#include <osmocom/ranap/RANAP_RAB-Parameter-GuaranteedBitrateList.h>

#if (ASN1C_ENVIRONMENT_VERSION < 924)
// # error "You are compiling with the wrong version of ASN1C"
#endif

#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>

struct gprs_ra_id;

#define RANAP_DEBUG(x, args ...) DEBUGP(_ranap_DRANAP, x, ## args)
extern int _ranap_DRANAP;

extern int asn1_xer_print;

extern const struct value_string ranap_presence_vals[5];
extern const struct value_string ranap_procedure_code_vals[48];

struct msgb *_ranap_gen_msg(RANAP_RANAP_PDU_t *pdu);
char *ranap_cause_str(const RANAP_Cause_t *cause);

void ranap_set_log_area(int log_area);

int ranap_parse_lai(struct gprs_ra_id *ra_id, const RANAP_LAI_t *lai);
int ranap_ip_from_transp_layer_addr(const BIT_STRING_t *in, uint32_t *ip);

/* The generated version does not work, this is a custom one */
int ranap_decode_rab_setupormodifieditemies_fromlist(
    RANAP_RAB_SetupOrModifiedItemIEs_t *raB_SetupOrModifiedItemIEs,
    ANY_t *any_p);

#define RANAP_FIND_PROTOCOLIE_BY_ID(IE_TYPE, ie, container, IE_ID, mandatory) \
  do {\
    IE_TYPE **ptr; \
    ie = NULL; \
    for (ptr = container->protocolIEs.list.array; \
         ptr < &container->protocolIEs.list.array[container->protocolIEs.list.count]; \
         ptr++) { \
      if((*ptr)->id == IE_ID) { \
        ie = *ptr; \
        break; \
      } \
    } \
    if (mandatory && !ie) return -1; \
  } while(0)
