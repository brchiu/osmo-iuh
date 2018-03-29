#pragma once

#include <asn_application.h>

#include <osmocom/rua/RUA_asn_constant.h>
#include <osmocom/rua/RUA_RUA-PDU.h>
#include <osmocom/rua/RUA_ProtocolIE-Field.h>
#include <osmocom/rua/RUA_ProtocolExtensionField.h>
#include <osmocom/rua/RUA_ProtocolExtensionContainer.h>

#if (ASN1C_ENVIRONMENT_VERSION < 924)
// # error "You are compiling with the wrong version of ASN1C"
#endif

#include <osmocom/core/logging.h>

#define RUA_DEBUG(x, args ...) DEBUGP(0, x, ## args)

extern int asn1_xer_print;

struct msgb *rua_generate_initiating_message(
					RUA_ProcedureCode_t procedureCode,
					RUA_Criticality_t criticality,
					asn_TYPE_descriptor_t * td, void *sptr);

struct msgb *rua_generate_successful_outcome(
					   RUA_ProcedureCode_t procedureCode,
					   RUA_Criticality_t criticality,
					   asn_TYPE_descriptor_t * td,
					   void *sptr);

struct msgb *rua_generate_unsuccessful_outcome(
					   RUA_ProcedureCode_t procedureCode,
					   RUA_Criticality_t criticality,
					   asn_TYPE_descriptor_t * td,
					   void *sptr);

char *rua_cause_str(RUA_Cause_t *cause);

struct msgb *_rua_gen_msg(RUA_RUA_PDU_t *pdu);

#define RUA_FIND_PROTOCOLIE_BY_ID(IE_TYPE, ie, container, IE_ID, mandatory) \
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
