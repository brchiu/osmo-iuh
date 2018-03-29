#pragma once

#include "asn_application.h"

#include <ANY.h>
#include <BIT_STRING.h>
#include <INTEGER.h>
#include <NativeEnumerated.h>
#include <NativeInteger.h>
#include <OBJECT_IDENTIFIER.h>
#include <OCTET_STRING.h>

#include <osmocom/hnbap/asn_constant.h>
#include <osmocom/hnbap/HNBAP-PDU.h>
#include <osmocom/hnbap/ProtocolIE-Field.h>
#include <osmocom/hnbap/ProtocolExtensionField.h>
#include <osmocom/hnbap/ProtocolExtensionContainer.h>

#if (ASN1C_ENVIRONMENT_VERSION < 924)
// # error "You are compiling with the wrong version of ASN1C"
#endif

#include <osmocom/core/logging.h>

#define HNBAP_DEBUG(x, args ...) DEBUGP(1, x, ## args)

extern int asn1_xer_print;

char *hnbap_cause_str(Cause_t *cause);

struct msgb *_hnbap_gen_msg(HNBAP_PDU_t *pdu);

#define HNBAP_FIND_PROTOCOLIE_BY_ID(IE_TYPE, ie, container, IE_ID, mandatory) \
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
