ASN_MODULE_SOURCES=	\
	RUA_RUA-PDU.c	\
	RUA_InitiatingMessage.c	\
	RUA_SuccessfulOutcome.c	\
	RUA_UnsuccessfulOutcome.c	\
	RUA_Connect.c	\
	RUA_DirectTransfer.c	\
	RUA_Disconnect.c	\
	RUA_ConnectionlessTransfer.c	\
	RUA_ErrorIndication.c	\
	RUA_PrivateMessage.c	\
	RUA_CN-DomainIndicator.c	\
	RUA_CSGMembershipStatus.c	\
	RUA_Establishment-Cause.c	\
	RUA_Context-ID.c	\
	RUA_IntraDomainNasNodeSelector.c	\
	RUA_Gsm-map-IDNNS.c	\
	RUA_Ansi-41-IDNNS.c	\
	RUA_RANAP-Message.c	\
	RUA_RoutingParameter.c	\
	RUA_Cause.c	\
	RUA_CauseRadioNetwork.c	\
	RUA_CauseTransport.c	\
	RUA_CauseProtocol.c	\
	RUA_CauseMisc.c	\
	RUA_CriticalityDiagnostics.c	\
	RUA_CriticalityDiagnostics-IE-List.c	\
	RUA_TypeOfError.c	\
	RUA_Criticality.c	\
	RUA_Presence.c	\
	RUA_ProcedureCode.c	\
	RUA_PrivateIE-ID.c	\
	RUA_ProtocolIE-ID.c	\
	RUA_TriggeringMessage.c	\
	RUA_ProtocolIE-Container.c	\
	RUA_ProtocolIE-Single-Container.c	\
	RUA_ProtocolIE-Field.c	\
	RUA_ProtocolIE-ContainerList.c	\
	RUA_ProtocolExtensionContainer.c	\
	RUA_ProtocolExtensionField.c	\
	RUA_PrivateIE-Container.c	\
	RUA_PrivateIE-Field.c

ASN_MODULE_INC=	\
	RUA_RUA-PDU.h	\
	RUA_InitiatingMessage.h	\
	RUA_SuccessfulOutcome.h	\
	RUA_UnsuccessfulOutcome.h	\
	RUA_Connect.h	\
	RUA_DirectTransfer.h	\
	RUA_Disconnect.h	\
	RUA_ConnectionlessTransfer.h	\
	RUA_ErrorIndication.h	\
	RUA_PrivateMessage.h	\
	RUA_CN-DomainIndicator.h	\
	RUA_CSGMembershipStatus.h	\
	RUA_Establishment-Cause.h	\
	RUA_Context-ID.h	\
	RUA_IntraDomainNasNodeSelector.h	\
	RUA_Gsm-map-IDNNS.h	\
	RUA_Ansi-41-IDNNS.h	\
	RUA_RANAP-Message.h	\
	RUA_RoutingParameter.h	\
	RUA_Cause.h	\
	RUA_CauseRadioNetwork.h	\
	RUA_CauseTransport.h	\
	RUA_CauseProtocol.h	\
	RUA_CauseMisc.h	\
	RUA_CriticalityDiagnostics.h	\
	RUA_CriticalityDiagnostics-IE-List.h	\
	RUA_TypeOfError.h	\
	RUA_Criticality.h	\
	RUA_Presence.h	\
	RUA_ProcedureCode.h	\
	RUA_PrivateIE-ID.h	\
	RUA_ProtocolIE-ID.h	\
	RUA_TriggeringMessage.h	\
	RUA_ProtocolIE-Container.h	\
	RUA_ProtocolIE-Single-Container.h	\
	RUA_ProtocolIE-Field.h	\
	RUA_ProtocolIE-ContainerList.h	\
	RUA_ProtocolExtensionContainer.h	\
	RUA_ProtocolExtensionField.h	\
	RUA_PrivateIE-Container.h	\
	RUA_PrivateIE-Field.h \
	RUA_asn_constant.h

AM_CFLAGS = -I$(top_srcdir)/include $(ASN1C_CFLAGS) $(OSMOCORE_CFLAGS)

noinst_LIBRARIES=libosmo-asn1-rua.a
libosmo_asn1_rua_a_SOURCES=$(ASN_MODULE_SOURCES)
libosmo_asn1_rua_a_LIBADD=$(ASN1C_LDADD)

regen: regenerate-from-asn1-source

regenerate-from-asn1-source:
	ASN1C_PREFIX="RUA_" asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example $(top_srcdir)/asn1/rua/rua-14.0.0.asn1
#	change include style to `#include <dir/foo.h>'
	$(top_srcdir)/move-asn1-header-files.sh osmocom/rua $(ASN_MODULE_INC)
#	remove the local copy of the runtime code
	@rm -f ANY.* BOOLEAN.* INTEGER*.* NativeEnumerated*.* NativeInteger*.* NULL.* OBJECT_IDENTIFIER.* OCTET_STRING*.* OPEN_TYPE*.* converter-sample.c oer_* per_* xer_* constr* der_* ber_* BIT_STRING*.* asn*.*

