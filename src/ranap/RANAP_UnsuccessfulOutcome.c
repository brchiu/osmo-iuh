/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-PDU-Descriptions"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#include <osmocom/ranap/RANAP_UnsuccessfulOutcome.h>

static const long asn_VAL_1_RANAP_id_Iu_Release = 1;
static const long asn_VAL_1_RANAP_reject = 0;
static const long asn_VAL_2_RANAP_id_RelocationPreparation = 2;
static const long asn_VAL_2_RANAP_reject = 0;
static const long asn_VAL_3_RANAP_id_RelocationResourceAllocation = 3;
static const long asn_VAL_3_RANAP_reject = 0;
static const long asn_VAL_4_RANAP_id_RelocationCancel = 4;
static const long asn_VAL_4_RANAP_reject = 0;
static const long asn_VAL_5_RANAP_id_SRNS_ContextTransfer = 5;
static const long asn_VAL_5_RANAP_reject = 0;
static const long asn_VAL_6_RANAP_id_SecurityModeControl = 6;
static const long asn_VAL_6_RANAP_reject = 0;
static const long asn_VAL_7_RANAP_id_DataVolumeReport = 7;
static const long asn_VAL_7_RANAP_reject = 0;
static const long asn_VAL_8_RANAP_id_Reset = 9;
static const long asn_VAL_8_RANAP_reject = 0;
static const long asn_VAL_9_RANAP_id_ResetResource = 27;
static const long asn_VAL_9_RANAP_reject = 0;
static const long asn_VAL_10_RANAP_id_LocationRelatedData = 30;
static const long asn_VAL_10_RANAP_reject = 0;
static const long asn_VAL_11_RANAP_id_InformationTransfer = 31;
static const long asn_VAL_11_RANAP_reject = 0;
static const long asn_VAL_12_RANAP_id_UplinkInformationExchange = 33;
static const long asn_VAL_12_RANAP_reject = 0;
static const long asn_VAL_13_RANAP_id_MBMSSessionStart = 35;
static const long asn_VAL_13_RANAP_reject = 0;
static const long asn_VAL_14_RANAP_id_MBMSSessionUpdate = 36;
static const long asn_VAL_14_RANAP_reject = 0;
static const long asn_VAL_15_RANAP_id_MBMSSessionStop = 37;
static const long asn_VAL_15_RANAP_reject = 0;
static const long asn_VAL_16_RANAP_id_MBMSUELinking = 38;
static const long asn_VAL_16_RANAP_reject = 0;
static const long asn_VAL_17_RANAP_id_MBMSRegistration = 39;
static const long asn_VAL_17_RANAP_reject = 0;
static const long asn_VAL_18_RANAP_id_MBMSCNDe_Registration_Procedure = 40;
static const long asn_VAL_18_RANAP_reject = 0;
static const long asn_VAL_19_RANAP_id_MBMSRABRelease = 42;
static const long asn_VAL_19_RANAP_reject = 0;
static const long asn_VAL_20_RANAP_id_enhancedRelocationComplete = 43;
static const long asn_VAL_20_RANAP_reject = 0;
static const long asn_VAL_21_RANAP_id_RANAPenhancedRelocation = 45;
static const long asn_VAL_21_RANAP_reject = 0;
static const long asn_VAL_22_RANAP_id_SRVCCPreparation = 46;
static const long asn_VAL_22_RANAP_reject = 0;
static const long asn_VAL_23_RANAP_id_UeRadioCapabilityMatch = 47;
static const long asn_VAL_23_RANAP_ignore = 1;
static const long asn_VAL_24_RANAP_id_UeRegistrationQuery = 48;
static const long asn_VAL_24_RANAP_ignore = 1;
static const long asn_VAL_25_RANAP_id_RAB_ReleaseRequest = 10;
static const long asn_VAL_25_RANAP_ignore = 1;
static const long asn_VAL_26_RANAP_id_Iu_ReleaseRequest = 11;
static const long asn_VAL_26_RANAP_ignore = 1;
static const long asn_VAL_27_RANAP_id_RelocationDetect = 12;
static const long asn_VAL_27_RANAP_ignore = 1;
static const long asn_VAL_28_RANAP_id_RelocationComplete = 13;
static const long asn_VAL_28_RANAP_ignore = 1;
static const long asn_VAL_29_RANAP_id_Paging = 14;
static const long asn_VAL_29_RANAP_ignore = 1;
static const long asn_VAL_30_RANAP_id_CommonID = 15;
static const long asn_VAL_30_RANAP_ignore = 1;
static const long asn_VAL_31_RANAP_id_CN_InvokeTrace = 16;
static const long asn_VAL_31_RANAP_ignore = 1;
static const long asn_VAL_32_RANAP_id_CN_DeactivateTrace = 26;
static const long asn_VAL_32_RANAP_ignore = 1;
static const long asn_VAL_33_RANAP_id_LocationReportingControl = 17;
static const long asn_VAL_33_RANAP_ignore = 1;
static const long asn_VAL_34_RANAP_id_LocationReport = 18;
static const long asn_VAL_34_RANAP_ignore = 1;
static const long asn_VAL_35_RANAP_id_InitialUE_Message = 19;
static const long asn_VAL_35_RANAP_ignore = 1;
static const long asn_VAL_36_RANAP_id_DirectTransfer = 20;
static const long asn_VAL_36_RANAP_ignore = 1;
static const long asn_VAL_37_RANAP_id_OverloadControl = 21;
static const long asn_VAL_37_RANAP_ignore = 1;
static const long asn_VAL_38_RANAP_id_ErrorIndication = 22;
static const long asn_VAL_38_RANAP_ignore = 1;
static const long asn_VAL_39_RANAP_id_SRNS_DataForward = 23;
static const long asn_VAL_39_RANAP_ignore = 1;
static const long asn_VAL_40_RANAP_id_ForwardSRNS_Context = 24;
static const long asn_VAL_40_RANAP_ignore = 1;
static const long asn_VAL_41_RANAP_id_privateMessage = 25;
static const long asn_VAL_41_RANAP_ignore = 1;
static const long asn_VAL_42_RANAP_id_RANAP_Relocation = 28;
static const long asn_VAL_42_RANAP_ignore = 1;
static const long asn_VAL_43_RANAP_id_RAB_ModifyRequest = 29;
static const long asn_VAL_43_RANAP_ignore = 1;
static const long asn_VAL_44_RANAP_id_UESpecificInformation = 32;
static const long asn_VAL_44_RANAP_ignore = 1;
static const long asn_VAL_45_RANAP_id_DirectInformationTransfer = 34;
static const long asn_VAL_45_RANAP_ignore = 1;
static const long asn_VAL_46_RANAP_id_MBMSRABEstablishmentIndication = 41;
static const long asn_VAL_46_RANAP_ignore = 1;
static const long asn_VAL_47_RANAP_id_enhancedRelocationCompleteConfirm = 44;
static const long asn_VAL_47_RANAP_ignore = 1;
static const long asn_VAL_48_RANAP_id_RerouteNASRequest = 49;
static const long asn_VAL_48_RANAP_reject = 0;
static const long asn_VAL_49_RANAP_id_RAB_Assignment = 0;
static const long asn_VAL_49_RANAP_reject = 0;
static const asn_ioc_cell_t asn_IOS_RANAP_RANAP_ELEMENTARY_PROCEDURES_1_rows[] = {
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_Iu_ReleaseCommand },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_RANAP_Iu_ReleaseComplete },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_1_RANAP_id_Iu_Release },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_1_RANAP_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_RelocationRequired },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_RANAP_RelocationCommand },
	{ "&UnsuccessfulOutcome", aioc__type, &asn_DEF_RANAP_RelocationPreparationFailure },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_2_RANAP_id_RelocationPreparation },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_2_RANAP_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_RelocationRequest },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_RANAP_RelocationRequestAcknowledge },
	{ "&UnsuccessfulOutcome", aioc__type, &asn_DEF_RANAP_RelocationFailure },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_3_RANAP_id_RelocationResourceAllocation },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_3_RANAP_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_RelocationCancel },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_RANAP_RelocationCancelAcknowledge },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_4_RANAP_id_RelocationCancel },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_4_RANAP_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_SRNS_ContextRequest },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_RANAP_SRNS_ContextResponse },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_5_RANAP_id_SRNS_ContextTransfer },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_5_RANAP_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_SecurityModeCommand },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_RANAP_SecurityModeComplete },
	{ "&UnsuccessfulOutcome", aioc__type, &asn_DEF_RANAP_SecurityModeReject },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_6_RANAP_id_SecurityModeControl },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_6_RANAP_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_DataVolumeReportRequest },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_RANAP_DataVolumeReport },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_7_RANAP_id_DataVolumeReport },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_7_RANAP_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_Reset },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_RANAP_ResetAcknowledge },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_8_RANAP_id_Reset },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_8_RANAP_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_ResetResource },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_RANAP_ResetResourceAcknowledge },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_9_RANAP_id_ResetResource },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_9_RANAP_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_LocationRelatedDataRequest },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_RANAP_LocationRelatedDataResponse },
	{ "&UnsuccessfulOutcome", aioc__type, &asn_DEF_RANAP_LocationRelatedDataFailure },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_10_RANAP_id_LocationRelatedData },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_10_RANAP_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_InformationTransferIndication },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_RANAP_InformationTransferConfirmation },
	{ "&UnsuccessfulOutcome", aioc__type, &asn_DEF_RANAP_InformationTransferFailure },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_11_RANAP_id_InformationTransfer },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_11_RANAP_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_UplinkInformationExchangeRequest },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_RANAP_UplinkInformationExchangeResponse },
	{ "&UnsuccessfulOutcome", aioc__type, &asn_DEF_RANAP_UplinkInformationExchangeFailure },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_12_RANAP_id_UplinkInformationExchange },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_12_RANAP_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_MBMSSessionStart },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_RANAP_MBMSSessionStartResponse },
	{ "&UnsuccessfulOutcome", aioc__type, &asn_DEF_RANAP_MBMSSessionStartFailure },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_13_RANAP_id_MBMSSessionStart },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_13_RANAP_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_MBMSSessionUpdate },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_RANAP_MBMSSessionUpdateResponse },
	{ "&UnsuccessfulOutcome", aioc__type, &asn_DEF_RANAP_MBMSSessionUpdateFailure },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_14_RANAP_id_MBMSSessionUpdate },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_14_RANAP_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_MBMSSessionStop },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_RANAP_MBMSSessionStopResponse },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_15_RANAP_id_MBMSSessionStop },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_15_RANAP_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_MBMSUELinkingRequest },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome", aioc__type, &asn_DEF_RANAP_MBMSUELinkingResponse },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_16_RANAP_id_MBMSUELinking },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_16_RANAP_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_MBMSRegistrationRequest },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_RANAP_MBMSRegistrationResponse },
	{ "&UnsuccessfulOutcome", aioc__type, &asn_DEF_RANAP_MBMSRegistrationFailure },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_17_RANAP_id_MBMSRegistration },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_17_RANAP_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_MBMSCNDe_RegistrationRequest },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_RANAP_MBMSCNDe_RegistrationResponse },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_18_RANAP_id_MBMSCNDe_Registration_Procedure },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_18_RANAP_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_MBMSRABReleaseRequest },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_RANAP_MBMSRABRelease },
	{ "&UnsuccessfulOutcome", aioc__type, &asn_DEF_RANAP_MBMSRABReleaseFailure },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_19_RANAP_id_MBMSRABRelease },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_19_RANAP_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_EnhancedRelocationCompleteRequest },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_RANAP_EnhancedRelocationCompleteResponse },
	{ "&UnsuccessfulOutcome", aioc__type, &asn_DEF_RANAP_EnhancedRelocationCompleteFailure },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_20_RANAP_id_enhancedRelocationComplete },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_20_RANAP_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_RANAP_EnhancedRelocationInformationRequest },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_RANAP_RANAP_EnhancedRelocationInformationResponse },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_21_RANAP_id_RANAPenhancedRelocation },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_21_RANAP_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_SRVCC_CSKeysRequest },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome", aioc__type, &asn_DEF_RANAP_SRVCC_CSKeysResponse },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_22_RANAP_id_SRVCCPreparation },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_22_RANAP_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_UeRadioCapabilityMatchRequest },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome", aioc__type, &asn_DEF_RANAP_UeRadioCapabilityMatchResponse },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_23_RANAP_id_UeRadioCapabilityMatch },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_23_RANAP_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_UeRegistrationQueryRequest },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome", aioc__type, &asn_DEF_RANAP_UeRegistrationQueryResponse },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_24_RANAP_id_UeRegistrationQuery },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_24_RANAP_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_RAB_ReleaseRequest },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_25_RANAP_id_RAB_ReleaseRequest },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_25_RANAP_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_Iu_ReleaseRequest },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_26_RANAP_id_Iu_ReleaseRequest },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_26_RANAP_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_RelocationDetect },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_27_RANAP_id_RelocationDetect },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_27_RANAP_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_RelocationComplete },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_28_RANAP_id_RelocationComplete },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_28_RANAP_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_Paging },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_29_RANAP_id_Paging },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_29_RANAP_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_CommonID },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_30_RANAP_id_CommonID },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_30_RANAP_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_CN_InvokeTrace },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_31_RANAP_id_CN_InvokeTrace },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_31_RANAP_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_CN_DeactivateTrace },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_32_RANAP_id_CN_DeactivateTrace },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_32_RANAP_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_LocationReportingControl },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_33_RANAP_id_LocationReportingControl },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_33_RANAP_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_LocationReport },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_34_RANAP_id_LocationReport },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_34_RANAP_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_InitialUE_Message },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_35_RANAP_id_InitialUE_Message },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_35_RANAP_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_DirectTransfer },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_36_RANAP_id_DirectTransfer },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_36_RANAP_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_Overload },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_37_RANAP_id_OverloadControl },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_37_RANAP_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_ErrorIndication },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_38_RANAP_id_ErrorIndication },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_38_RANAP_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_SRNS_DataForwardCommand },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_39_RANAP_id_SRNS_DataForward },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_39_RANAP_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_ForwardSRNS_Context },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_40_RANAP_id_ForwardSRNS_Context },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_40_RANAP_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_PrivateMessage },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_41_RANAP_id_privateMessage },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_41_RANAP_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_RANAP_RelocationInformation },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_42_RANAP_id_RANAP_Relocation },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_42_RANAP_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_RAB_ModifyRequest },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_43_RANAP_id_RAB_ModifyRequest },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_43_RANAP_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_UESpecificInformationIndication },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_44_RANAP_id_UESpecificInformation },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_44_RANAP_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_DirectInformationTransfer },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_45_RANAP_id_DirectInformationTransfer },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_45_RANAP_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_MBMSRABEstablishmentIndication },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_46_RANAP_id_MBMSRABEstablishmentIndication },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_46_RANAP_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_EnhancedRelocationCompleteConfirm },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_47_RANAP_id_enhancedRelocationCompleteConfirm },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_47_RANAP_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_RerouteNASRequest },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_48_RANAP_id_RerouteNASRequest },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_48_RANAP_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_RANAP_RAB_AssignmentRequest },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&Outcome", aioc__type, &asn_DEF_RANAP_RAB_AssignmentResponse },
	{ "&procedureCode", aioc__value, &asn_DEF_RANAP_ProcedureCode, &asn_VAL_49_RANAP_id_RAB_Assignment },
	{ "&criticality", aioc__value, &asn_DEF_RANAP_Criticality, &asn_VAL_49_RANAP_reject }
};
static const asn_ioc_set_t asn_IOS_RANAP_RANAP_ELEMENTARY_PROCEDURES_1[] = {
	{ 49, 6, asn_IOS_RANAP_RANAP_ELEMENTARY_PROCEDURES_1_rows }
};
static int
memb_RANAP_procedureCode_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 255)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_type_selector_result_t
select_UnsuccessfulOutcome_RANAP_criticality_type(const asn_TYPE_descriptor_t *parent_type, const void *parent_sptr) {
	asn_type_selector_result_t result = {0, 0};
	const asn_ioc_set_t *itable = asn_IOS_RANAP_RANAP_ELEMENTARY_PROCEDURES_1;
	size_t constraining_column = 4; /* &procedureCode */
	size_t for_column = 5; /* &criticality */
	size_t row, presence_index = 0;
	const long *constraining_value = (const long *)((const char *)parent_sptr + offsetof(struct RANAP_UnsuccessfulOutcome, procedureCode));
	
	for(row=0; row < itable->rows_count; row++) {
	    const asn_ioc_cell_t *constraining_cell = &itable->rows[row * itable->columns_count + constraining_column];
	    const asn_ioc_cell_t *type_cell = &itable->rows[row * itable->columns_count + for_column];
	
	    if(type_cell->cell_kind == aioc__undefined)
	        continue;
	
	    presence_index++;
	    if(constraining_cell->type_descriptor->op->compare_struct(constraining_cell->type_descriptor, constraining_value, constraining_cell->value_sptr) == 0) {
	        result.type_descriptor = type_cell->type_descriptor;
	        result.presence_index = presence_index;
	        break;
	    }
	}
	
	return result;
}

static int
memb_RANAP_criticality_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	
	if(1 /* No applicable constraints whatsoever */) {
		/* Nothing is here. See below */
	}
	
	return td->encoding_constraints.general_constraints(td, sptr, ctfailcb, app_key);
}

static asn_type_selector_result_t
select_UnsuccessfulOutcome_RANAP_value_type(const asn_TYPE_descriptor_t *parent_type, const void *parent_sptr) {
	asn_type_selector_result_t result = {0, 0};
	const asn_ioc_set_t *itable = asn_IOS_RANAP_RANAP_ELEMENTARY_PROCEDURES_1;
	size_t constraining_column = 4; /* &procedureCode */
	size_t for_column = 2; /* &UnsuccessfulOutcome */
	size_t row, presence_index = 0;
	const long *constraining_value = (const long *)((const char *)parent_sptr + offsetof(struct RANAP_UnsuccessfulOutcome, procedureCode));
	
	for(row=0; row < itable->rows_count; row++) {
	    const asn_ioc_cell_t *constraining_cell = &itable->rows[row * itable->columns_count + constraining_column];
	    const asn_ioc_cell_t *type_cell = &itable->rows[row * itable->columns_count + for_column];
	
	    if(type_cell->cell_kind == aioc__undefined)
	        continue;
	
	    presence_index++;
	    if(constraining_cell->type_descriptor->op->compare_struct(constraining_cell->type_descriptor, constraining_value, constraining_cell->value_sptr) == 0) {
	        result.type_descriptor = type_cell->type_descriptor;
	        result.presence_index = presence_index;
	        break;
	    }
	}
	
	return result;
}

static int
memb_RANAP_value_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	
	if(1 /* No applicable constraints whatsoever */) {
		/* Nothing is here. See below */
	}
	
	return td->encoding_constraints.general_constraints(td, sptr, ctfailcb, app_key);
}

static asn_oer_constraints_t asn_OER_memb_RANAP_procedureCode_constr_2 CC_NOTUSED = {
	{ 1, 1 }	/* (0..255) */,
	-1};
static asn_per_constraints_t asn_PER_memb_RANAP_procedureCode_constr_2 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 8,  8,  0,  255 }	/* (0..255) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_RANAP_criticality_constr_3 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_memb_RANAP_criticality_constr_3 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  2 }	/* (0..2) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_RANAP_value_constr_4 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_memb_RANAP_value_constr_4 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_RANAP_value_4[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_UnsuccessfulOutcome__value, choice.RelocationPreparationFailure),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_RANAP_RelocationPreparationFailure,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"RelocationPreparationFailure"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_UnsuccessfulOutcome__value, choice.RelocationFailure),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_RANAP_RelocationFailure,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"RelocationFailure"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_UnsuccessfulOutcome__value, choice.SecurityModeReject),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_RANAP_SecurityModeReject,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"SecurityModeReject"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_UnsuccessfulOutcome__value, choice.LocationRelatedDataFailure),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_RANAP_LocationRelatedDataFailure,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"LocationRelatedDataFailure"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_UnsuccessfulOutcome__value, choice.InformationTransferFailure),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_RANAP_InformationTransferFailure,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"InformationTransferFailure"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_UnsuccessfulOutcome__value, choice.UplinkInformationExchangeFailure),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_RANAP_UplinkInformationExchangeFailure,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"UplinkInformationExchangeFailure"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_UnsuccessfulOutcome__value, choice.MBMSSessionStartFailure),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_RANAP_MBMSSessionStartFailure,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"MBMSSessionStartFailure"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_UnsuccessfulOutcome__value, choice.MBMSSessionUpdateFailure),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_RANAP_MBMSSessionUpdateFailure,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"MBMSSessionUpdateFailure"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_UnsuccessfulOutcome__value, choice.MBMSRegistrationFailure),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_RANAP_MBMSRegistrationFailure,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"MBMSRegistrationFailure"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_UnsuccessfulOutcome__value, choice.MBMSRABReleaseFailure),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_RANAP_MBMSRABReleaseFailure,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"MBMSRABReleaseFailure"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_UnsuccessfulOutcome__value, choice.EnhancedRelocationCompleteFailure),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_RANAP_EnhancedRelocationCompleteFailure,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"EnhancedRelocationCompleteFailure"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_RANAP_value_tag2el_4[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 10 }, /* RelocationPreparationFailure */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 1, -1, 9 }, /* RelocationFailure */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 2, -2, 8 }, /* SecurityModeReject */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 3, -3, 7 }, /* LocationRelatedDataFailure */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 4, -4, 6 }, /* InformationTransferFailure */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 5, -5, 5 }, /* UplinkInformationExchangeFailure */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 6, -6, 4 }, /* MBMSSessionStartFailure */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 7, -7, 3 }, /* MBMSSessionUpdateFailure */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 8, -8, 2 }, /* MBMSRegistrationFailure */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 9, -9, 1 }, /* MBMSRABReleaseFailure */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 10, -10, 0 } /* EnhancedRelocationCompleteFailure */
};
static asn_CHOICE_specifics_t asn_SPC_RANAP_value_specs_4 = {
	sizeof(struct RANAP_UnsuccessfulOutcome__value),
	offsetof(struct RANAP_UnsuccessfulOutcome__value, _asn_ctx),
	offsetof(struct RANAP_UnsuccessfulOutcome__value, present),
	sizeof(((struct RANAP_UnsuccessfulOutcome__value *)0)->present),
	asn_MAP_RANAP_value_tag2el_4,
	11,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_RANAP_value_4 = {
	"value",
	"value",
	&asn_OP_OPEN_TYPE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ 0, 0, OPEN_TYPE_constraint },
	asn_MBR_RANAP_value_4,
	11,	/* Elements count */
	&asn_SPC_RANAP_value_specs_4	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_RANAP_UnsuccessfulOutcome_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_UnsuccessfulOutcome, procedureCode),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_ProcedureCode,
		0,
		{ &asn_OER_memb_RANAP_procedureCode_constr_2, &asn_PER_memb_RANAP_procedureCode_constr_2,  memb_RANAP_procedureCode_constraint_1 },
		0, 0, /* No default value */
		"procedureCode"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RANAP_UnsuccessfulOutcome, criticality),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RANAP_Criticality,
		select_UnsuccessfulOutcome_RANAP_criticality_type,
		{ &asn_OER_memb_RANAP_criticality_constr_3, &asn_PER_memb_RANAP_criticality_constr_3,  memb_RANAP_criticality_constraint_1 },
		0, 0, /* No default value */
		"criticality"
		},
	{ ATF_OPEN_TYPE | ATF_NOFLAGS, 0, offsetof(struct RANAP_UnsuccessfulOutcome, value),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_RANAP_value_4,
		select_UnsuccessfulOutcome_RANAP_value_type,
		{ &asn_OER_memb_RANAP_value_constr_4, &asn_PER_memb_RANAP_value_constr_4,  memb_RANAP_value_constraint_1 },
		0, 0, /* No default value */
		"value"
		},
};
static const ber_tlv_tag_t asn_DEF_RANAP_UnsuccessfulOutcome_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RANAP_UnsuccessfulOutcome_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* procedureCode */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* criticality */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* value */
};
asn_SEQUENCE_specifics_t asn_SPC_RANAP_UnsuccessfulOutcome_specs_1 = {
	sizeof(struct RANAP_UnsuccessfulOutcome),
	offsetof(struct RANAP_UnsuccessfulOutcome, _asn_ctx),
	asn_MAP_RANAP_UnsuccessfulOutcome_tag2el_1,
	3,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_RANAP_UnsuccessfulOutcome = {
	"UnsuccessfulOutcome",
	"UnsuccessfulOutcome",
	&asn_OP_SEQUENCE,
	asn_DEF_RANAP_UnsuccessfulOutcome_tags_1,
	sizeof(asn_DEF_RANAP_UnsuccessfulOutcome_tags_1)
		/sizeof(asn_DEF_RANAP_UnsuccessfulOutcome_tags_1[0]), /* 1 */
	asn_DEF_RANAP_UnsuccessfulOutcome_tags_1,	/* Same as above */
	sizeof(asn_DEF_RANAP_UnsuccessfulOutcome_tags_1)
		/sizeof(asn_DEF_RANAP_UnsuccessfulOutcome_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_RANAP_UnsuccessfulOutcome_1,
	3,	/* Elements count */
	&asn_SPC_RANAP_UnsuccessfulOutcome_specs_1	/* Additional specs */
};

