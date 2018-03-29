/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "HNBAP-Containers"
 * 	found in "../../asn1/hnbap/hnbap-14.0.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_ProtocolExtensionField_H_
#define	_ProtocolExtensionField_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/hnbap/ProtocolIE-ID.h>
#include <osmocom/hnbap/Criticality.h>
#include <ANY.h>
#include <asn_ioc.h>
#include <osmocom/hnbap/SAC.h>
#include <osmocom/hnbap/Presence.h>
#include <osmocom/hnbap/HNB-Cell-Access-Mode.h>
#include <osmocom/hnbap/PSC.h>
#include <osmocom/hnbap/IP-Address.h>
#include <osmocom/hnbap/Tunnel-Information.h>
#include <osmocom/hnbap/CELL-FACHMobilitySupport.h>
#include <osmocom/hnbap/NeighbourCellIdentityList.h>
#include <osmocom/hnbap/URAIdentityList.h>
#include <osmocom/hnbap/HNBCapacity.h>
#include <OPEN_TYPE.h>
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>
#include <osmocom/hnbap/MuxPortNumber.h>
#include <osmocom/hnbap/S-RNTIPrefix.h>
#include <osmocom/hnbap/CSGMembershipStatus.h>
#include <osmocom/hnbap/AdditionalNeighbourInfoList.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum HNBRegisterRequestExtensions__extensionValue_PR {
	HNBRegisterRequestExtensions__extensionValue_PR_NOTHING,	/* No components present */
	HNBRegisterRequestExtensions__extensionValue_PR_SAC,
	HNBRegisterRequestExtensions__extensionValue_PR_HNB_Cell_Access_Mode,
	HNBRegisterRequestExtensions__extensionValue_PR_PSC,
	HNBRegisterRequestExtensions__extensionValue_PR_IP_Address,
	HNBRegisterRequestExtensions__extensionValue_PR_Tunnel_Information,
	HNBRegisterRequestExtensions__extensionValue_PR_CELL_FACHMobilitySupport,
	HNBRegisterRequestExtensions__extensionValue_PR_NeighbourCellIdentityList,
	HNBRegisterRequestExtensions__extensionValue_PR_URAIdentityList,
	HNBRegisterRequestExtensions__extensionValue_PR_HNBCapacity
} HNBRegisterRequestExtensions__extensionValue_PR;
typedef enum HNBRegisterResponseExtensions__extensionValue_PR {
	HNBRegisterResponseExtensions__extensionValue_PR_NOTHING,	/* No components present */
	HNBRegisterResponseExtensions__extensionValue_PR_MuxPortNumber,
	HNBRegisterResponseExtensions__extensionValue_PR_IP_Address,
	HNBRegisterResponseExtensions__extensionValue_PR_S_RNTIPrefix
} HNBRegisterResponseExtensions__extensionValue_PR;
typedef enum HNBRegisterRejectExtensions__extensionValue_PR {
	HNBRegisterRejectExtensions__extensionValue_PR_NOTHING	/* No components present */
	
} HNBRegisterRejectExtensions__extensionValue_PR;
typedef enum HNBDe_RegisterExtensions__extensionValue_PR {
	HNBDe_RegisterExtensions__extensionValue_PR_NOTHING	/* No components present */
	
} HNBDe_RegisterExtensions__extensionValue_PR;
typedef enum UERegisterRequestExtensions__extensionValue_PR {
	UERegisterRequestExtensions__extensionValue_PR_NOTHING	/* No components present */
	
} UERegisterRequestExtensions__extensionValue_PR;
typedef enum UERegisterAcceptExtensions__extensionValue_PR {
	UERegisterAcceptExtensions__extensionValue_PR_NOTHING,	/* No components present */
	UERegisterAcceptExtensions__extensionValue_PR_CSGMembershipStatus
} UERegisterAcceptExtensions__extensionValue_PR;
typedef enum UERegisterRejectExtensions__extensionValue_PR {
	UERegisterRejectExtensions__extensionValue_PR_NOTHING	/* No components present */
	
} UERegisterRejectExtensions__extensionValue_PR;
typedef enum UEDe_RegisterExtensions__extensionValue_PR {
	UEDe_RegisterExtensions__extensionValue_PR_NOTHING	/* No components present */
	
} UEDe_RegisterExtensions__extensionValue_PR;
typedef enum CSGMembershipUpdateExtensions__extensionValue_PR {
	CSGMembershipUpdateExtensions__extensionValue_PR_NOTHING	/* No components present */
	
} CSGMembershipUpdateExtensions__extensionValue_PR;
typedef enum TNLUpdateExtensions__extensionValue_PR {
	TNLUpdateExtensions__extensionValue_PR_NOTHING	/* No components present */
	
} TNLUpdateExtensions__extensionValue_PR;
typedef enum TNLUpdateResponseExtensions__extensionValue_PR {
	TNLUpdateResponseExtensions__extensionValue_PR_NOTHING	/* No components present */
	
} TNLUpdateResponseExtensions__extensionValue_PR;
typedef enum TNLUpdateFailureExtensions__extensionValue_PR {
	TNLUpdateFailureExtensions__extensionValue_PR_NOTHING	/* No components present */
	
} TNLUpdateFailureExtensions__extensionValue_PR;
typedef enum HNBConfigTransferRequestExtensions__extensionValue_PR {
	HNBConfigTransferRequestExtensions__extensionValue_PR_NOTHING	/* No components present */
	
} HNBConfigTransferRequestExtensions__extensionValue_PR;
typedef enum HNBConfigTransferResponseExtensions__extensionValue_PR {
	HNBConfigTransferResponseExtensions__extensionValue_PR_NOTHING,	/* No components present */
	HNBConfigTransferResponseExtensions__extensionValue_PR_AdditionalNeighbourInfoList
} HNBConfigTransferResponseExtensions__extensionValue_PR;
typedef enum RelocationCompleteExtensions__extensionValue_PR {
	RelocationCompleteExtensions__extensionValue_PR_NOTHING	/* No components present */
	
} RelocationCompleteExtensions__extensionValue_PR;
typedef enum ErrorIndicationExtensions__extensionValue_PR {
	ErrorIndicationExtensions__extensionValue_PR_NOTHING	/* No components present */
	
} ErrorIndicationExtensions__extensionValue_PR;
typedef enum U_RNTIQueryRequestExtensions__extensionValue_PR {
	U_RNTIQueryRequestExtensions__extensionValue_PR_NOTHING	/* No components present */
	
} U_RNTIQueryRequestExtensions__extensionValue_PR;
typedef enum U_RNTIQueryResponseExtensions__extensionValue_PR {
	U_RNTIQueryResponseExtensions__extensionValue_PR_NOTHING	/* No components present */
	
} U_RNTIQueryResponseExtensions__extensionValue_PR;
typedef enum CriticalityDiagnostics_ExtIEs__extensionValue_PR {
	CriticalityDiagnostics_ExtIEs__extensionValue_PR_NOTHING	/* No components present */
	
} CriticalityDiagnostics_ExtIEs__extensionValue_PR;
typedef enum CriticalityDiagnostics_IE_List_ExtIEs__extensionValue_PR {
	CriticalityDiagnostics_IE_List_ExtIEs__extensionValue_PR_NOTHING	/* No components present */
	
} CriticalityDiagnostics_IE_List_ExtIEs__extensionValue_PR;
typedef enum CGI_ExtIEs__extensionValue_PR {
	CGI_ExtIEs__extensionValue_PR_NOTHING	/* No components present */
	
} CGI_ExtIEs__extensionValue_PR;
typedef enum GeographicLocation_ExtIEs__extensionValue_PR {
	GeographicLocation_ExtIEs__extensionValue_PR_NOTHING	/* No components present */
	
} GeographicLocation_ExtIEs__extensionValue_PR;
typedef enum GeographicalCoordinates_ExtIEs__extensionValue_PR {
	GeographicalCoordinates_ExtIEs__extensionValue_PR_NOTHING	/* No components present */
	
} GeographicalCoordinates_ExtIEs__extensionValue_PR;
typedef enum HNB_Cell_Identifier_ExtIEs__extensionValue_PR {
	HNB_Cell_Identifier_ExtIEs__extensionValue_PR_NOTHING	/* No components present */
	
} HNB_Cell_Identifier_ExtIEs__extensionValue_PR;
typedef enum HNBConfigInfo_ExtIEs__extensionValue_PR {
	HNBConfigInfo_ExtIEs__extensionValue_PR_NOTHING	/* No components present */
	
} HNBConfigInfo_ExtIEs__extensionValue_PR;
typedef enum HNBConfigurationInformationProvided_ExtIEs__extensionValue_PR {
	HNBConfigurationInformationProvided_ExtIEs__extensionValue_PR_NOTHING,	/* No components present */
	HNBConfigurationInformationProvided_ExtIEs__extensionValue_PR_S_RNTIPrefix,
	HNBConfigurationInformationProvided_ExtIEs__extensionValue_PR_URAIdentityList
} HNBConfigurationInformationProvided_ExtIEs__extensionValue_PR;
typedef enum HNBConfigurationInformationMissing_ExtIEs__extensionValue_PR {
	HNBConfigurationInformationMissing_ExtIEs__extensionValue_PR_NOTHING	/* No components present */
	
} HNBConfigurationInformationMissing_ExtIEs__extensionValue_PR;
typedef enum HNB_Location_Information_ExtIEs__extensionValue_PR {
	HNB_Location_Information_ExtIEs__extensionValue_PR_NOTHING,	/* No components present */
	HNB_Location_Information_ExtIEs__extensionValue_PR_IP_Address
} HNB_Location_Information_ExtIEs__extensionValue_PR;
typedef enum HNB_Identity_ExtIEs__extensionValue_PR {
	HNB_Identity_ExtIEs__extensionValue_PR_NOTHING	/* No components present */
	
} HNB_Identity_ExtIEs__extensionValue_PR;
typedef enum IP_Address_ExtIEs__extensionValue_PR {
	IP_Address_ExtIEs__extensionValue_PR_NOTHING	/* No components present */
	
} IP_Address_ExtIEs__extensionValue_PR;
typedef enum MacroCoverageInformation_ExtIEs__extensionValue_PR {
	MacroCoverageInformation_ExtIEs__extensionValue_PR_NOTHING	/* No components present */
	
} MacroCoverageInformation_ExtIEs__extensionValue_PR;
typedef enum NeighbourInfoRequestItem_ExtIEs__extensionValue_PR {
	NeighbourInfoRequestItem_ExtIEs__extensionValue_PR_NOTHING	/* No components present */
	
} NeighbourInfoRequestItem_ExtIEs__extensionValue_PR;
typedef enum RABListItem_ExtIEs__extensionValue_PR {
	RABListItem_ExtIEs__extensionValue_PR_NOTHING	/* No components present */
	
} RABListItem_ExtIEs__extensionValue_PR;
typedef enum TransportInfo_ExtIEs__extensionValue_PR {
	TransportInfo_ExtIEs__extensionValue_PR_NOTHING	/* No components present */
	
} TransportInfo_ExtIEs__extensionValue_PR;
typedef enum Tunnel_Information_ExtIEs__extensionValue_PR {
	Tunnel_Information_ExtIEs__extensionValue_PR_NOTHING	/* No components present */
	
} Tunnel_Information_ExtIEs__extensionValue_PR;
typedef enum UE_Capabilities_ExtIEs__extensionValue_PR {
	UE_Capabilities_ExtIEs__extensionValue_PR_NOTHING	/* No components present */
	
} UE_Capabilities_ExtIEs__extensionValue_PR;
typedef enum UTRANCellID_ExtIEs__extensionValue_PR {
	UTRANCellID_ExtIEs__extensionValue_PR_NOTHING	/* No components present */
	
} UTRANCellID_ExtIEs__extensionValue_PR;

/* ProtocolExtensionField */
typedef struct HNBRegisterRequestExtensions {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct HNBRegisterRequestExtensions__extensionValue {
		HNBRegisterRequestExtensions__extensionValue_PR present;
		union HNBRegisterRequestExtensions__extensionValue_u {
			SAC_t	 SAC;
			HNB_Cell_Access_Mode_t	 HNB_Cell_Access_Mode;
			PSC_t	 PSC;
			IP_Address_t	 IP_Address;
			Tunnel_Information_t	 Tunnel_Information;
			CELL_FACHMobilitySupport_t	 CELL_FACHMobilitySupport;
			NeighbourCellIdentityList_t	 NeighbourCellIdentityList;
			URAIdentityList_t	 URAIdentityList;
			HNBCapacity_t	 HNBCapacity;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} HNBRegisterRequestExtensions_t;
typedef struct HNBRegisterResponseExtensions {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct HNBRegisterResponseExtensions__extensionValue {
		HNBRegisterResponseExtensions__extensionValue_PR present;
		union HNBRegisterResponseExtensions__extensionValue_u {
			MuxPortNumber_t	 MuxPortNumber;
			IP_Address_t	 IP_Address;
			S_RNTIPrefix_t	 S_RNTIPrefix;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} HNBRegisterResponseExtensions_t;
typedef struct HNBRegisterRejectExtensions {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct HNBRegisterRejectExtensions__extensionValue {
		HNBRegisterRejectExtensions__extensionValue_PR present;
		union HNBRegisterRejectExtensions__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} HNBRegisterRejectExtensions_t;
typedef struct HNBDe_RegisterExtensions {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct HNBDe_RegisterExtensions__extensionValue {
		HNBDe_RegisterExtensions__extensionValue_PR present;
		union HNBDe_RegisterExtensions__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} HNBDe_RegisterExtensions_t;
typedef struct UERegisterRequestExtensions {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct UERegisterRequestExtensions__extensionValue {
		UERegisterRequestExtensions__extensionValue_PR present;
		union UERegisterRequestExtensions__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UERegisterRequestExtensions_t;
typedef struct UERegisterAcceptExtensions {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct UERegisterAcceptExtensions__extensionValue {
		UERegisterAcceptExtensions__extensionValue_PR present;
		union UERegisterAcceptExtensions__extensionValue_u {
			CSGMembershipStatus_t	 CSGMembershipStatus;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UERegisterAcceptExtensions_t;
typedef struct UERegisterRejectExtensions {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct UERegisterRejectExtensions__extensionValue {
		UERegisterRejectExtensions__extensionValue_PR present;
		union UERegisterRejectExtensions__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UERegisterRejectExtensions_t;
typedef struct UEDe_RegisterExtensions {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct UEDe_RegisterExtensions__extensionValue {
		UEDe_RegisterExtensions__extensionValue_PR present;
		union UEDe_RegisterExtensions__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UEDe_RegisterExtensions_t;
typedef struct CSGMembershipUpdateExtensions {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct CSGMembershipUpdateExtensions__extensionValue {
		CSGMembershipUpdateExtensions__extensionValue_PR present;
		union CSGMembershipUpdateExtensions__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CSGMembershipUpdateExtensions_t;
typedef struct TNLUpdateExtensions {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct TNLUpdateExtensions__extensionValue {
		TNLUpdateExtensions__extensionValue_PR present;
		union TNLUpdateExtensions__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} TNLUpdateExtensions_t;
typedef struct TNLUpdateResponseExtensions {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct TNLUpdateResponseExtensions__extensionValue {
		TNLUpdateResponseExtensions__extensionValue_PR present;
		union TNLUpdateResponseExtensions__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} TNLUpdateResponseExtensions_t;
typedef struct TNLUpdateFailureExtensions {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct TNLUpdateFailureExtensions__extensionValue {
		TNLUpdateFailureExtensions__extensionValue_PR present;
		union TNLUpdateFailureExtensions__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} TNLUpdateFailureExtensions_t;
typedef struct HNBConfigTransferRequestExtensions {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct HNBConfigTransferRequestExtensions__extensionValue {
		HNBConfigTransferRequestExtensions__extensionValue_PR present;
		union HNBConfigTransferRequestExtensions__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} HNBConfigTransferRequestExtensions_t;
typedef struct HNBConfigTransferResponseExtensions {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct HNBConfigTransferResponseExtensions__extensionValue {
		HNBConfigTransferResponseExtensions__extensionValue_PR present;
		union HNBConfigTransferResponseExtensions__extensionValue_u {
			AdditionalNeighbourInfoList_t	 AdditionalNeighbourInfoList;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} HNBConfigTransferResponseExtensions_t;
typedef struct RelocationCompleteExtensions {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct RelocationCompleteExtensions__extensionValue {
		RelocationCompleteExtensions__extensionValue_PR present;
		union RelocationCompleteExtensions__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RelocationCompleteExtensions_t;
typedef struct ErrorIndicationExtensions {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct ErrorIndicationExtensions__extensionValue {
		ErrorIndicationExtensions__extensionValue_PR present;
		union ErrorIndicationExtensions__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ErrorIndicationExtensions_t;
typedef struct U_RNTIQueryRequestExtensions {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct U_RNTIQueryRequestExtensions__extensionValue {
		U_RNTIQueryRequestExtensions__extensionValue_PR present;
		union U_RNTIQueryRequestExtensions__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} U_RNTIQueryRequestExtensions_t;
typedef struct U_RNTIQueryResponseExtensions {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct U_RNTIQueryResponseExtensions__extensionValue {
		U_RNTIQueryResponseExtensions__extensionValue_PR present;
		union U_RNTIQueryResponseExtensions__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} U_RNTIQueryResponseExtensions_t;
typedef struct CriticalityDiagnostics_ExtIEs {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct CriticalityDiagnostics_ExtIEs__extensionValue {
		CriticalityDiagnostics_ExtIEs__extensionValue_PR present;
		union CriticalityDiagnostics_ExtIEs__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CriticalityDiagnostics_ExtIEs_t;
typedef struct CriticalityDiagnostics_IE_List_ExtIEs {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct CriticalityDiagnostics_IE_List_ExtIEs__extensionValue {
		CriticalityDiagnostics_IE_List_ExtIEs__extensionValue_PR present;
		union CriticalityDiagnostics_IE_List_ExtIEs__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CriticalityDiagnostics_IE_List_ExtIEs_t;
typedef struct CGI_ExtIEs {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct CGI_ExtIEs__extensionValue {
		CGI_ExtIEs__extensionValue_PR present;
		union CGI_ExtIEs__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CGI_ExtIEs_t;
typedef struct GeographicLocation_ExtIEs {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct GeographicLocation_ExtIEs__extensionValue {
		GeographicLocation_ExtIEs__extensionValue_PR present;
		union GeographicLocation_ExtIEs__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} GeographicLocation_ExtIEs_t;
typedef struct GeographicalCoordinates_ExtIEs {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct GeographicalCoordinates_ExtIEs__extensionValue {
		GeographicalCoordinates_ExtIEs__extensionValue_PR present;
		union GeographicalCoordinates_ExtIEs__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} GeographicalCoordinates_ExtIEs_t;
typedef struct HNB_Cell_Identifier_ExtIEs {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct HNB_Cell_Identifier_ExtIEs__extensionValue {
		HNB_Cell_Identifier_ExtIEs__extensionValue_PR present;
		union HNB_Cell_Identifier_ExtIEs__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} HNB_Cell_Identifier_ExtIEs_t;
typedef struct HNBConfigInfo_ExtIEs {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct HNBConfigInfo_ExtIEs__extensionValue {
		HNBConfigInfo_ExtIEs__extensionValue_PR present;
		union HNBConfigInfo_ExtIEs__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} HNBConfigInfo_ExtIEs_t;
typedef struct HNBConfigurationInformationProvided_ExtIEs {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct HNBConfigurationInformationProvided_ExtIEs__extensionValue {
		HNBConfigurationInformationProvided_ExtIEs__extensionValue_PR present;
		union HNBConfigurationInformationProvided_ExtIEs__extensionValue_u {
			S_RNTIPrefix_t	 S_RNTIPrefix;
			URAIdentityList_t	 URAIdentityList;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} HNBConfigurationInformationProvided_ExtIEs_t;
typedef struct HNBConfigurationInformationMissing_ExtIEs {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct HNBConfigurationInformationMissing_ExtIEs__extensionValue {
		HNBConfigurationInformationMissing_ExtIEs__extensionValue_PR present;
		union HNBConfigurationInformationMissing_ExtIEs__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} HNBConfigurationInformationMissing_ExtIEs_t;
typedef struct HNB_Location_Information_ExtIEs {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct HNB_Location_Information_ExtIEs__extensionValue {
		HNB_Location_Information_ExtIEs__extensionValue_PR present;
		union HNB_Location_Information_ExtIEs__extensionValue_u {
			IP_Address_t	 IP_Address;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} HNB_Location_Information_ExtIEs_t;
typedef struct HNB_Identity_ExtIEs {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct HNB_Identity_ExtIEs__extensionValue {
		HNB_Identity_ExtIEs__extensionValue_PR present;
		union HNB_Identity_ExtIEs__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} HNB_Identity_ExtIEs_t;
typedef struct IP_Address_ExtIEs {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct IP_Address_ExtIEs__extensionValue {
		IP_Address_ExtIEs__extensionValue_PR present;
		union IP_Address_ExtIEs__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} IP_Address_ExtIEs_t;
typedef struct MacroCoverageInformation_ExtIEs {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct MacroCoverageInformation_ExtIEs__extensionValue {
		MacroCoverageInformation_ExtIEs__extensionValue_PR present;
		union MacroCoverageInformation_ExtIEs__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MacroCoverageInformation_ExtIEs_t;
typedef struct NeighbourInfoRequestItem_ExtIEs {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct NeighbourInfoRequestItem_ExtIEs__extensionValue {
		NeighbourInfoRequestItem_ExtIEs__extensionValue_PR present;
		union NeighbourInfoRequestItem_ExtIEs__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NeighbourInfoRequestItem_ExtIEs_t;
typedef struct RABListItem_ExtIEs {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct RABListItem_ExtIEs__extensionValue {
		RABListItem_ExtIEs__extensionValue_PR present;
		union RABListItem_ExtIEs__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RABListItem_ExtIEs_t;
typedef struct TransportInfo_ExtIEs {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct TransportInfo_ExtIEs__extensionValue {
		TransportInfo_ExtIEs__extensionValue_PR present;
		union TransportInfo_ExtIEs__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} TransportInfo_ExtIEs_t;
typedef struct Tunnel_Information_ExtIEs {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct Tunnel_Information_ExtIEs__extensionValue {
		Tunnel_Information_ExtIEs__extensionValue_PR present;
		union Tunnel_Information_ExtIEs__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Tunnel_Information_ExtIEs_t;
typedef struct UE_Capabilities_ExtIEs {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct UE_Capabilities_ExtIEs__extensionValue {
		UE_Capabilities_ExtIEs__extensionValue_PR present;
		union UE_Capabilities_ExtIEs__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UE_Capabilities_ExtIEs_t;
typedef struct UTRANCellID_ExtIEs {
	ProtocolIE_ID_t	 id;
	Criticality_t	 criticality;
	struct UTRANCellID_ExtIEs__extensionValue {
		UTRANCellID_ExtIEs__extensionValue_PR present;
		union UTRANCellID_ExtIEs__extensionValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} extensionValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UTRANCellID_ExtIEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_HNBRegisterRequestExtensions;
extern asn_SEQUENCE_specifics_t asn_SPC_HNBRegisterRequestExtensions_specs_1;
extern asn_TYPE_member_t asn_MBR_HNBRegisterRequestExtensions_1[3];
extern asn_TYPE_descriptor_t asn_DEF_HNBRegisterResponseExtensions;
extern asn_SEQUENCE_specifics_t asn_SPC_HNBRegisterResponseExtensions_specs_5;
extern asn_TYPE_member_t asn_MBR_HNBRegisterResponseExtensions_5[3];
extern asn_TYPE_descriptor_t asn_DEF_HNBRegisterRejectExtensions;
extern asn_SEQUENCE_specifics_t asn_SPC_HNBRegisterRejectExtensions_specs_9;
extern asn_TYPE_member_t asn_MBR_HNBRegisterRejectExtensions_9[3];
extern asn_TYPE_descriptor_t asn_DEF_HNBDe_RegisterExtensions;
extern asn_SEQUENCE_specifics_t asn_SPC_HNBDe_RegisterExtensions_specs_13;
extern asn_TYPE_member_t asn_MBR_HNBDe_RegisterExtensions_13[3];
extern asn_TYPE_descriptor_t asn_DEF_UERegisterRequestExtensions;
extern asn_SEQUENCE_specifics_t asn_SPC_UERegisterRequestExtensions_specs_17;
extern asn_TYPE_member_t asn_MBR_UERegisterRequestExtensions_17[3];
extern asn_TYPE_descriptor_t asn_DEF_UERegisterAcceptExtensions;
extern asn_SEQUENCE_specifics_t asn_SPC_UERegisterAcceptExtensions_specs_21;
extern asn_TYPE_member_t asn_MBR_UERegisterAcceptExtensions_21[3];
extern asn_TYPE_descriptor_t asn_DEF_UERegisterRejectExtensions;
extern asn_SEQUENCE_specifics_t asn_SPC_UERegisterRejectExtensions_specs_25;
extern asn_TYPE_member_t asn_MBR_UERegisterRejectExtensions_25[3];
extern asn_TYPE_descriptor_t asn_DEF_UEDe_RegisterExtensions;
extern asn_SEQUENCE_specifics_t asn_SPC_UEDe_RegisterExtensions_specs_29;
extern asn_TYPE_member_t asn_MBR_UEDe_RegisterExtensions_29[3];
extern asn_TYPE_descriptor_t asn_DEF_CSGMembershipUpdateExtensions;
extern asn_SEQUENCE_specifics_t asn_SPC_CSGMembershipUpdateExtensions_specs_33;
extern asn_TYPE_member_t asn_MBR_CSGMembershipUpdateExtensions_33[3];
extern asn_TYPE_descriptor_t asn_DEF_TNLUpdateExtensions;
extern asn_SEQUENCE_specifics_t asn_SPC_TNLUpdateExtensions_specs_37;
extern asn_TYPE_member_t asn_MBR_TNLUpdateExtensions_37[3];
extern asn_TYPE_descriptor_t asn_DEF_TNLUpdateResponseExtensions;
extern asn_SEQUENCE_specifics_t asn_SPC_TNLUpdateResponseExtensions_specs_41;
extern asn_TYPE_member_t asn_MBR_TNLUpdateResponseExtensions_41[3];
extern asn_TYPE_descriptor_t asn_DEF_TNLUpdateFailureExtensions;
extern asn_SEQUENCE_specifics_t asn_SPC_TNLUpdateFailureExtensions_specs_45;
extern asn_TYPE_member_t asn_MBR_TNLUpdateFailureExtensions_45[3];
extern asn_TYPE_descriptor_t asn_DEF_HNBConfigTransferRequestExtensions;
extern asn_SEQUENCE_specifics_t asn_SPC_HNBConfigTransferRequestExtensions_specs_49;
extern asn_TYPE_member_t asn_MBR_HNBConfigTransferRequestExtensions_49[3];
extern asn_TYPE_descriptor_t asn_DEF_HNBConfigTransferResponseExtensions;
extern asn_SEQUENCE_specifics_t asn_SPC_HNBConfigTransferResponseExtensions_specs_53;
extern asn_TYPE_member_t asn_MBR_HNBConfigTransferResponseExtensions_53[3];
extern asn_TYPE_descriptor_t asn_DEF_RelocationCompleteExtensions;
extern asn_SEQUENCE_specifics_t asn_SPC_RelocationCompleteExtensions_specs_57;
extern asn_TYPE_member_t asn_MBR_RelocationCompleteExtensions_57[3];
extern asn_TYPE_descriptor_t asn_DEF_ErrorIndicationExtensions;
extern asn_SEQUENCE_specifics_t asn_SPC_ErrorIndicationExtensions_specs_61;
extern asn_TYPE_member_t asn_MBR_ErrorIndicationExtensions_61[3];
extern asn_TYPE_descriptor_t asn_DEF_U_RNTIQueryRequestExtensions;
extern asn_SEQUENCE_specifics_t asn_SPC_U_RNTIQueryRequestExtensions_specs_65;
extern asn_TYPE_member_t asn_MBR_U_RNTIQueryRequestExtensions_65[3];
extern asn_TYPE_descriptor_t asn_DEF_U_RNTIQueryResponseExtensions;
extern asn_SEQUENCE_specifics_t asn_SPC_U_RNTIQueryResponseExtensions_specs_69;
extern asn_TYPE_member_t asn_MBR_U_RNTIQueryResponseExtensions_69[3];
extern asn_TYPE_descriptor_t asn_DEF_CriticalityDiagnostics_ExtIEs;
extern asn_SEQUENCE_specifics_t asn_SPC_CriticalityDiagnostics_ExtIEs_specs_73;
extern asn_TYPE_member_t asn_MBR_CriticalityDiagnostics_ExtIEs_73[3];
extern asn_TYPE_descriptor_t asn_DEF_CriticalityDiagnostics_IE_List_ExtIEs;
extern asn_SEQUENCE_specifics_t asn_SPC_CriticalityDiagnostics_IE_List_ExtIEs_specs_77;
extern asn_TYPE_member_t asn_MBR_CriticalityDiagnostics_IE_List_ExtIEs_77[3];
extern asn_TYPE_descriptor_t asn_DEF_CGI_ExtIEs;
extern asn_SEQUENCE_specifics_t asn_SPC_CGI_ExtIEs_specs_81;
extern asn_TYPE_member_t asn_MBR_CGI_ExtIEs_81[3];
extern asn_TYPE_descriptor_t asn_DEF_GeographicLocation_ExtIEs;
extern asn_SEQUENCE_specifics_t asn_SPC_GeographicLocation_ExtIEs_specs_85;
extern asn_TYPE_member_t asn_MBR_GeographicLocation_ExtIEs_85[3];
extern asn_TYPE_descriptor_t asn_DEF_GeographicalCoordinates_ExtIEs;
extern asn_SEQUENCE_specifics_t asn_SPC_GeographicalCoordinates_ExtIEs_specs_89;
extern asn_TYPE_member_t asn_MBR_GeographicalCoordinates_ExtIEs_89[3];
extern asn_TYPE_descriptor_t asn_DEF_HNB_Cell_Identifier_ExtIEs;
extern asn_SEQUENCE_specifics_t asn_SPC_HNB_Cell_Identifier_ExtIEs_specs_93;
extern asn_TYPE_member_t asn_MBR_HNB_Cell_Identifier_ExtIEs_93[3];
extern asn_TYPE_descriptor_t asn_DEF_HNBConfigInfo_ExtIEs;
extern asn_SEQUENCE_specifics_t asn_SPC_HNBConfigInfo_ExtIEs_specs_97;
extern asn_TYPE_member_t asn_MBR_HNBConfigInfo_ExtIEs_97[3];
extern asn_TYPE_descriptor_t asn_DEF_HNBConfigurationInformationProvided_ExtIEs;
extern asn_SEQUENCE_specifics_t asn_SPC_HNBConfigurationInformationProvided_ExtIEs_specs_101;
extern asn_TYPE_member_t asn_MBR_HNBConfigurationInformationProvided_ExtIEs_101[3];
extern asn_TYPE_descriptor_t asn_DEF_HNBConfigurationInformationMissing_ExtIEs;
extern asn_SEQUENCE_specifics_t asn_SPC_HNBConfigurationInformationMissing_ExtIEs_specs_105;
extern asn_TYPE_member_t asn_MBR_HNBConfigurationInformationMissing_ExtIEs_105[3];
extern asn_TYPE_descriptor_t asn_DEF_HNB_Location_Information_ExtIEs;
extern asn_SEQUENCE_specifics_t asn_SPC_HNB_Location_Information_ExtIEs_specs_109;
extern asn_TYPE_member_t asn_MBR_HNB_Location_Information_ExtIEs_109[3];
extern asn_TYPE_descriptor_t asn_DEF_HNB_Identity_ExtIEs;
extern asn_SEQUENCE_specifics_t asn_SPC_HNB_Identity_ExtIEs_specs_113;
extern asn_TYPE_member_t asn_MBR_HNB_Identity_ExtIEs_113[3];
extern asn_TYPE_descriptor_t asn_DEF_IP_Address_ExtIEs;
extern asn_SEQUENCE_specifics_t asn_SPC_IP_Address_ExtIEs_specs_117;
extern asn_TYPE_member_t asn_MBR_IP_Address_ExtIEs_117[3];
extern asn_TYPE_descriptor_t asn_DEF_MacroCoverageInformation_ExtIEs;
extern asn_SEQUENCE_specifics_t asn_SPC_MacroCoverageInformation_ExtIEs_specs_121;
extern asn_TYPE_member_t asn_MBR_MacroCoverageInformation_ExtIEs_121[3];
extern asn_TYPE_descriptor_t asn_DEF_NeighbourInfoRequestItem_ExtIEs;
extern asn_SEQUENCE_specifics_t asn_SPC_NeighbourInfoRequestItem_ExtIEs_specs_125;
extern asn_TYPE_member_t asn_MBR_NeighbourInfoRequestItem_ExtIEs_125[3];
extern asn_TYPE_descriptor_t asn_DEF_RABListItem_ExtIEs;
extern asn_SEQUENCE_specifics_t asn_SPC_RABListItem_ExtIEs_specs_129;
extern asn_TYPE_member_t asn_MBR_RABListItem_ExtIEs_129[3];
extern asn_TYPE_descriptor_t asn_DEF_TransportInfo_ExtIEs;
extern asn_SEQUENCE_specifics_t asn_SPC_TransportInfo_ExtIEs_specs_133;
extern asn_TYPE_member_t asn_MBR_TransportInfo_ExtIEs_133[3];
extern asn_TYPE_descriptor_t asn_DEF_Tunnel_Information_ExtIEs;
extern asn_SEQUENCE_specifics_t asn_SPC_Tunnel_Information_ExtIEs_specs_137;
extern asn_TYPE_member_t asn_MBR_Tunnel_Information_ExtIEs_137[3];
extern asn_TYPE_descriptor_t asn_DEF_UE_Capabilities_ExtIEs;
extern asn_SEQUENCE_specifics_t asn_SPC_UE_Capabilities_ExtIEs_specs_141;
extern asn_TYPE_member_t asn_MBR_UE_Capabilities_ExtIEs_141[3];
extern asn_TYPE_descriptor_t asn_DEF_UTRANCellID_ExtIEs;
extern asn_SEQUENCE_specifics_t asn_SPC_UTRANCellID_ExtIEs_specs_145;
extern asn_TYPE_member_t asn_MBR_UTRANCellID_ExtIEs_145[3];

#ifdef __cplusplus
}
#endif

#endif	/* _ProtocolExtensionField_H_ */
#include <asn_internal.h>
