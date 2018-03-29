/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RANAP-IEs"
 * 	found in "../../asn1/ranap/ranap-14.1.0.asn1"
 * 	`asn1c -fcompound-names -fno-include-deps -gen-PER -no-gen-example`
 */

#ifndef	_RANAP_CauseRadioNetwork_H_
#define	_RANAP_CauseRadioNetwork_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RANAP_CauseRadioNetwork {
	RANAP_CauseRadioNetwork_rab_pre_empted	= 1,
	RANAP_CauseRadioNetwork_trelocoverall_expiry	= 2,
	RANAP_CauseRadioNetwork_trelocprep_expiry	= 3,
	RANAP_CauseRadioNetwork_treloccomplete_expiry	= 4,
	RANAP_CauseRadioNetwork_tqueing_expiry	= 5,
	RANAP_CauseRadioNetwork_relocation_triggered	= 6,
	RANAP_CauseRadioNetwork_trellocalloc_expiry	= 7,
	RANAP_CauseRadioNetwork_unable_to_establish_during_relocation	= 8,
	RANAP_CauseRadioNetwork_unknown_target_rnc	= 9,
	RANAP_CauseRadioNetwork_relocation_cancelled	= 10,
	RANAP_CauseRadioNetwork_successful_relocation	= 11,
	RANAP_CauseRadioNetwork_requested_ciphering_and_or_integrity_protection_algorithms_not_supported	= 12,
	RANAP_CauseRadioNetwork_conflict_with_already_existing_integrity_protection_and_or_ciphering_information	= 13,
	RANAP_CauseRadioNetwork_failure_in_the_radio_interface_procedure	= 14,
	RANAP_CauseRadioNetwork_release_due_to_utran_generated_reason	= 15,
	RANAP_CauseRadioNetwork_user_inactivity	= 16,
	RANAP_CauseRadioNetwork_time_critical_relocation	= 17,
	RANAP_CauseRadioNetwork_requested_traffic_class_not_available	= 18,
	RANAP_CauseRadioNetwork_invalid_rab_parameters_value	= 19,
	RANAP_CauseRadioNetwork_requested_maximum_bit_rate_not_available	= 20,
	RANAP_CauseRadioNetwork_requested_guaranteed_bit_rate_not_available	= 21,
	RANAP_CauseRadioNetwork_requested_transfer_delay_not_achievable	= 22,
	RANAP_CauseRadioNetwork_invalid_rab_parameters_combination	= 23,
	RANAP_CauseRadioNetwork_condition_violation_for_sdu_parameters	= 24,
	RANAP_CauseRadioNetwork_condition_violation_for_traffic_handling_priority	= 25,
	RANAP_CauseRadioNetwork_condition_violation_for_guaranteed_bit_rate	= 26,
	RANAP_CauseRadioNetwork_user_plane_versions_not_supported	= 27,
	RANAP_CauseRadioNetwork_iu_up_failure	= 28,
	RANAP_CauseRadioNetwork_relocation_failure_in_target_CN_RNC_or_target_system	= 29,
	RANAP_CauseRadioNetwork_invalid_RAB_ID	= 30,
	RANAP_CauseRadioNetwork_no_remaining_rab	= 31,
	RANAP_CauseRadioNetwork_interaction_with_other_procedure	= 32,
	RANAP_CauseRadioNetwork_requested_maximum_bit_rate_for_dl_not_available	= 33,
	RANAP_CauseRadioNetwork_requested_maximum_bit_rate_for_ul_not_available	= 34,
	RANAP_CauseRadioNetwork_requested_guaranteed_bit_rate_for_dl_not_available	= 35,
	RANAP_CauseRadioNetwork_requested_guaranteed_bit_rate_for_ul_not_available	= 36,
	RANAP_CauseRadioNetwork_repeated_integrity_checking_failure	= 37,
	RANAP_CauseRadioNetwork_requested_request_type_not_supported	= 38,
	RANAP_CauseRadioNetwork_request_superseded	= 39,
	RANAP_CauseRadioNetwork_release_due_to_UE_generated_signalling_connection_release	= 40,
	RANAP_CauseRadioNetwork_resource_optimisation_relocation	= 41,
	RANAP_CauseRadioNetwork_requested_information_not_available	= 42,
	RANAP_CauseRadioNetwork_relocation_desirable_for_radio_reasons	= 43,
	RANAP_CauseRadioNetwork_relocation_not_supported_in_target_RNC_or_target_system	= 44,
	RANAP_CauseRadioNetwork_directed_retry	= 45,
	RANAP_CauseRadioNetwork_radio_connection_with_UE_Lost	= 46,
	RANAP_CauseRadioNetwork_rNC_unable_to_establish_all_RFCs	= 47,
	RANAP_CauseRadioNetwork_deciphering_keys_not_available	= 48,
	RANAP_CauseRadioNetwork_dedicated_assistance_data_not_available	= 49,
	RANAP_CauseRadioNetwork_relocation_target_not_allowed	= 50,
	RANAP_CauseRadioNetwork_location_reporting_congestion	= 51,
	RANAP_CauseRadioNetwork_reduce_load_in_serving_cell	= 52,
	RANAP_CauseRadioNetwork_no_radio_resources_available_in_target_cell	= 53,
	RANAP_CauseRadioNetwork_gERAN_Iumode_failure	= 54,
	RANAP_CauseRadioNetwork_access_restricted_due_to_shared_networks	= 55,
	RANAP_CauseRadioNetwork_incoming_relocation_not_supported_due_to_PUESBINE_feature	= 56,
	RANAP_CauseRadioNetwork_traffic_load_in_the_target_cell_higher_than_in_the_source_cell	= 57,
	RANAP_CauseRadioNetwork_mBMS_no_multicast_service_for_this_UE	= 58,
	RANAP_CauseRadioNetwork_mBMS_unknown_UE_ID	= 59,
	RANAP_CauseRadioNetwork_successful_MBMS_session_start_no_data_bearer_necessary	= 60,
	RANAP_CauseRadioNetwork_mBMS_superseded_due_to_NNSF	= 61,
	RANAP_CauseRadioNetwork_mBMS_UE_linking_already_done	= 62,
	RANAP_CauseRadioNetwork_mBMS_UE_de_linking_failure_no_existing_UE_linking	= 63,
	RANAP_CauseRadioNetwork_tMGI_unknown	= 64
} e_RANAP_CauseRadioNetwork;

/* RANAP_CauseRadioNetwork */
typedef long	 RANAP_CauseRadioNetwork_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_RANAP_CauseRadioNetwork_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_RANAP_CauseRadioNetwork;
asn_struct_free_f RANAP_CauseRadioNetwork_free;
asn_struct_print_f RANAP_CauseRadioNetwork_print;
asn_constr_check_f RANAP_CauseRadioNetwork_constraint;
ber_type_decoder_f RANAP_CauseRadioNetwork_decode_ber;
der_type_encoder_f RANAP_CauseRadioNetwork_encode_der;
xer_type_decoder_f RANAP_CauseRadioNetwork_decode_xer;
xer_type_encoder_f RANAP_CauseRadioNetwork_encode_xer;
oer_type_decoder_f RANAP_CauseRadioNetwork_decode_oer;
oer_type_encoder_f RANAP_CauseRadioNetwork_encode_oer;
per_type_decoder_f RANAP_CauseRadioNetwork_decode_uper;
per_type_encoder_f RANAP_CauseRadioNetwork_encode_uper;
per_type_decoder_f RANAP_CauseRadioNetwork_decode_aper;
per_type_encoder_f RANAP_CauseRadioNetwork_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _RANAP_CauseRadioNetwork_H_ */
#include <asn_internal.h>
