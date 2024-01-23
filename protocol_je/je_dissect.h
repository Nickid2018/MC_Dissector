//
// Created by Nickid2018 on 2023/7/13.
//

#ifndef MC_DISSECTOR_JE_DISSECT_H
#define MC_DISSECTOR_JE_DISSECT_H

#include <epan/packet.h>
#include "protocol_data.h"

extern dissector_handle_t mcje_handle;
extern gchar *pref_ignore_packets_je;
extern gchar *pref_secret_key;
extern gboolean pref_do_nbt_decode;

extern int hf_invalid_data_je;
extern int hf_ignored_packet_je;
extern int hf_packet_length_je;
extern int hf_packet_data_length_je;
extern int hf_packet_id_je;
extern int hf_packet_name_je;
extern int hf_protocol_version_je;
extern int hf_server_address_je;
extern int hf_next_state_je;
extern int hf_ping_time_je;
extern int hf_server_status_je;
extern int hf_legacy_slp_payload;

extern int hf_unknown_int_je;
extern int hf_unknown_uint_je;
extern int hf_unknown_int64_je;
extern int hf_unknown_uint64_je;
extern int hf_unknown_float_je;
extern int hf_unknown_double_je;
extern int hf_unknown_bytes_je;
extern int hf_unknown_string_je;
extern int hf_unknown_boolean_je;
extern int hf_unknown_uuid_je;
extern int hf_array_length_je;

extern int ett_mcje;
extern int ett_je_proto;
extern int ett_sub_je;
extern wmem_map_t *name_hf_map_je;
extern wmem_map_t *complex_name_map_je;
extern wmem_map_t *complex_hf_map_je;
extern wmem_map_t *unknown_hf_map_je;
extern wmem_map_t *bitmask_hf_map_je;
extern wmem_map_t *component_map_je;

void proto_register_mcje();

void proto_reg_handoff_mcje();

void sub_dissect_je(guint length, tvbuff_t *tvb, packet_info *pinfo,
                    proto_tree *tree, mcje_protocol_context *ctx,
                    bool is_client, bool visited);

int dissect_je_core(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

int dissect_je_conv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_);

#endif //MC_DISSECTOR_JE_DISSECT_H
