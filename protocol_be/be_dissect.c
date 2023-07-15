//
// Created by Nickid2018 on 2023/7/13.
//

#include "be_dissect.h"
#include "../protocol_data.h"
#include "../mc_dissector.h"

dissector_handle_t mcbe_boot_handle, mcbe_handle, ignore_be_handle;

int hf_unknown_int_be = -1;
int hf_unknown_uint_be = -1;
int hf_unknown_int64_be = -1;
int hf_unknown_uint64_be = -1;
int hf_unknown_float_be = -1;
int hf_unknown_double_be = -1;
int hf_unknown_bytes_be = -1;
int hf_unknown_string_be = -1;
int hf_unknown_boolean_be = -1;
int hf_unknown_uuid_be = -1;

int ett_sub_be = -1;
wmem_map_t *name_hf_map_be = NULL;
wmem_map_t *unknown_hf_map_be = NULL;
wmem_map_t *bitmask_hf_map_be = NULL;

void proto_register_mcbe() {
    proto_mcbe = proto_register_protocol(MCBE_NAME, MCBE_SHORT_NAME, MCBE_FILTER);
}

void proto_reg_handoff_mcbe() {
    mcbe_boot_handle = create_dissector_handle(dissect_be_boot, proto_mcbe);
    mcbe_handle = create_dissector_handle(dissect_be_conv, proto_mcbe);
    ignore_be_handle = create_dissector_handle(dissect_be_ignore, proto_mcbe);
    dissector_add_uint("udp.port", MCBE_PORT, mcbe_boot_handle);
}

int dissect_be_boot(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
    return tvb_captured_length(tvb);
}

int dissect_be_conv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
    return tvb_captured_length(tvb);
}

int dissect_be_ignore(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
    return tvb_captured_length(tvb);
}