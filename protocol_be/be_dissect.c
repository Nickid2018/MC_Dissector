//
// Created by Nickid2018 on 2023/7/13.
//

#include "be_dissect.h"
#include "protocol/protocol_data.h"
#include "../mc_dissector.h"

dissector_handle_t mcbe_boot_handle, mcbe_handle, ignore_be_handle;

int ett_sub_be = -1;

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