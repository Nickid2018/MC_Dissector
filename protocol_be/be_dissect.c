//
// Created by Nickid2018 on 2023/7/13.
//

#include <epan/dissectors/packet-raknet.h>

#include "be_dissect.h"
#include "../mc_dissector.h"

dissector_handle_t mcbe_handle;

void proto_reg_handoff_mcbe() {
    mcbe_handle = create_dissector_handle(dissect_be_conv, proto_mcbe);
    raknet_add_udp_dissector(MCBE_PORT, mcbe_handle);
}

int dissect_be_conv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
    return tvb_captured_length(tvb);
}
