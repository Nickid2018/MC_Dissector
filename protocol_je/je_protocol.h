//
// Created by Nickid2018 on 2023/7/12.
//

#ifndef MC_DISSECTOR_JE_PROTOCOL_H
#define MC_DISSECTOR_JE_PROTOCOL_H

#include <epan/proto.h>
#include "protocol/protocol_data.h"

int try_switch_initial(tvbuff_t *tvb, packet_info *pinfo, mc_protocol_context *ctx, bool is_client);

int try_switch_state(tvbuff_t *tvb, mc_protocol_context *ctx, mc_frame_data *frame_data, bool is_client);

void handle_initial(
        proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, mc_protocol_context *ctx, je_state state, bool is_client
);

void handle_protocol(
        proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, mc_protocol_context *ctx, je_state state, bool is_client
);

#endif //MC_DISSECTOR_JE_PROTOCOL_H
