//
// Created by Nickid2018 on 2023/7/12.
//

#ifndef MC_DISSECTOR_JE_PROTOCOL_H
#define MC_DISSECTOR_JE_PROTOCOL_H

#include <epan/proto.h>
#include "protocol_data.h"

void handle_server_handshake(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const guint8 *data, guint length, mc_protocol_context *ctx);

#endif //MC_DISSECTOR_JE_PROTOCOL_H
