//
// Created by Nickid2018 on 2023/7/12.
//

#ifndef MC_DISSECTOR_JE_PROTOCOL_H
#define MC_DISSECTOR_JE_PROTOCOL_H

#include <epan/proto.h>
#include "protocol/protocol_data.h"

#define PACKET_ID_HANDSHAKE 0x00
#define PACKET_ID_LEGACY_SERVER_LIST_PING 0xFE
#define PACKET_ID_SERVER_PING_START 0x00
#define PACKET_ID_SERVER_PING 0x01
#define PACKET_ID_CLIENT_SERVER_INFO 0x00
#define PACKET_ID_CLIENT_PING 0x01

int handle_server_handshake_switch(tvbuff_t *tvb, mc_protocol_context *ctx);

void handle_server_handshake(proto_tree *packet_tree, packet_info *pinfo, tvbuff_t *tvb);

void handle_server_slp(proto_tree *packet_tree, tvbuff_t *tvb);

void handle_client_slp(proto_tree *packet_tree, packet_info *pinfo, tvbuff_t *tvb);

int try_switch_state(tvbuff_t *tvb, mc_protocol_context *ctx, bool is_client);

void handle_protocol(
        proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, mc_protocol_context *ctx, je_state state, bool is_client
);

#endif //MC_DISSECTOR_JE_PROTOCOL_H
