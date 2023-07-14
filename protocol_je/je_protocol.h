//
// Created by Nickid2018 on 2023/7/12.
//

#ifndef MC_DISSECTOR_JE_PROTOCOL_H
#define MC_DISSECTOR_JE_PROTOCOL_H

#include <epan/proto.h>
#include "../protocol_data.h"

#define PACKET_ID_HANDSHAKE 0x00
#define PACKET_ID_SERVER_PING_START 0x00
#define PACKET_ID_SERVER_PING 0x01
#define PACKET_ID_CLIENT_SERVER_INFO 0x00
#define PACKET_ID_CLIENT_PING 0x01

int handle_server_handshake_switch(const guint8 *data, guint length, mcje_protocol_context *ctx);

void handle_server_handshake(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const guint8 *data,
                             guint length, mcje_protocol_context *ctx);

void handle_server_slp(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const guint8 *data,
                       guint length, mcje_protocol_context *ctx);

void handle_client_slp(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const guint8 *data,
                       guint length, mcje_protocol_context *ctx);

int handle_client_login_switch(const guint8 *data, guint length, mcje_protocol_context *ctx);

void handle_client_login(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const guint8 *data,
                         guint length, mcje_protocol_context *ctx);

void handle_server_login(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const guint8 *data,
                         guint length, mcje_protocol_context *ctx);

#endif //MC_DISSECTOR_JE_PROTOCOL_H
