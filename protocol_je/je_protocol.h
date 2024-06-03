//
// Created by Nickid2018 on 2023/7/12.
//

#ifndef MC_DISSECTOR_JE_PROTOCOL_H
#define MC_DISSECTOR_JE_PROTOCOL_H

#include <epan/proto.h>
#include "protocol_data.h"

#define PACKET_ID_HANDSHAKE 0x00
#define PACKET_ID_LEGACY_SERVER_LIST_PING 0xFE
#define PACKET_ID_SERVER_PING_START 0x00
#define PACKET_ID_SERVER_PING 0x01
#define PACKET_ID_CLIENT_SERVER_INFO 0x00
#define PACKET_ID_CLIENT_PING 0x01
#define PACKET_ID_CLIENT_SUCCESS 0x02
#define PACKET_ID_CLIENT_COMPRESS 0x03
#define PACKET_ID_SERVER_ENCRYPTION_BEGIN 0x01

int handle_server_handshake_switch(tvbuff_t *tvb, mcje_protocol_context *ctx);

void handle_server_handshake(proto_tree *packet_tree, packet_info *pinfo, tvbuff_t *tvb);

void handle_server_slp(proto_tree *packet_tree, tvbuff_t *tvb);

void handle_client_slp(proto_tree *packet_tree, packet_info *pinfo, tvbuff_t *tvb);

int handle_client_login_switch(tvbuff_t *tvb, mcje_protocol_context *ctx);

int handle_server_login_switch(tvbuff_t *tvb, mcje_protocol_context *ctx);

void handle_login(proto_tree *packet_tree, packet_info *pinfo, tvbuff_t *tvb, mcje_protocol_context *ctx, bool is_client);

int handle_client_play_switch(tvbuff_t *tvb, mcje_protocol_context *ctx);

int handle_server_play_switch(tvbuff_t *tvb, mcje_protocol_context *ctx);

void handle_play(proto_tree *packet_tree, packet_info *pinfo, tvbuff_t *tvb, mcje_protocol_context *ctx, bool is_client);

int handle_client_configuration_switch(tvbuff_t *tvb, mcje_protocol_context *ctx);

int handle_server_configuration_switch(tvbuff_t *tvb, mcje_protocol_context *ctx);

void handle_configuration(proto_tree *packet_tree, packet_info *pinfo, tvbuff_t *tvb, mcje_protocol_context *ctx, bool is_client);

#endif //MC_DISSECTOR_JE_PROTOCOL_H
