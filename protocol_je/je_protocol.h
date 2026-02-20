//
// Created by Nickid2018 on 2023/7/12.
//

#ifndef MC_DISSECTOR_JE_PROTOCOL_H
#define MC_DISSECTOR_JE_PROTOCOL_H

#include <epan/proto.h>

extern char *JE_STATE_NAME[];

typedef enum {
    HANDSHAKE, PLAY, STATUS, LOGIN, TRANSFER, CONFIGURATION, // Normal states
    LEGACY_QUERY, // Old version compatibility for <1.6
    INVALID, NOT_COMPATIBLE, PROTOCOL_NOT_FOUND, SECRET_KEY_NOT_FOUND // Special states
} je_state;

enum je_protocol_state {
    HANDSHAKE_SERVER = 0,
    PLAY_SERVER = 1,
    STATUS_SERVER = 2,
    LOGIN_SERVER = 3,
    CONFIGURATION_SERVER = 4,
    PLAY_CLIENT = PLAY_SERVER + 8,
    STATUS_CLIENT = STATUS_SERVER + 8,
    LOGIN_CLIENT = LOGIN_SERVER + 8,
    CONFIGURATION_CLIENT = CONFIGURATION_SERVER + 8,
};

int try_switch_initial(tvbuff_t *tvb, packet_info *pinfo, mc_protocol_context *ctx, bool is_client);

int try_switch_state(
    tvbuff_t *tvb, packet_info *pinfo, mc_protocol_context *ctx, mc_frame_data *frame_data, bool is_client
);

void handle_initial(
    proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, mc_protocol_context *ctx, je_state state, bool is_client
);

void handle_protocol(
    proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, mc_protocol_context *ctx, je_state state, bool is_client
);

void handle_legacy_query(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, mc_protocol_context *ctx);

#endif //MC_DISSECTOR_JE_PROTOCOL_H
