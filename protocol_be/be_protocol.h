//
// Created by nickid2018 on 2026/2/20.
//

#ifndef MC_DISSECTOR_BE_PROTOCOL_H
#define MC_DISSECTOR_BE_PROTOCOL_H

#include <epan/packet_info.h>
#include <epan/tvbuff.h>
#include "protocol/protocol_data.h"

extern char *BE_STATE_NAME[];

typedef enum {
    INITIAL, GAME, // Normal states
    INVALID, NOT_COMPATIBLE, PROTOCOL_NOT_FOUND, SECRET_KEY_NOT_FOUND // Special states
} be_state;

typedef enum {
    ZLIB, SNAPPY, NONE
} compression_algorithm;

typedef struct {
    int32_t compression_threshold;
    compression_algorithm compression_algorithm;
    int64_t client_counter;
    int64_t server_counter;
} mcbe_context;

typedef struct {
    uint8_t *decrypted_data;
    int32_t compression_threshold;
    compression_algorithm compression_algorithm;
    char *expect_checksum;
} mcbe_frame_data;

int32_t read_packet_len(tvbuff_t *tvb, int32_t offset);

int try_change_state(
    tvbuff_t *tvb, int32_t offset, packet_info *pinfo,
    mc_protocol_context *ctx, mc_frame_data *frame_data, bool is_client
);

void handle_packet(
    proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int32_t offset,
    mc_protocol_context *ctx, be_state state, bool is_client
);

#endif //MC_DISSECTOR_BE_PROTOCOL_H
