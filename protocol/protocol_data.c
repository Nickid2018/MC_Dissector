//
// Created by Nickid2018 on 2023/7/12.
//

#include <epan/conversation.h>
#include "protocol_data.h"

char *STATE_NAME[] = {"Handshake", "Play", "Status", "Login", "Transfer", "Configuration", "Invalid"};

int32_t read_var_int(tvbuff_t *tvb, int32_t offset, int32_t *result) {
    uint8_t read;
    int32_t p = 0;
    *result = 0;
    do {
        if (p == 5)
            return INVALID_DATA;
        read = tvb_get_uint8(tvb, offset + p);
        *result |= (read & 0x7F) << (7 * p++);
    } while ((read & 0x80) != 0);
    return p;
}

int32_t read_var_int_with_limit(tvbuff_t *tvb, int32_t offset, int32_t max_length, int32_t *result) {
    uint8_t read;
    int32_t p = 0;
    *result = 0;
    do {
        if (p == 5 || p >= max_length)
            return INVALID_DATA;
        read = tvb_get_uint8(tvb, offset + p);
        *result |= (read & 0x7F) << (7 * p++);
    } while ((read & 0x80) != 0);
    return p;
}

int32_t read_var_long(tvbuff_t *tvb, int32_t offset, int64_t *result) {
    int32_t p = 0;
    *result = 0;
    uint8_t read;
    do {
        if (p == 10)
            return INVALID_DATA;
        read = tvb_get_uint8(tvb, offset + p);
        *result |= (read & 0x7F) << (7 * p++);
    } while ((read & 0x80) != 0);
    return p;
}

int32_t read_buffer(tvbuff_t *tvb, int32_t offset, uint8_t **result, wmem_allocator_t *allocator) {
    int32_t length;
    int32_t read = read_var_int(tvb, offset, &length);
    if (is_invalid(read))
        return INVALID_DATA;
    *result = tvb_memdup(allocator, tvb, offset + read, length);
    return read + length;
}

wmem_map_t *get_global_data(packet_info *pinfo) {
    conversation_t *conv = find_or_create_conversation(pinfo);
    mc_protocol_context *ctx = conversation_get_proto_data(conv, proto_mcje);
    return ctx->global_data;
}

uint32_t je_state_to_protocol_set_state(je_state state, bool is_client) {
    if (state == TRANSFER)
        state = LOGIN;
    return is_client ? state : 16 + state;
}