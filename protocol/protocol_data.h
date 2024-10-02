//
// Created by Nickid2018 on 2023/7/12.
//

#ifndef MC_DISSECTOR_PROTOCOL_DATA_H
#define MC_DISSECTOR_PROTOCOL_DATA_H

#include <epan/proto.h>
#include <gcrypt.h>
#include "storage/storage.h"
#include "protocol/schema/schema.h"

#define INVALID_DATA (-1)
#define is_invalid(x) ((x) == INVALID_DATA)

typedef enum {
    HANDSHAKE, PLAY, STATUS, LOGIN, TRANSFER, CONFIGURATION, // Normal states
    INVALID, NOT_COMPATIBLE, PROTOCOL_NOT_FOUND // Special states
} je_state;

typedef struct {
    je_state client_state;
    je_state server_state;

    uint32_t server_port;
    address server_address;

    uint32_t protocol_version;
    uint32_t data_version;
    protocol_dissector_set *dissector_set;

    int32_t compression_threshold;
    bool encrypted;

    gcry_cipher_hd_t server_cipher;
    gcry_cipher_hd_t client_cipher;
    int32_t server_last_segment_remaining;
    int32_t client_last_segment_remaining;
    uint8_t *server_last_remains;
    uint8_t *client_last_remains;

    wmem_map_t *global_data;
} mc_protocol_context;

typedef struct {
    je_state client_state;
    je_state server_state;

    bool encrypted;
    uint8_t *decrypted_data_head;
    uint8_t *decrypted_data_tail;
    int32_t compression_threshold;
} mc_frame_data;

extern char *STATE_NAME[];

wmem_map_t *get_global_data(packet_info *pinfo);

uint32_t je_state_to_protocol_set_state(je_state state, bool is_client);

int32_t read_var_int(tvbuff_t *tvb, int32_t offset, int32_t *result);

int32_t read_var_int_with_limit(tvbuff_t *tvb, int32_t offset, int32_t max_length, int32_t *result);

int32_t read_var_long(tvbuff_t *tvb, int32_t offset, int64_t *result);

int32_t read_buffer(tvbuff_t *tvb, int32_t offset, uint8_t **resul, wmem_allocator_t *allocator);

#endif //MC_DISSECTOR_PROTOCOL_DATA_H
