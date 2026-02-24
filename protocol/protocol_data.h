//
// Created by Nickid2018 on 2023/7/12.
//

#ifndef MC_DISSECTOR_PROTOCOL_DATA_H
#define MC_DISSECTOR_PROTOCOL_DATA_H

#include <epan/proto.h>
#include <gcrypt.h>
#include "protocol/schema/schema.h"

#define INVALID_DATA (-1)
#define is_invalid(x) ((x) == INVALID_DATA)

typedef struct {
    uint32_t client_state;
    uint32_t server_state;

    uint32_t server_port;
    address server_address;

    void *protocol_data;
    wmem_map_t *global_data;

    protocol_dissector_set *dissector_set;
    uint32_t protocol_version;

    bool encrypted;
    uint8_t *secret_key;
    gcry_cipher_hd_t server_cipher;
    gcry_cipher_hd_t client_cipher;
} mc_protocol_context;

typedef struct {
    uint32_t client_state;
    uint32_t server_state;

    bool encrypted;
    void *protocol_data;
} mc_frame_data;

wmem_map_t *get_global_data(packet_info *pinfo);

int32_t read_var_int(tvbuff_t *tvb, int32_t offset, int32_t *result);

int32_t read_var_int_with_limit(tvbuff_t *tvb, int32_t offset, int32_t max_length, int32_t *result);

int32_t read_var_long(tvbuff_t *tvb, int32_t offset, int64_t *result);

int32_t read_buffer(tvbuff_t *tvb, int32_t offset, uint8_t **resul, wmem_allocator_t *allocator);

int32_t read_string(tvbuff_t *tvb, int32_t offset, char **result, wmem_allocator_t *allocator);

uint8_t *read_legacy_string(tvbuff_t *tvb, int32_t offset, int32_t *len);

int32_t read_zigzag_int(tvbuff_t *tvb, int32_t offset);

#endif //MC_DISSECTOR_PROTOCOL_DATA_H
