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

typedef enum {
    NONE, SNAPPY, ZLIB
} compression_algorithm;

typedef struct {
    uint32_t client_state;
    uint32_t server_state;

    uint32_t server_port;
    address server_address;

    uint32_t protocol_version;
    uint32_t data_version;
    protocol_dissector_set *dissector_set;

    int32_t compression_threshold;
    compression_algorithm compression_algorithm;

    bool encrypted;
    uint8_t *secret_key;
    gcry_cipher_hd_t server_cipher;
    gcry_cipher_hd_t client_cipher;
    int32_t server_last_segment_remaining;
    int32_t client_last_segment_remaining;
    uint8_t *server_last_remains;
    uint8_t *client_last_remains;

    wmem_map_t *global_data;
} mc_protocol_context;

typedef struct {
    uint32_t client_state;
    uint32_t server_state;

    uint8_t *decrypted_data_head;
    uint8_t *decrypted_data_tail;

    int32_t compression_threshold;
    compression_algorithm compression_algorithm;

    bool encrypted;
    bool first_compression_packet;
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
