//
// Created by Nickid2018 on 2023/7/12.
//

#ifndef MC_DISSECTOR_PROTOCOL_DATA_H
#define MC_DISSECTOR_PROTOCOL_DATA_H

#include <epan/proto.h>
#include <gcrypt.h>
#include "storage/storage.h"

#define INVALID_DATA (-1)
#define is_invalid(x) ((x) == INVALID_DATA)

typedef enum {
    HANDSHAKE, PLAY, PING, LOGIN, TRANSFER, CONFIGURATION, // Normal states
    INVALID, NOT_COMPATIBLE, PROTOCOL_NOT_FOUND // Special states
} je_state;

typedef struct {
    je_state client_state;
    je_state server_state;

    guint32 server_port;
    address server_address;

    guint32 protocol_version;
    guint32 data_version;
    protocol_je_set protocol_set;

    gint32 compression_threshold;
    bool encrypted;

    gcry_cipher_hd_t server_cipher;
    gcry_cipher_hd_t client_cipher;
    gint server_last_segment_remaining;
    gint client_last_segment_remaining;
    guint8 *server_last_remains;
    guint8 *client_last_remains;

    void *extra;
} mcje_protocol_context;

typedef struct {
    je_state client_state;
    je_state server_state;

    bool encrypted;
    guint8 *decrypted_data_head;
    guint8 *decrypted_data_tail;
    gint32 compression_threshold;
} mcje_frame_data;

extern char *STATE_NAME[];

gint read_var_int(tvbuff_t *tvb, gint offset, gint *result);

gint read_var_int_with_limit(tvbuff_t *tvb, gint offset, gint max_length, gint *result);

gint read_var_long(tvbuff_t *tvb, gint offset, gint64 *result);

gint read_buffer(tvbuff_t *tvb, gint offset, guint8 **resul, wmem_allocator_t *allocator);

#endif //MC_DISSECTOR_PROTOCOL_DATA_H
