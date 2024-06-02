//
// Created by Nickid2018 on 2023/7/12.
//

#ifndef MC_DISSECTOR_PROTOCOL_DATA_H
#define MC_DISSECTOR_PROTOCOL_DATA_H

#include <epan/proto.h>
#include <gcrypt.h>
#include "protocols/protocols.h"

#define INVALID_DATA (-1)
#define is_invalid(x) ((x) == INVALID_DATA)

typedef enum {
    HANDSHAKE, PLAY, PING, LOGIN, TRANSFER, CONFIGURATION, INVALID
} je_state;

typedef struct {
    guint8 *server_decrypt;
    guint8 *client_decrypt;
    gint server_decrypt_length;
    gint client_decrypt_length;

    gcry_cipher_hd_t server_cipher;
    gcry_cipher_hd_t client_cipher;

    gint server_last_decrypt_available;
    gint client_last_decrypt_available;
    gint server_required_length;
    gint client_required_length;
} mcje_decryption_context;

typedef struct {
    je_state client_state;
    je_state server_state;
    guint32 server_port;
    address server_address;
    guint32 protocol_version;
    guint32 data_version;
    protocol_je_set protocol_set;
    gint32 compression_threshold;
    void *extra;
    mcje_decryption_context *decryption_context;
} mcje_protocol_context;

typedef struct {
    gint record_total;
    gint record_latest;
} reassemble_offset;

extern char *STATE_NAME[];

gint read_var_int(tvbuff_t *tvb, gint offset, gint *result);

gint read_var_int_with_limit(tvbuff_t *tvb, gint offset, gint max_length, gint *result);

gint read_var_long(tvbuff_t *tvb, gint offset, gint64 *result);

gint read_buffer(tvbuff_t *tvb, gint offset, guint8 **resul, wmem_allocator_t *allocator);

#endif //MC_DISSECTOR_PROTOCOL_DATA_H
