//
// Created by Nickid2018 on 2023/7/12.
//

#ifndef MC_DISSECTOR_PROTOCOL_DATA_H
#define MC_DISSECTOR_PROTOCOL_DATA_H

#include <epan/proto.h>
#include "protocols/protocols.h"

#define INVALID_DATA (-1)
#define is_invalid(x) ((x) == INVALID_DATA)

typedef enum {
    HANDSHAKE, PLAY, PING, LOGIN, CONFIGURATION, INVALID
} je_state;

typedef struct {
    je_state client_state;
    je_state server_state;
    guint32 server_port;
    guint32 protocol_version;
    guint32 data_version;
    protocol_je_set protocol_set;
    gint32 compression_threshold;
    bool encrypted;
} mcje_protocol_context;

extern char *STATE_NAME[];

gint read_var_int(const guint8 *data, guint max_length, guint *result);

gint read_var_long(const guint8 *data, guint max_length, guint64 *result);

gint read_ushort(const guint8 *data, guint16 *result);

gint read_ulong(const guint8 *data, guint64 *result);

gint read_buffer(const guint8 *data, guint8 **result);

#endif //MC_DISSECTOR_PROTOCOL_DATA_H
