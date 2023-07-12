//
// Created by Nickid2018 on 2023/7/12.
//

#ifndef MC_DISSECTOR_PROTOCOL_DATA_H
#define MC_DISSECTOR_PROTOCOL_DATA_H

#include <epan/proto.h>

#define INVALID_DATA (-1)
#define is_invalid(x) ((x) == INVALID_DATA)

typedef struct {
    enum {
        PING, HANDSHAKE, LOGIN, PLAY, INVALID
    } state;
    guint32 server_port;
    guint32 protocol_version;
    guint32 compression_threshold;
} mc_protocol_context;

guint read_var_int(const guint8 *data, guint max_length, guint *result);

int read_var_long(const guint8 *data, guint max_length, guint64 *result);

#endif //MC_DISSECTOR_PROTOCOL_DATA_H
