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
    bool encrypted;
} mc_protocol_context;

extern char *STATE_NAME[];

int read_var_int(const guint8 *data, guint max_length, guint *result);



#endif //MC_DISSECTOR_PROTOCOL_DATA_H
