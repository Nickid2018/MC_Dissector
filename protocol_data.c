//
// Created by Nickid2018 on 2023/7/12.
//

#include "protocol_data.h"

char *STATE_NAME[] = {"PING", "HANDSHAKE", "LOGIN", "PLAY", "INVALID"};

int read_var_int(const guint8 *data, guint max_length, guint *result) {
    guint p = 0;
    *result = 0;
    guint8 read;
    do {
        if (p == 5 || p >= max_length)
            return INVALID_DATA;
        read = data[p];
        *result |= (read & 0x7F) << (7 * p++);
    } while ((read & 0x80) != 0);
    return p;
}