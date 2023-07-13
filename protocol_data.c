//
// Created by Nickid2018 on 2023/7/12.
//

#include "protocol_data.h"

char *STATE_NAME[] = {"Handshake", "Play", "Server List Ping", "Login", "Invalid"};

gint read_var_int(const guint8 *data, guint max_length, guint *result) {
    gint p = 0;
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

gint read_ushort(const guint8 *data, guint16 *result) {
    *result = (data[0] << 8) | data[1];
    return 2;
}

gint read_ulong(const guint8 *data, guint64 *result) {
    *result = ((guint64) data[0] << 56) | ((guint64) data[1] << 48) | ((guint64) data[2] << 40) |
              ((guint64) data[3] << 32) | ((guint64) data[4] << 24) | ((guint64) data[5] << 16) |
              ((guint64) data[6] << 8) | data[7];
    return 8;
}

gint read_string(const guint8 *data, guint8 **result) {
    guint length;
    gint read = read_var_int(data, 5, &length);
    if (is_invalid(read))
        return INVALID_DATA;
    *result = wmem_alloc(wmem_packet_scope(), length + 1);
    memcpy(*result, data + read, length);
    (*result)[length] = '\0';
    return read + length;
}