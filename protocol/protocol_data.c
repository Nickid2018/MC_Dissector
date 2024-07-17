//
// Created by Nickid2018 on 2023/7/12.
//

#include "protocol_data.h"

char *STATE_NAME[] = {"Handshake", "Play", "Server List Ping", "Login", "Transfer", "Configuration", "Invalid"};

gint read_var_int(tvbuff_t *tvb, gint offset, gint *result) {
    guint8 read;
    gint p = 0;
    *result = 0;
    do {
        if (p == 5)
            return INVALID_DATA;
        read = tvb_get_guint8(tvb, offset + p);
        *result |= (read & 0x7F) << (7 * p++);
    } while ((read & 0x80) != 0);
    return p;
}

gint read_var_int_with_limit(tvbuff_t *tvb, gint offset, gint max_length, gint *result) {
    guint8 read;
    gint p = 0;
    *result = 0;
    do {
        if (p == 5 || p >= max_length)
            return INVALID_DATA;
        read = tvb_get_guint8(tvb, offset + p);
        *result |= (read & 0x7F) << (7 * p++);
    } while ((read & 0x80) != 0);
    return p;
}

gint read_var_long(tvbuff_t *tvb, gint offset, gint64 *result) {
    gint p = 0;
    *result = 0;
    guint8 read;
    do {
        if (p == 10)
            return INVALID_DATA;
        read = tvb_get_guint8(tvb, offset + p);
        *result |= (read & 0x7F) << (7 * p++);
    } while ((read & 0x80) != 0);
    return p;
}

gint read_buffer(tvbuff_t *tvb, gint offset, guint8 **result, wmem_allocator_t *allocator) {
    gint length;
    gint read = read_var_int(tvb, offset, &length);
    if (is_invalid(read))
        return INVALID_DATA;
    *result = wmem_alloc(allocator, length + 1);
    tvb_memcpy(tvb, *result, offset + read, length);
    (*result)[length] = '\0';
    return read + length;
}