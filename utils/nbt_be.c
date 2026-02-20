
#include "nbt.h"
#include "protocol/protocol_data.h"

int32_t count_be_nbt_length_with_type(tvbuff_t *tvb, int32_t offset, uint32_t type) {
    if (type == TAG_END)
        return 0;
    if (type == TAG_BYTE)
        return 1;
    if (type == TAG_SHORT)
        return 2;
    if (type == TAG_FLOAT)
        return 4;
    if (type == TAG_DOUBLE)
        return 8;
    if (type == TAG_INT) {
        int32_t uncare;
        int32_t length = read_var_int(tvb, offset, &uncare);
        return length;
    }
    if (type == TAG_LONG) {
        int64_t uncare;
        int32_t length = read_var_long(tvb, offset, &uncare);
        return length;
    }
    if (type == TAG_BYTE_ARRAY || type == TAG_STRING) {
        int32_t len;
        int32_t length = read_var_int(tvb, offset, &len);
        return length + len;
    }
    if (type == TAG_LIST) {
        uint32_t sub_type = tvb_get_uint8(tvb, offset);
        int32_t len;
        int32_t length = read_var_int(tvb, offset, &len);
        if (sub_type == TAG_END)
            return 1 + length;
        int32_t sub_length = 0;
        for (uint32_t i = 0; i < len; i++)
            sub_length += count_be_nbt_length_with_type(tvb, offset + 1 + length + sub_length, sub_type);
        return 1 + length + sub_length;
    }
    if (type == TAG_COMPOUND) {
        int32_t sub_length = 0;
        uint32_t sub_type;
        while ((sub_type = tvb_get_uint8(tvb, offset + sub_length)) != TAG_END) {
            int32_t name_length;
            int32_t length = read_var_int(tvb, offset, &name_length);
            sub_length += 1 + length + name_length;
            sub_length += count_be_nbt_length_with_type(tvb, offset + sub_length, sub_type);
        }
        return sub_length + 1;
    }
    if (type == TAG_INT_ARRAY) {
        int32_t len;
        int32_t length = read_var_int(tvb, offset, &len);
        for (uint32_t i = 0; i < len; i++) {
            int32_t uncare;
            length += read_var_int(tvb, offset + 1 + length, &uncare);
        }
        return 1 + length;
    }
    return 0;
}

int32_t count_be_nbt_length(tvbuff_t *tvb, int32_t offset) {
    uint8_t type = tvb_get_uint8(tvb, offset);
    int32_t name_length;
    int32_t length = read_var_int(tvb, offset, &name_length);
    return count_be_nbt_length_with_type(tvb, offset + 1 + length + name_length, type) + 1 + length + name_length;
}