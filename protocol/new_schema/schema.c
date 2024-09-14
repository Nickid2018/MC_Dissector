//
// Created by nickid2018 on 24-9-14.
//

#include "schema.h"
#include "protocol/protocol_data.h"

extern int hf_int8;
extern int hf_uint8;
extern int hf_hint8;
extern int hf_int16;
extern int hf_uint16;
extern int hf_hint16;
extern int hf_int32;
extern int hf_uint32;
extern int hf_hint32;
extern int hf_int64;
extern int hf_uint64;
extern int hf_hint64;
extern int hf_float;
extern int hf_double;
extern int hf_bytes;
extern int hf_string;
extern int hf_boolean;
extern int hf_uuid;
extern int hf_varint;
extern int hf_varlong;

extern int hf_invalid_data;

struct protocol_dissector_struct {
    wmem_map_t *dissect_arguments;

    uint (*dissect_protocol)(
            proto_tree *tree, packet_info *pinfo,
            tvbuff_t *tvb, int offset,
            protocol_dissector dissector, gchar *name,
            wmem_map_t *packet_saves, const gchar **value
    );

    void (*destroy)(wmem_map_t *dissect_arguments);
};

// SMALL UTILITY FUNCTIONS ---------------------------------------------------------------------------------------------

inline void add_name(proto_item *item, gchar *name) {
    proto_item_prepend_text(item, "%s ", name);
}

inline uint add_invalid_data(proto_tree *tree, tvbuff_t *tvb, int offset, gchar *name, gchar *value) {
    if (tree)
        add_name(
                proto_tree_add_string(tree, hf_invalid_data, tvb, offset, 0, value),
                name
        );
    return -1;
}

// PROTOCOL SUB-DISSECTORS ---------------------------------------------------------------------------------------------

#define DISSECT_PROTOCOL(fn) \
uint dissect_##fn(           \
    proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset, \
    protocol_dissector dissector, gchar *name, wmem_map_t *packet_saves, const gchar **value \
)

// INTEGER SUB-DISSECTORS ----------------------------------------------------------------------------------------------

DISSECT_PROTOCOL(i8) {
    int8_t i8 = tvb_get_int8(tvb, offset);
    if (value) *value = g_strdup_printf("%d", i8);
    if (tree) add_name(proto_tree_add_int(tree, hf_int8, tvb, offset, 1, i8), name);
    return 1;
}

DISSECT_PROTOCOL(i16) {
    int16_t i16 = tvb_get_ntohis(tvb, offset);
    if (value) *value = g_strdup_printf("%d", i16);
    if (tree) add_name(proto_tree_add_int(tree, hf_int16, tvb, offset, 2, i16), name);
    return 2;
}

DISSECT_PROTOCOL(i32) {
    int32_t i32 = tvb_get_ntohil(tvb, offset);
    if (value) *value = g_strdup_printf("%d", i32);
    if (tree) add_name(proto_tree_add_int(tree, hf_int32, tvb, offset, 4, i32), name);
    return 4;
}

DISSECT_PROTOCOL(i64) {
    int64_t i64 = tvb_get_ntohi64(tvb, offset);
    if (value) *value = g_strdup_printf("%ld", i64);
    if (tree) add_name(proto_tree_add_int64(tree, hf_int64, tvb, offset, 8, i64), name);
    return 8;
}

DISSECT_PROTOCOL(u8) {
    uint8_t u8 = tvb_get_uint8(tvb, offset);
    if (value) *value = g_strdup_printf("%u", u8);
    if (tree) add_name(proto_tree_add_uint(tree, hf_uint8, tvb, offset, 1, u8), name);
    return 1;
}

DISSECT_PROTOCOL(u16) {
    uint16_t u16 = tvb_get_ntohs(tvb, offset);
    if (value) *value = g_strdup_printf("%u", u16);
    if (tree) add_name(proto_tree_add_uint(tree, hf_uint16, tvb, offset, 2, u16), name);
    return 2;
}

DISSECT_PROTOCOL(u32) {
    uint32_t u32 = tvb_get_ntohl(tvb, offset);
    if (value) *value = g_strdup_printf("%u", u32);
    if (tree) add_name(proto_tree_add_uint(tree, hf_uint32, tvb, offset, 4, u32), name);
    return 4;
}

DISSECT_PROTOCOL(u64) {
    uint64_t u64 = tvb_get_ntoh64(tvb, offset);
    if (value) *value = g_strdup_printf("%lu", u64);
    if (tree) add_name(proto_tree_add_uint64(tree, hf_uint64, tvb, offset, 8, u64), name);
    return 8;
}

DISSECT_PROTOCOL(h8) {
    uint8_t u8 = tvb_get_uint8(tvb, offset);
    if (value) *value = g_strdup_printf("%u", u8);
    if (tree) add_name(proto_tree_add_uint(tree, hf_hint8, tvb, offset, 1, u8), name);
    return 1;
}

DISSECT_PROTOCOL(h16) {
    uint16_t u16 = tvb_get_ntohs(tvb, offset);
    if (value) *value = g_strdup_printf("%u", u16);
    if (tree) add_name(proto_tree_add_uint(tree, hf_hint16, tvb, offset, 2, u16), name);
    return 2;
}

DISSECT_PROTOCOL(h32) {
    uint32_t u32 = tvb_get_ntohl(tvb, offset);
    if (value) *value = g_strdup_printf("%u", u32);
    if (tree) add_name(proto_tree_add_uint(tree, hf_hint32, tvb, offset, 4, u32), name);
    return 4;
}

DISSECT_PROTOCOL(h64) {
    uint64_t u64 = tvb_get_ntoh64(tvb, offset);
    if (value) *value = g_strdup_printf("%lu", u64);
    if (tree) add_name(proto_tree_add_uint64(tree, hf_hint64, tvb, offset, 8, u64), name);
    return 8;
}

DISSECT_PROTOCOL(varint) {
    int32_t result;
    int32_t length = read_var_int(tvb, offset, &result);
    if (length < 0) return add_invalid_data(tree, tvb, offset, name, "Invalid VarInt");
    if (value) *value = g_strdup_printf("%u", result);
    if (tree) add_name(proto_tree_add_uint(tree, hf_varint, tvb, offset, length, result), name);
    return length;
}

DISSECT_PROTOCOL(varlong) {
    int64_t result;
    int32_t length = read_var_long(tvb, offset, &result);
    if (length < 0) return add_invalid_data(tree, tvb, offset, name, "Invalid VarLong");
    if (value) *value = g_strdup_printf("%lu", result);
    if (tree) add_name(proto_tree_add_uint64(tree, hf_varlong, tvb, offset, length, result), name);
    return length;
}


// FLOAT POINTER NUMBER SUB-DISSECTORS ---------------------------------------------------------------------------------

DISSECT_PROTOCOL(f32) {
    float f32 = tvb_get_ntohieee_float(tvb, offset);
    if (value) *value = g_strdup_printf("%f", f32);
    if (tree) add_name(proto_tree_add_float(tree, hf_float, tvb, offset, 4, f32), name);
    return 4;
}

DISSECT_PROTOCOL(f64) {
    double f64 = tvb_get_ntohieee_double(tvb, offset);
    if (value) *value = g_strdup_printf("%f", f64);
    if (tree) add_name(proto_tree_add_double(tree, hf_double, tvb, offset, 8, f64), name);
    return 8;
}

// OTHER SIMPLE SUB-DISSECTORS -----------------------------------------------------------------------------------------

DISSECT_PROTOCOL(void) {
    return 0;
}

DISSECT_PROTOCOL(bool) {
    bool boolean = tvb_get_uint8(tvb, offset);
    if (value) *value = g_strdup(boolean ? "true" : "false");
    if (tree) add_name(proto_tree_add_boolean(tree, hf_boolean, tvb, offset, 1, boolean), name);
    return 1;
}

DISSECT_PROTOCOL(string) {
    uint8_t *str;
    int32_t length = read_buffer(tvb, offset, &str, pinfo->pool);
    if (length < 0) return add_invalid_data(tree, tvb, offset, name, "Invalid String");
    gchar *print = g_strdup_printf("%s", str);
    if (value) *value = g_strdup(print);
    if (tree) add_name(proto_tree_add_string(tree, hf_string, tvb, offset, length, print), name);
    return length;
}

DISSECT_PROTOCOL(buffer) {
    int32_t buffer_len;
    int32_t length = read_var_int(tvb, offset, &buffer_len);
    if (length < 0) return add_invalid_data(tree, tvb, offset, name, "Invalid Buffer");
    if (tree) {
        uint8_t *buffer = tvb_memdup(pinfo->pool, tvb, offset + length, buffer_len > 200 ? 200 : buffer_len);
        add_name(proto_tree_add_bytes(tree, hf_bytes, tvb, offset, length + buffer_len, buffer), name);
    }
    return length + buffer_len;
}

DISSECT_PROTOCOL(uuid) {
    e_guid_t *uuid = wmem_new(pinfo->pool, e_guid_t);
    tvb_get_guid(tvb, offset, uuid, 0);
    if (value) *value = guids_resolve_guid_to_str(uuid, pinfo->pool);
    if (tree) add_name(proto_tree_add_guid(tree, hf_uuid, tvb, offset, 16, uuid), name);
    return 16;
}

// COMPOSITE SUB-DISSECTORS --------------------------------------------------------------------------------------------