//
// Created by nickid2018 on 24-9-14.
//

#include "schema.h"
#include "protocol/protocol_data.h"
#include "utils/nbt.h"
#include "functions.h"
#include <epan/conversation.h>

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
extern int hf_parsing_error;

extern int ett_mc;

extern gchar *pref_protocol_data_dir;

gboolean destroy_dissector(gpointer key _U_, gpointer value, gpointer user_data _U_) {
    protocol_dissector *dissector = value;
    if (dissector->dissect_arguments && dissector->destroy) dissector->destroy(dissector->dissect_arguments);
    if (dissector->dissect_arguments) wmem_free(wmem_epan_scope(), dissector->dissect_arguments);
    wmem_free(wmem_epan_scope(), dissector);
    return true;
}

gboolean destroy_pointer(gpointer key _U_, gpointer value, gpointer user_data _U_) {
    wmem_free(wmem_epan_scope(), value);
    return true;
}

void destroy_protocol(protocol_dissector_set *dissector_set) {
    wmem_map_foreach_remove(dissector_set->dissectors_by_name, destroy_dissector, NULL);
    wmem_map_foreach_remove(dissector_set->dissectors_by_state, destroy_pointer, NULL);
    wmem_map_foreach_remove(dissector_set->registry_keys, destroy_pointer, NULL);
    wmem_map_foreach_remove(dissector_set->readable_names, destroy_pointer, NULL);
    wmem_free(wmem_epan_scope(), dissector_set->dissectors_by_name);
    wmem_free(wmem_epan_scope(), dissector_set->dissectors_by_state);
    wmem_free(wmem_epan_scope(), dissector_set->registry_keys);
    wmem_free(wmem_epan_scope(), dissector_set->readable_names);
    wmem_free(wmem_epan_scope(), dissector_set);
}

// PROTOCOL SUB-DISSECTORS ---------------------------------------------------------------------------------------------

#define DISSECT_PROTOCOL(fn) \
int32_t dissect_##fn(           \
    proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset, \
    protocol_dissector *dissector, gchar *name, wmem_map_t *packet_saves, gchar **value \
)

#define DESTROY_DISSECTOR(fn) void destroy_##fn(wmem_map_t *dissect_arguments)

// SMALL UTILITY FUNCTIONS ---------------------------------------------------------------------------------------------

void add_name(proto_item *item, gchar *name) {
    proto_item_prepend_text(item, "%s ", name);
}

int32_t add_invalid_data(proto_tree *tree, tvbuff_t *tvb, int offset, gchar *name, gchar *value) {
    if (tree) add_name(proto_tree_add_string(tree, hf_invalid_data, tvb, offset, 0, value), name);
    return DISSECT_ERROR;
}

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

DISSECT_PROTOCOL(rest_buffer) {
    int32_t buffer_len = tvb_reported_length_remaining(tvb, offset);
    if (tree) {
        uint8_t *buffer = tvb_memdup(pinfo->pool, tvb, offset, buffer_len > 200 ? 200 : buffer_len);
        add_name(proto_tree_add_bytes(tree, hf_bytes, tvb, offset, buffer_len, buffer), name);
    }
    return buffer_len;
}

DISSECT_PROTOCOL(uuid) {
    e_guid_t *uuid = wmem_new(pinfo->pool, e_guid_t);
    tvb_get_guid(tvb, offset, uuid, 0);
    if (value) *value = g_strdup(guids_resolve_guid_to_str(uuid, pinfo->pool));
    if (tree) add_name(proto_tree_add_guid(tree, hf_uuid, tvb, offset, 16, uuid), name);
    return 16;
}

DISSECT_PROTOCOL(nbt) {
    bool is_new_nbt = wmem_map_lookup(get_global_data(pinfo), "nbt_any_type");

    int len = 0;
    int present = 1;
    if (is_new_nbt) {
        present = tvb_get_uint8(tvb, offset);
        len = 1;
    }

    if (!present) {
        if (tree) {
            proto_item *text = proto_tree_add_boolean(tree, hf_boolean, tvb, offset, 1, false);
            proto_item_set_text(text, "%s [optional nbt]: Not present", name);
        }
        return len;
    }
    if (tree && pref_do_nbt_decode) return do_nbt_tree(tree, pinfo, tvb, offset, name, !is_new_nbt);

    int32_t len_nbt;
    if (is_new_nbt) len_nbt = count_nbt_length_with_type(tvb, offset + len, present);
    else len_nbt = count_nbt_length(tvb, offset + len);
    if (tree)
        add_name(proto_tree_add_bytes(
                tree, hf_bytes, tvb, offset + len, len_nbt,
                tvb_memdup(pinfo->pool, tvb, offset + len, len_nbt > 200 ? 200 : len_nbt)
        ), name);

    return len + len_nbt;
}

DISSECT_PROTOCOL(optional_nbt) {
    if (tvb_get_uint8(tvb, offset) == TAG_END) {
        if (tree) {
            proto_item *text = proto_tree_add_boolean(tree, hf_boolean, tvb, offset, 1, false);
            proto_item_set_text(text, "%s [optional nbt]: Not present", name);
        }
        return 1;
    }

    if (tree && pref_do_nbt_decode) return do_nbt_tree(tree, pinfo, tvb, offset + 1, name, true) + 1;
    int32_t len_nbt = count_nbt_length(tvb, offset + 1);
    if (tree)
        add_name(proto_tree_add_bytes(
                tree, hf_bytes, tvb, offset + 1, len_nbt,
                tvb_memdup(pinfo->pool, tvb, offset + 1, len_nbt > 200 ? 200 : len_nbt)
        ), name);

    return 1 + len_nbt;
}

// COMPOSITE SUB-DISSECTORS --------------------------------------------------------------------------------------------

DISSECT_PROTOCOL(error) {
    gchar *error_message = wmem_map_lookup(dissector->dissect_arguments, "e");
    if (tree)
        add_name(proto_tree_add_string_format_value(
                tree, hf_parsing_error, tvb, offset, 0, "", "The protocol dissector failed to parse: %s", error_message
        ), name);
    return DISSECT_ERROR;
}

DESTROY_DISSECTOR(error) {
    g_free(wmem_map_remove(dissect_arguments, "e"));
}

typedef struct name_and_dissector_struct {
    gchar *name;
    protocol_dissector *dissector;
} name_and_dissector;

DISSECT_PROTOCOL(container) {
    name_and_dissector **sub_dissectors = wmem_map_lookup(dissector->dissect_arguments, "d");
    uint64_t count = (uint64_t) wmem_map_lookup(dissector->dissect_arguments, "s");
    if (!sub_dissectors) return DISSECT_ERROR;
    if (count == 0) return 0;
    if (tree) tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_mc, NULL, name);
    int32_t total = 0;
    for (int i = 0; i < count; i++) {
        name_and_dissector *sub_dissector = sub_dissectors[i];
        int32_t len = sub_dissector->dissector->dissect_protocol(
                tree, pinfo, tvb, offset + total, sub_dissector->dissector, sub_dissector->name, packet_saves, NULL
        );
        if (len == DISSECT_ERROR) return DISSECT_ERROR;
        total += len;
    }
    if (tree) proto_item_set_len(tree, total);
    return total;
}

DESTROY_DISSECTOR(container) {
    name_and_dissector **sub_dissectors = wmem_map_remove(dissect_arguments, "d");
    uint64_t count = (uint64_t) wmem_map_lookup(dissect_arguments, "s");
    for (int i = 0; i < count; i++) {
        name_and_dissector *sub_dissector = sub_dissectors[i];
        g_free(sub_dissector->name);
        wmem_free(wmem_epan_scope(), sub_dissector);
    }
    wmem_free(wmem_epan_scope(), sub_dissectors);
}

DISSECT_PROTOCOL(array) {
    protocol_dissector *sub_dissector = wmem_map_lookup(dissector->dissect_arguments, "d");
    gchar *search_key = wmem_map_lookup(dissector->dissect_arguments, "k");
    protocol_dissector *get_count_dissector = wmem_map_lookup(dissector->dissect_arguments, "c");

    int64_t parsed_count = 0;
    int32_t total = 0;
    if (search_key) {
        gchar *searched_value = wmem_map_lookup(packet_saves, search_key);
        if (!searched_value) searched_value = search_key;
        gchar *end;
        errno = 0;
        parsed_count = strtoll(searched_value, &end, 10);
        if (errno == ERANGE) return add_invalid_data(tree, tvb, offset, name, "Array size is too large");
        if (searched_value == end) return add_invalid_data(tree, tvb, offset, name, "Invalid array size string");
    } else {
        gchar *saved_value;
        int32_t len = get_count_dissector->dissect_protocol(
                NULL, pinfo, tvb, offset, get_count_dissector, "", packet_saves, &saved_value
        );
        if (len == DISSECT_ERROR) return DISSECT_ERROR;
        if (!saved_value)
            return add_invalid_data(tree, tvb, offset, name, "Can't receive value from source, protocol has error?");
        gchar *end;
        errno = 0;
        parsed_count = strtoll(saved_value, &end, 10);
        if (errno == ERANGE) return add_invalid_data(tree, tvb, offset, name, "Array size is too large");
        if (saved_value == end) return add_invalid_data(tree, tvb, offset, name, "Invalid array size string");
        g_free(saved_value);
        total += len;
    }

    if (tree) tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_mc, NULL, name);
    for (int i = 0; i < parsed_count; i++) {
        gchar *name_format = g_strdup_printf("%s[%d]", name, i);
        int32_t len = sub_dissector->dissect_protocol(
                tree, pinfo, tvb, offset + total, sub_dissector, name_format, packet_saves, NULL
        );
        if (len == DISSECT_ERROR) return DISSECT_ERROR;
        total += len;
    }
    if (tree) proto_item_set_len(tree, total);

    return total;
}

DESTROY_DISSECTOR(array) {
    g_free(wmem_map_remove(dissect_arguments, "k"));
}

DISSECT_PROTOCOL(option) {
    bool is_present = tvb_get_uint8(tvb, offset) != 0;
    if (!is_present) return 1;
    protocol_dissector *sub_dissector = wmem_map_lookup(dissector->dissect_arguments, "d");
    int32_t len = sub_dissector->dissect_protocol(
            tree, pinfo, tvb, offset + 1, sub_dissector, name, packet_saves, value
    );
    if (len == DISSECT_ERROR) return DISSECT_ERROR;
    return len + 1;
}

DISSECT_PROTOCOL(mapper) {
    protocol_dissector *sub_dissector = wmem_map_lookup(dissector->dissect_arguments, "d");
    gchar *saved_value = NULL;
    int32_t len = sub_dissector->dissect_protocol(
            NULL, pinfo, tvb, offset, sub_dissector, name, packet_saves, &saved_value
    );
    if (len == DISSECT_ERROR) return DISSECT_ERROR;
    if (!saved_value)
        return add_invalid_data(tree, tvb, offset, name, "Can't receive value from source, protocol has error?");
    wmem_map_t *mapper = wmem_map_lookup(dissector->dissect_arguments, "m");
    gchar *mapped = wmem_map_lookup(mapper, saved_value);
    if (!mapped) mapped = g_strdup(saved_value);
    if (value) *value = g_strdup(mapped);
    if (tree)
        add_name(proto_tree_add_string_format_value(
                tree, hf_string, tvb, offset, len, mapped, "%s (%s)", mapped, saved_value
        ), name);
    return len;
}

DESTROY_DISSECTOR(mapper) {
    wmem_map_t *mapper = wmem_map_remove(dissect_arguments, "m");
    wmem_list_t *keys = wmem_map_get_keys(wmem_epan_scope(), mapper);
    wmem_list_frame_t *frame = wmem_list_head(keys);
    do {
        g_free(wmem_map_remove(mapper, wmem_list_frame_data(frame)));
    } while ((frame = wmem_list_frame_next(frame)));
    wmem_destroy_list(keys);
    wmem_free(wmem_epan_scope(), keys);
    wmem_free(wmem_epan_scope(), mapper);
}

DISSECT_PROTOCOL(switch) {
    gchar *key = wmem_map_lookup(dissector->dissect_arguments, "k");
    gchar *searched_value = wmem_map_lookup(packet_saves, key);
    if (!searched_value) return add_invalid_data(tree, tvb, offset, name, "Context has no specific key");
    wmem_map_t *mapper = wmem_map_lookup(dissector->dissect_arguments, "m");
    protocol_dissector *mapped = wmem_map_lookup(mapper, searched_value);
    if (!mapped) mapped = wmem_map_lookup(dissector->dissect_arguments, "d");
    if (!mapped) return add_invalid_data(tree, tvb, offset, name, "No compatible dissector found");
    return mapped->dissect_protocol(tree, pinfo, tvb, offset, mapped, name, packet_saves, value);
}

DESTROY_DISSECTOR(switch) {
    g_free(wmem_map_remove(dissect_arguments, "k"));
    wmem_free(wmem_epan_scope(), wmem_map_remove(dissect_arguments, "m"));
}

typedef struct bit_field_struct {
    gchar *name;
    gchar *save_name;
    int counts;
    bool signed_number;
} bit_field;

DISSECT_PROTOCOL(bitfield) {
    bit_field **bit_fields = wmem_map_lookup(dissector->dissect_arguments, "s");
    uint64_t count = (uint64_t) wmem_map_lookup(dissector->dissect_arguments, "c");

    int offset_bit = 0;
    for (int i = 0; i < count; i++) {
        int total_offset = offset * 8 + offset_bit;
        bit_field *bit_field = bit_fields[i];
        if (strcmp(bit_field->name, "unused") != 0) {
            proto_item *item;
            if (bit_field->counts > 32) {
                item = proto_tree_add_bits_item(
                        tree, bit_field->signed_number ? hf_int64 : hf_uint64,
                        tvb, total_offset, bit_field->counts, ENC_BIG_ENDIAN
                );
            } else {
                item = proto_tree_add_bits_item(
                        tree, bit_field->signed_number ? hf_int32 : hf_uint32,
                        tvb, total_offset, bit_field->counts, ENC_BIG_ENDIAN
                );
            }
            proto_item_append_text(item, " <bitmask %s>", bit_field->name);
            if (bit_field->save_name) {
                uint64_t u64 = tvb_get_bits64(tvb, total_offset, bit_field->counts, ENC_BIG_ENDIAN);
                wmem_map_insert(
                        packet_saves, bit_field->save_name,
                        g_strdup_printf(
                                bit_field->signed_number ? "%ld" : "%lu",
                                bit_field->signed_number ? *(int64_t *) &u64 : u64
                        )
                );
            }
        }
        offset_bit += bit_field->counts;
    }

    return (offset_bit + 7) / 8;
}

DESTROY_DISSECTOR(bitfield) {
    bit_field **bit_fields = wmem_map_remove(dissect_arguments, "s");
    uint64_t count = (uint64_t) wmem_map_remove(dissect_arguments, "c");
    for (int i = 0; i < count; i++) {
        bit_field *bit_field = bit_fields[i];
        g_free(bit_field->name);
        if (bit_field->save_name) g_free(bit_field->save_name);
        wmem_free(wmem_epan_scope(), bit_field);
    }
    wmem_free(wmem_epan_scope(), bit_fields);
}

DISSECT_PROTOCOL(save) {
    protocol_dissector *sub_dissector = wmem_map_lookup(dissector->dissect_arguments, "d");
    gchar *save_name = wmem_map_lookup(dissector->dissect_arguments, "s");
    gchar *saved_value;
    int32_t len = sub_dissector->dissect_protocol(
            tree, pinfo, tvb, offset, sub_dissector, name, packet_saves, &saved_value
    );
    if (len == DISSECT_ERROR) return DISSECT_ERROR;
    wmem_map_insert(packet_saves, save_name, saved_value);
    return len;
}

DESTROY_DISSECTOR(save) {
    g_free(wmem_map_remove(dissect_arguments, "s"));
}

DISSECT_PROTOCOL(global_save) {
    protocol_dissector *sub_dissector = wmem_map_lookup(dissector->dissect_arguments, "d");
    gchar *save_name = wmem_map_lookup(dissector->dissect_arguments, "s");
    gchar *saved_value;
    int32_t len = sub_dissector->dissect_protocol(
            tree, pinfo, tvb, offset, sub_dissector, name, packet_saves, &saved_value
    );
    if (len == DISSECT_ERROR) return DISSECT_ERROR;
    wmem_map_t *global_data = get_global_data(pinfo);
    if (!wmem_map_contains(global_data, save_name))
        wmem_map_insert(global_data, save_name, saved_value);
    return len;
}

DESTROY_DISSECTOR(global_save) {
    g_free(wmem_map_remove(dissect_arguments, "s"));
}

DISSECT_PROTOCOL(registry) {
    gchar *registry_name = wmem_map_lookup(dissector->dissect_arguments, "n");
    wmem_map_t *writable_registry = wmem_map_lookup(get_global_data(pinfo), "#writable_registry");
    wmem_map_t *writable_registry_size = wmem_map_lookup(get_global_data(pinfo), "#writable_registry_size");
    int32_t index;
    int32_t len = read_var_int(tvb, offset, &index);
    gchar *key;
    if (writable_registry != NULL && wmem_map_contains(writable_registry, registry_name)) {
        gchar **data = wmem_map_lookup(writable_registry, registry_name);
        uint64_t count = (uint64_t) wmem_map_lookup(writable_registry_size, registry_name);
        if (index >= count) {
            key = "<Unknown Registry Entry>";
        } else {
            key = data[index];
        }
    } else {
        uint32_t protocol_version = (uint64_t) wmem_map_lookup(get_global_data(pinfo), "protocol_version");
        key = get_registry_data(protocol_version, registry_name, index);
    }
    if (value) *value = g_strdup(key);
    if (tree)
        add_name(proto_tree_add_string_format_value(
                tree, hf_string, tvb, offset, len, key, "%s (%d)", key, index), name
        );
    return len;
}

DESTROY_DISSECTOR(registry) {
    g_free(wmem_map_remove(dissect_arguments, "n"));
}

DISSECT_PROTOCOL(codec) {
    protocol_dissector **list = wmem_map_lookup(dissector->dissect_arguments, "d");
    uint64_t count = (uint64_t) wmem_map_lookup(dissector->dissect_arguments, "c");
    gchar *registry_name = wmem_map_lookup(dissector->dissect_arguments, "n");
    uint32_t protocol_version = (uint64_t) wmem_map_lookup(get_global_data(pinfo), "protocol_version");
    int32_t index;
    int32_t len = read_var_int(tvb, offset, &index);
    if (index >= count) return DISSECT_ERROR;
    gchar *key = get_registry_data(protocol_version, registry_name, index);
    if (value) *value = g_strdup(key);
    if (tree)
        add_name(proto_tree_add_string_format(tree, hf_string, tvb, offset, len, key, "%s (%d)", key, index), name);
    protocol_dissector *sub = list[index];
    int32_t sub_len = sub->dissect_protocol(
            tree, pinfo, tvb, offset + len, sub, g_strdup_printf("%s Codec", registry_name), packet_saves, NULL
    );
    if (sub_len == DISSECT_ERROR) return DISSECT_ERROR;
    return len + sub_len;
}

DESTROY_DISSECTOR(codec) {
    wmem_free(wmem_epan_scope(), wmem_map_remove(dissect_arguments, "d"));
    g_free(wmem_map_remove(dissect_arguments, "n"));
}

DISSECT_PROTOCOL(top_bit_set_terminated_array) {
    uint8_t now;
    int32_t len = 0;
    protocol_dissector *sub_dissector = wmem_map_lookup(dissector->dissect_arguments, "d");
    if (tree) tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_mc, NULL, name);
    while (((now = tvb_get_uint8(tvb, offset + len)) & 0x80) != 0) {
        uint32_t ord = now & 0x7F;
        int32_t sub_len = sub_dissector->dissect_protocol(
                tree, pinfo, tvb, offset + len, sub_dissector, g_strdup_printf("%s[%d]", name, ord), packet_saves, NULL
        );
        if (sub_len == DISSECT_ERROR) return DISSECT_ERROR;
        len += sub_len;
    }
    if (tree) proto_item_set_len(tree, len + 1);
    return len + 1;
}

DISSECT_PROTOCOL(entity_metadata_loop) {
    uint8_t end_val = (uint64_t) wmem_map_lookup(dissector->dissect_arguments, "e");
    protocol_dissector *sub_dissector = wmem_map_lookup(dissector->dissect_arguments, "d");
    if (tree) tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_mc, NULL, name);
    int32_t len = 0;
    int ord = 0;
    while (tvb_get_uint8(tvb, offset + len) != end_val) {
        int32_t sub_len = sub_dissector->dissect_protocol(
                tree, pinfo, tvb, offset + len, sub_dissector, g_strdup_printf("%s[%d]", name, ord), packet_saves, NULL
        );
        if (sub_len == DISSECT_ERROR) return DISSECT_ERROR;
        len += sub_len;
        ord++;
    }
    if (tree) proto_item_set_len(tree, len + 1);
    return len + 1;
}

// PARSING PROTOCOL SCHEMA ---------------------------------------------------------------------------------------------

protocol_dissector *make_protocol_dissector(
        cJSON *root, wmem_map_t *dissectors, uint32_t protocol_version, protocol_dissector *recursive_root,
        bool put_dissectors
);

// PARSERS -------------------------------------------------------------------------------------------------------------

protocol_dissector *make_void() {
    protocol_dissector *simple_dissector = wmem_alloc(wmem_epan_scope(), sizeof(protocol_dissector));
    simple_dissector->dissect_arguments = NULL;
    simple_dissector->dissect_protocol = dissect_void;
    simple_dissector->destroy = NULL;
    return simple_dissector;
}

protocol_dissector *make_error(gchar *error_message) {
    protocol_dissector *error_dissector = wmem_alloc(wmem_epan_scope(), sizeof(protocol_dissector));
    error_dissector->dissect_arguments = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    wmem_map_insert(error_dissector->dissect_arguments, "e", error_message);
    error_dissector->dissect_protocol = dissect_error;
    error_dissector->destroy = destroy_error;
    return error_dissector;
}

#define SIMPLE_PROTOCOL(name, func) \
if (strcmp(type, #name) == 0) { \
    if (!put_dissectors) return make_simple(func); \
    if (wmem_map_contains(dissectors, #name)) return wmem_map_lookup(dissectors, #name); \
    protocol_dissector *dissector = make_simple(func); \
    wmem_map_insert(dissectors, #name, dissector); \
    return dissector; \
}

protocol_dissector *make_simple(DISSECT_FUNCTION_SIG(func)) {
    protocol_dissector *simple_dissector = wmem_alloc(wmem_epan_scope(), sizeof(protocol_dissector));
    simple_dissector->dissect_arguments = NULL;
    simple_dissector->dissect_protocol = func;
    simple_dissector->destroy = NULL;
    return simple_dissector;
}

#define COMPOSITE_PROTOCOL_DEFINE(fn) \
protocol_dissector *make_##fn(cJSON *params, wmem_map_t *dissectors, uint32_t protocol_version, protocol_dissector *recursive_root)
#define COMPOSITE_PROTOCOL(name, count) \
if (strcmp(type, #name) == 0 && args == count && composite_type) { \
    if (!put_dissectors) return make_##name(root, dissectors, protocol_version, recursive_root); \
    protocol_dissector *dissector = make_##name(root, dissectors, protocol_version, recursive_root); \
    wmem_map_insert(dissectors, g_uuid_string_random(), dissector); \
    return dissector; \
}
#define RECURSIVE_ROOT recursive_root == NULL ? this_dissector : recursive_root

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(container) {
    cJSON *list = cJSON_GetArrayItem(params, 1);
    if (!cJSON_IsArray(list)) return make_error("Container param needs to be a list");
    int count = cJSON_GetArraySize(list);
    protocol_dissector *this_dissector = wmem_alloc(wmem_epan_scope(), sizeof(protocol_dissector));
    name_and_dissector **sub_dissectors = wmem_alloc(wmem_epan_scope(), sizeof(name_and_dissector *) * count);
    for (int i = 0; i < count; i++) {
        cJSON *node = cJSON_GetArrayItem(list, i);
        cJSON *name_node = cJSON_GetObjectItem(node, "name");
        if (name_node == NULL) return make_error("Lack of name for container object");
        if (!cJSON_IsString(name_node)) return make_error("Invalid name for container object");
        gchar *name = g_strdup(name_node->valuestring);
        cJSON *type = cJSON_GetObjectItem(node, "type");
        if (type == NULL) return make_error("Lack of type for container object");
        protocol_dissector *sub_dissector = make_protocol_dissector(
                type, dissectors, protocol_version, RECURSIVE_ROOT, true
        );
        name_and_dissector *data = wmem_alloc(wmem_epan_scope(), sizeof(name_and_dissector));
        data->name = name;
        data->dissector = sub_dissector;
        sub_dissectors[i] = data;
    }
    this_dissector->dissect_arguments = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    wmem_map_insert(this_dissector->dissect_arguments, "d", sub_dissectors);
    wmem_map_insert(this_dissector->dissect_arguments, "s", (void *) (uint64_t) count);
    this_dissector->dissect_protocol = dissect_container;
    this_dissector->destroy = destroy_container;
    return this_dissector;
}

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(array) {
    cJSON *object = cJSON_GetArrayItem(params, 1);
    if (!cJSON_IsObject(object)) return make_error("Array param needs to be a object");
    cJSON *type = cJSON_GetObjectItem(object, "type");
    if (type == NULL) return make_error("Lack of type for array object");
    cJSON *count_type = cJSON_GetObjectItem(object, "countType");
    cJSON *count = cJSON_GetObjectItem(object, "count");
    if (count == NULL && count_type == NULL) return make_error("Lack of count/countType for array object");
    protocol_dissector *this_dissector = wmem_alloc(wmem_epan_scope(), sizeof(protocol_dissector));
    this_dissector->dissect_arguments = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    protocol_dissector *sub_dissector = make_protocol_dissector(
            type, dissectors, protocol_version, RECURSIVE_ROOT, true
    );
    wmem_map_insert(this_dissector->dissect_arguments, "d", sub_dissector);
    if (count_type != NULL) {
        protocol_dissector *count_type_dissect = make_protocol_dissector(
                count_type, dissectors, protocol_version, RECURSIVE_ROOT, true
        );
        wmem_map_insert(this_dissector->dissect_arguments, "c", count_type_dissect);
    } else {
        bool is_string = cJSON_IsString(count);
        bool is_number = cJSON_IsNumber(count);
        if (!is_string && !is_number) return make_error("Invalid count for array object");
        if (is_string)
            wmem_map_insert(this_dissector->dissect_arguments, "k", count->valuestring);
        if (is_number)
            wmem_map_insert(this_dissector->dissect_arguments, "k", g_strdup_printf("%d", (int) count->valuedouble));
    }
    this_dissector->dissect_protocol = dissect_array;
    this_dissector->destroy = destroy_array;
    return this_dissector;
}

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(option) {
    cJSON *type = cJSON_GetArrayItem(params, 1);
    protocol_dissector *this_dissector = wmem_alloc(wmem_epan_scope(), sizeof(protocol_dissector));
    this_dissector->dissect_arguments = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    protocol_dissector *sub_dissector = make_protocol_dissector(
            type, dissectors, protocol_version, RECURSIVE_ROOT, true
    );
    wmem_map_insert(this_dissector->dissect_arguments, "d", sub_dissector);
    this_dissector->dissect_protocol = dissect_option;
    return this_dissector;
}

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(mapper) {
    cJSON *object = cJSON_GetArrayItem(params, 1);
    if (!cJSON_IsObject(object)) return make_error("Mapper param needs to be a object");
    cJSON *type = cJSON_GetObjectItem(object, "type");
    if (type == NULL) return make_error("Lack of type for mapper object");
    cJSON *mappings = cJSON_GetObjectItem(object, "mappings");
    cJSON *source = cJSON_GetObjectItem(object, "source");
    if (mappings == NULL && source == NULL) return make_error("Lack of mappings and source for mapper object");
    wmem_map_t *map = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    if (mappings != NULL) {
        if (!cJSON_IsObject(mappings)) return make_error("Invalid mappings for mapper object");
        cJSON *node = mappings->child;
        while (node != NULL) {
            if (!cJSON_IsString(node)) {
                wmem_free(wmem_epan_scope(), map);
                return make_error("Invalid mapping entry for mapper object");
            }
            wmem_map_insert(map, g_strdup(node->string), g_strdup(node->valuestring));
            node = node->next;
        }
    } else {
        if (!cJSON_IsString(source)) return make_error("Invalid source for mapper object");
        gchar *file = build_indexed_file_name("mappings", source->valuestring, protocol_version);
        gchar *content = NULL;
        if (!g_file_get_contents(file, &content, NULL, NULL)) {
            ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot read file %s", file);
            g_free(file);
            wmem_free(wmem_epan_scope(), map);
            return make_error("Cannot read mapping file");
        }
        cJSON *json = cJSON_Parse(content);
        g_free(content);
        if (json == NULL) {
            const gchar *error = cJSON_GetErrorPtr();
            ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot parse file %s: %s", file, error);
            g_free(file);
            wmem_free(wmem_epan_scope(), map);
            return make_error(g_strdup_printf("Cannot parse mapping file: %s", error));
        }
        g_free(file);
        if (!cJSON_IsObject(json)) {
            cJSON_free(json);
            wmem_free(wmem_epan_scope(), map);
            return make_error("Mapping file is not an object");
        }
        cJSON *now = json->child;
        while (now != NULL) {
            if (!cJSON_IsString(now)) {
                wmem_free(wmem_epan_scope(), map);
                return make_error("Invalid mapping");
            }
            wmem_map_insert(map, g_strdup(now->string), g_strdup(now->valuestring));
            now = now->next;
        }
        cJSON_free(json);
    }
    protocol_dissector *this_dissector = wmem_alloc(wmem_epan_scope(), sizeof(protocol_dissector));
    this_dissector->dissect_arguments = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    protocol_dissector *sub_dissector = make_protocol_dissector(
            type, dissectors, protocol_version, RECURSIVE_ROOT, true
    );
    wmem_map_insert(this_dissector->dissect_arguments, "d", sub_dissector);
    wmem_map_insert(this_dissector->dissect_arguments, "m", map);
    this_dissector->dissect_protocol = dissect_mapper;
    this_dissector->destroy = destroy_mapper;
    return this_dissector;
}

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(switch) {
    cJSON *object = cJSON_GetArrayItem(params, 1);
    if (!cJSON_IsObject(object)) return make_error("Switch param needs to be a object");
    cJSON *key = cJSON_GetObjectItem(object, "compareTo");
    if (key == NULL) return make_error("Lack of compareTo for switch object");
    if (!cJSON_IsString(key)) return make_error("Invalid compareTo for switch object");
    cJSON *fields = cJSON_GetObjectItem(object, "fields");
    if (fields == NULL) return make_error("Lack of fields for switch object");
    if (!cJSON_IsObject(fields)) return make_error("Invalid fields for switch object");
    protocol_dissector *this_dissector = wmem_alloc(wmem_epan_scope(), sizeof(protocol_dissector));
    wmem_map_t *map = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    cJSON *node = fields->child;
    while (node != NULL) {
        protocol_dissector *sub_dissector = make_protocol_dissector(
                node, dissectors, protocol_version, RECURSIVE_ROOT, true
        );
        wmem_map_insert(map, g_strdup(node->string), sub_dissector);
        node = node->next;
    }
    this_dissector->dissect_arguments = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    wmem_map_insert(this_dissector->dissect_arguments, "k", key);
    wmem_map_insert(this_dissector->dissect_arguments, "m", map);
    if (cJSON_HasObjectItem(object, "default")) {
        cJSON *def = cJSON_GetObjectItem(node, "default");
        protocol_dissector *sub_dissector = make_protocol_dissector(
                def, dissectors, protocol_version, RECURSIVE_ROOT, true
        );
        wmem_map_insert(this_dissector->dissect_arguments, "d", sub_dissector);
    }
    this_dissector->dissect_protocol = dissect_switch;
    this_dissector->destroy = destroy_switch;
    return this_dissector;
}

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(bitfield) {
    cJSON *list = cJSON_GetArrayItem(params, 1);
    if (!cJSON_IsArray(list)) return make_error("Bitfield param needs to be a list");
    int count = cJSON_GetArraySize(list);
    protocol_dissector *this_dissector = wmem_alloc(wmem_epan_scope(), sizeof(protocol_dissector));
    bit_field **bit_fields = wmem_alloc(wmem_epan_scope(), sizeof(bit_field *) * count);
    for (int i = 0; i < count; i++) {
        cJSON *node = cJSON_GetArrayItem(list, i);
        cJSON *name_node = cJSON_GetObjectItem(node, "name");
        if (name_node == NULL) return make_error("Lack of name for bitfield object");
        if (!cJSON_IsString(name_node)) return make_error("Invalid name for bitfield object");
        gchar *name = g_strdup(name_node->valuestring);
        cJSON *size_node = cJSON_GetObjectItem(node, "size");
        if (size_node == NULL) return make_error("Lack of size for bitfield object");
        if (!cJSON_IsNumber(size_node)) return make_error("Invalid size for bitfield object");
        int size = (int) size_node->valuedouble;
        cJSON *signed_node = cJSON_GetObjectItem(node, "signed");
        if (signed_node != NULL && !cJSON_IsBool(signed_node)) return make_error("Invalid signed for bitfield object");
        bool signed_num = signed_node == NULL || cJSON_IsTrue(signed_node);
        cJSON *save_name = cJSON_GetObjectItem(node, "saveName");
        if (save_name != NULL && !cJSON_IsString(save_name)) return make_error("Invalid saveName for bitfield object");
        gchar *save = save_name == NULL ? NULL : g_strdup(save_name->valuestring);
        bit_field *field = wmem_alloc(wmem_epan_scope(), sizeof(bit_field));
        field->name = name;
        field->counts = size;
        field->signed_number = signed_num;
        field->save_name = save;
        bit_fields[i] = field;
    }
    this_dissector->dissect_arguments = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    wmem_map_insert(this_dissector->dissect_arguments, "s", bit_fields);
    wmem_map_insert(this_dissector->dissect_arguments, "c", (void *) (uint64_t) count);
    this_dissector->dissect_protocol = dissect_bitfield;
    this_dissector->destroy = destroy_bitfield;
    return this_dissector;
}

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(save) {
    cJSON *type = cJSON_GetArrayItem(params, 1);
    cJSON *name_node = cJSON_GetArrayItem(params, 2);
    if (!cJSON_IsString(name_node)) return make_error("Save param 2 needs to be a string");
    gchar *name = g_strdup(name_node->valuestring);
    protocol_dissector *this_dissector = wmem_alloc(wmem_epan_scope(), sizeof(protocol_dissector));
    this_dissector->dissect_arguments = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    protocol_dissector *sub_dissector = make_protocol_dissector(
            type, dissectors, protocol_version, RECURSIVE_ROOT, true
    );
    wmem_map_insert(this_dissector->dissect_arguments, "d", sub_dissector);
    wmem_map_insert(this_dissector->dissect_arguments, "s", name);
    this_dissector->dissect_protocol = dissect_save;
    this_dissector->destroy = destroy_save;
    return this_dissector;
}

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(global_save) {
    cJSON *type = cJSON_GetArrayItem(params, 1);
    cJSON *name_node = cJSON_GetArrayItem(params, 2);
    if (!cJSON_IsString(name_node)) return make_error("Global Save param 2 needs to be a string");
    gchar *name = g_strdup(name_node->valuestring);
    protocol_dissector *this_dissector = wmem_alloc(wmem_epan_scope(), sizeof(protocol_dissector));
    this_dissector->dissect_arguments = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    protocol_dissector *sub_dissector = make_protocol_dissector(
            type, dissectors, protocol_version, RECURSIVE_ROOT, true
    );
    wmem_map_insert(this_dissector->dissect_arguments, "d", sub_dissector);
    wmem_map_insert(this_dissector->dissect_arguments, "s", name);
    this_dissector->dissect_protocol = dissect_global_save;
    this_dissector->destroy = destroy_global_save;
    return this_dissector;
}

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(registry) {
    cJSON *name_node = cJSON_GetArrayItem(params, 1);
    if (!cJSON_IsString(name_node)) return make_error("Registry param needs to be a string");
    gchar *name = g_strdup(name_node->valuestring);
    protocol_dissector *this_dissector = wmem_alloc(wmem_epan_scope(), sizeof(protocol_dissector));
    this_dissector->dissect_arguments = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    wmem_map_insert(this_dissector->dissect_arguments, "n", name);
    this_dissector->dissect_protocol = dissect_registry;
    this_dissector->destroy = destroy_registry;
    return this_dissector;
}

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(reference) {
    cJSON *ref_node = cJSON_GetArrayItem(params, 1);
    if (!cJSON_IsString(ref_node)) return make_error("Reference param needs to be a string");
    gchar *ref = ref_node->valuestring;

    if (!wmem_map_contains(dissectors, ref)) {
        gchar *file = build_protocol_file_name("structures", ref, protocol_version);

        gchar *content = NULL;
        if (!g_file_get_contents(file, &content, NULL, NULL)) {
            ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot read file %s", file);
            g_free(file);
            return make_error("Cannot read referenced file");
        }

        cJSON *json = cJSON_Parse(content);
        g_free(content);
        if (json == NULL) {
            const gchar *error = cJSON_GetErrorPtr();
            ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot parse file %s: %s", file, error);
            g_free(file);
            return make_error(g_strdup_printf("Cannot parse referenced file: %s", error));
        }
        g_free(file);

        protocol_dissector *dissector = make_protocol_dissector(json, dissectors, protocol_version, NULL, false);
        wmem_map_insert(dissectors, g_strdup(ref), dissector);
        return dissector;
    } else {
        return wmem_map_lookup(dissectors, ref);
    }
}

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(codec) {
    cJSON *ref_node = cJSON_GetArrayItem(params, 1);
    if (!cJSON_IsString(ref_node)) return make_error("Codec param needs to be a string");
    gchar *ref = ref_node->valuestring;

    if (!wmem_map_contains(dissectors, ref)) {
        gchar *file = build_indexed_file_name("codec", ref, protocol_version);

        gchar *content = NULL;
        if (!g_file_get_contents(file, &content, NULL, NULL)) {
            ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot read file %s", file);
            g_free(file);
            return make_error("Cannot read codec file");
        }

        cJSON *json = cJSON_Parse(content);
        g_free(content);
        if (json == NULL) {
            const gchar *error = cJSON_GetErrorPtr();
            ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot parse file %s: %s", file, error);
            g_free(file);
            return make_error(g_strdup_printf("Cannot parse codec file: %s", error));
        }
        g_free(file);

        if (!cJSON_IsArray(json)) {
            cJSON_free(json);
            return make_error("Codec file is not an array");
        }

        int count = cJSON_GetArraySize(json);
        protocol_dissector **dissector_list = wmem_alloc(wmem_epan_scope(), sizeof(protocol_dissector *) * count);
        for (int i = 0; i < count; i++) {
            cJSON *dissector_root = cJSON_GetArrayItem(json, i);
            protocol_dissector *sub = make_protocol_dissector(dissector_root, dissectors, protocol_version, NULL, true);
            dissector_list[i] = sub;
        }
        cJSON_free(json);

        protocol_dissector *this_dissector = wmem_alloc(wmem_epan_scope(), sizeof(protocol_dissector));
        this_dissector->dissect_arguments = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
        wmem_map_insert(this_dissector->dissect_arguments, "d", dissector_list);
        wmem_map_insert(this_dissector->dissect_arguments, "n", g_strdup(ref));
        wmem_map_insert(this_dissector->dissect_arguments, "c", (void *) (uint64_t) count);
        this_dissector->dissect_protocol = dissect_registry;
        this_dissector->destroy = destroy_registry;
        wmem_map_insert(dissectors, ref, this_dissector);
        return this_dissector;
    } else {
        return wmem_map_lookup(dissectors, ref);
    }
}

#define FUNC_PROTOCOL(name, func) if (strcmp(ref, #name) == 0) this_dissector->dissect_protocol = func;

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(func) {
    cJSON *ref_node = cJSON_GetArrayItem(params, 1);
    if (!cJSON_IsString(ref_node)) return make_error("Func name needs to be a string");
    gchar *ref = ref_node->valuestring;

    protocol_dissector *this_dissector = wmem_alloc(wmem_epan_scope(), sizeof(protocol_dissector));
    this_dissector->dissect_arguments = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
    this_dissector->dissect_protocol = NULL;
    this_dissector->destroy = NULL;

    FUNC_PROTOCOL(sync_entity_data, dissect_sync_entity_data)
    FUNC_PROTOCOL(record_entity_id, dissect_record_entity_id)
    FUNC_PROTOCOL(record_entity_id_player, dissect_record_entity_id_player)
    FUNC_PROTOCOL(record_entity_id_experience_orb, dissect_record_entity_id_experience_orb)
    FUNC_PROTOCOL(record_entity_id_painting, dissect_record_entity_id_painting)

    if (this_dissector->dissect_protocol == NULL) {
        wmem_free(wmem_epan_scope(), this_dissector);
        return make_error("Unknown func type");
    }

    int count = cJSON_GetArraySize(params);
    for (int i = 2; i < count; i++) {
        cJSON *node = cJSON_GetArrayItem(params, i);
        if (!cJSON_IsString(node)) return make_error("Invalid func parameter");
        wmem_map_insert(this_dissector->dissect_arguments, (void *) (uint64_t) (i - 2), g_strdup(node->valuestring));
    }

    return this_dissector;
}

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(top_bit_set_terminated_array) {
    cJSON *object = cJSON_GetArrayItem(params, 1);
    if (!cJSON_IsObject(object)) return make_error("top_bit_set_terminated_array param needs to be a object");
    cJSON *type = cJSON_GetObjectItem(object, "type");
    if (type == NULL) return make_error("Lack of type for top_bit_set_terminated_array object");
    protocol_dissector *this_dissector = wmem_alloc(wmem_epan_scope(), sizeof(protocol_dissector));
    this_dissector->dissect_arguments = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    protocol_dissector *sub = make_protocol_dissector(type, dissectors, protocol_version, RECURSIVE_ROOT, true);
    wmem_map_insert(this_dissector->dissect_arguments, "d", sub);
    this_dissector->dissect_protocol = dissect_top_bit_set_terminated_array;
    this_dissector->destroy = NULL;
    return this_dissector;
}

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(entity_metadata_loop) {
    cJSON *object = cJSON_GetArrayItem(params, 1);
    if (!cJSON_IsObject(object)) return make_error("entity_metadata_loop param needs to be a object");
    cJSON *type = cJSON_GetObjectItem(object, "type");
    if (type == NULL) return make_error("Lack of type for entity_metadata_loop object");
    cJSON *end_val = cJSON_GetObjectItem(object, "endVal");
    if (end_val == NULL) return make_error("Lack of endVal for entity_metadata_loop object");
    if (!cJSON_IsNumber(end_val)) return make_error("Invalid endVal for entity_metadata_loop object");
    uint8_t end = (uint8_t) end_val->valuedouble;
    protocol_dissector *this_dissector = wmem_alloc(wmem_epan_scope(), sizeof(protocol_dissector));
    this_dissector->dissect_arguments = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    protocol_dissector *sub = make_protocol_dissector(type, dissectors, protocol_version, RECURSIVE_ROOT, true);
    wmem_map_insert(this_dissector->dissect_arguments, "d", sub);
    wmem_map_insert(this_dissector->dissect_arguments, "e", (void *) (uint64_t) end);
    this_dissector->dissect_protocol = dissect_entity_metadata_loop;
    this_dissector->destroy = NULL;
    return this_dissector;
}

// PROTOCOL PARSER -----------------------------------------------------------------------------------------------------

// NOLINTNEXTLINE
protocol_dissector *make_protocol_dissector(
        cJSON *root, wmem_map_t *dissectors, uint32_t protocol_version, protocol_dissector *recursive_root,
        bool put_dissectors
) {
    bool composite_type = cJSON_IsArray(root);
    if (!composite_type && !cJSON_IsString(root)) return make_error("Invalid protocol dissector type");
    gchar *type = composite_type ? cJSON_GetArrayItem(root, 0)->valuestring : root->valuestring;
    int args = composite_type ? cJSON_GetArraySize(root) - 1 : 0;

    SIMPLE_PROTOCOL(i8, dissect_i8)
    SIMPLE_PROTOCOL(i16, dissect_i16)
    SIMPLE_PROTOCOL(i32, dissect_i32)
    SIMPLE_PROTOCOL(i64, dissect_i64)
    SIMPLE_PROTOCOL(u8, dissect_u8)
    SIMPLE_PROTOCOL(u16, dissect_u16)
    SIMPLE_PROTOCOL(u32, dissect_u32)
    SIMPLE_PROTOCOL(u64, dissect_u64)
    SIMPLE_PROTOCOL(u8_hex, dissect_h8)
    SIMPLE_PROTOCOL(u16_hex, dissect_h16)
    SIMPLE_PROTOCOL(u32_hex, dissect_h32)
    SIMPLE_PROTOCOL(u64_hex, dissect_h64)
    SIMPLE_PROTOCOL(f32, dissect_f32)
    SIMPLE_PROTOCOL(f64, dissect_f64)
    SIMPLE_PROTOCOL(varint, dissect_varint)
    SIMPLE_PROTOCOL(varlong, dissect_varlong)
    SIMPLE_PROTOCOL(void, dissect_void)
    SIMPLE_PROTOCOL(bool, dissect_bool)
    SIMPLE_PROTOCOL(string, dissect_string)
    SIMPLE_PROTOCOL(buffer, dissect_buffer)
    SIMPLE_PROTOCOL(rest_buffer, dissect_rest_buffer)
    SIMPLE_PROTOCOL(uuid, dissect_uuid)
    SIMPLE_PROTOCOL(nbt, dissect_nbt)
    SIMPLE_PROTOCOL(optional_nbt, dissect_optional_nbt)

    if (strcmp(type, "recursive") == 0 && !composite_type && recursive_root) return recursive_root;

    COMPOSITE_PROTOCOL(container, 1)
    COMPOSITE_PROTOCOL(array, 1)
    COMPOSITE_PROTOCOL(option, 1)
    COMPOSITE_PROTOCOL(mapper, 1)
    COMPOSITE_PROTOCOL(switch, 1)
    COMPOSITE_PROTOCOL(bitfield, 1)
    COMPOSITE_PROTOCOL(save, 2)
    COMPOSITE_PROTOCOL(global_save, 2)
    COMPOSITE_PROTOCOL(registry, 1)

    if (strcmp(type, "reference") == 0 && composite_type && args == 1)
        return make_reference(root, dissectors, protocol_version, recursive_root);
    if (strcmp(type, "codec") == 0 && composite_type && args == 1)
        return make_codec(root, dissectors, protocol_version, recursive_root);
    if (strcmp(type, "func") == 0 && composite_type)
        return make_func(root, dissectors, protocol_version, recursive_root);

    return make_error(
            g_strdup_printf("Invalid protocol dissector type: %s%s", type, composite_type ? " (composite)" : "")
    );
}

void make_state_protocol(cJSON *root, protocol_dissector_set *set, uint32_t state) {
    int count = cJSON_GetArraySize(root);
    protocol_dissector **dissectors = wmem_alloc(wmem_epan_scope(), sizeof(protocol_dissector *) * count);
    gchar **keys = wmem_alloc(wmem_epan_scope(), sizeof(gchar *) * count);
    gchar **names = wmem_alloc(wmem_epan_scope(), sizeof(gchar *) * count);
    wmem_map_t *state_switch = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
    wmem_map_t *state_side = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
    wmem_map_t *special_mark = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
    wmem_map_insert(set->dissectors_by_state, (void *) (uint64_t) state, dissectors);
    wmem_map_insert(set->count_by_state, (void *) (uint64_t) state, (void *) (uint64_t) count);
    wmem_map_insert(set->registry_keys, (void *) (uint64_t) state, keys);
    wmem_map_insert(set->readable_names, (void *) (uint64_t) state, names);
    wmem_map_insert(set->state_to_next, (void *) (uint64_t) state, state_switch);
    wmem_map_insert(set->state_to_next_side, (void *) (uint64_t) state, state_side);
    wmem_map_insert(set->special_mark, (void *) (uint64_t) state, special_mark);

    protocol_dissector *void_dissector;
    if (wmem_map_contains(set->dissectors_by_name, "void"))
        void_dissector = wmem_map_lookup(set->dissectors_by_name, "void");
    else {
        void_dissector = make_void();
        wmem_map_insert(set->dissectors_by_name, "void", void_dissector);
    }

    for (int i = 0; i < count; i++) {
        dissectors[i] = void_dissector;
        keys[i] = "<unknown>";
        names[i] = "<unknown>";
        cJSON *dissector_data = cJSON_GetArrayItem(root, i);
        if (!cJSON_HasObjectItem(dissector_data, "key")) continue;
        if (!cJSON_HasObjectItem(dissector_data, "name")) continue;
        gchar *key = cJSON_GetObjectItem(dissector_data, "key")->valuestring;
        gchar *name = cJSON_GetObjectItem(dissector_data, "name")->valuestring;
        cJSON *type = cJSON_GetObjectItem(dissector_data, "type");
        protocol_dissector *dissector;
        if (type == NULL) {
            gchar *file_key = g_strdup_printf("%s_%s", map_state_to_name(state), key);
            type = get_packet_source(set->protocol_version, file_key);
            g_free(file_key);
        }
        if (type == NULL)
            dissector = make_error("Cannot find packet file");
        else
            dissector = make_protocol_dissector(
                    type, set->dissectors_by_name, set->protocol_version, NULL, true
            );
        dissectors[i] = dissector;
        keys[i] = g_strdup(key);
        names[i] = g_strdup(name);
        if (cJSON_HasObjectItem(dissector_data, "stateNext")) {
            cJSON *state_to_next = cJSON_GetObjectItem(dissector_data, "stateNext");
            if (!cJSON_IsString(state_to_next)) continue;
            uint32_t next_state = map_name_to_state(state_to_next->valuestring) & 0xF;
            if (next_state == ~0u) continue;
            wmem_map_insert(state_switch, (void *) (uint64_t) i, (void *) (uint64_t) next_state);
            cJSON *state_side_node = cJSON_GetObjectItem(dissector_data, "stateSide");
            if (!cJSON_IsString(state_side_node)) continue;
            gchar *side = state_side_node->valuestring;
            uint32_t side_int = 0;
            if (strcmp(side, "client") == 0) side_int = 1;
            if (strcmp(side, "server") == 0) side_int = 2;
            if (strcmp(side, "all") == 0) side_int = 3;
            wmem_map_insert(state_side, (void *) (uint64_t) i, (void *) (uint64_t) side_int);
        }
        if (cJSON_HasObjectItem(dissector_data, "specialMark")) {
            cJSON *mark = cJSON_GetObjectItem(dissector_data, "specialMark");
            if (!cJSON_IsString(mark)) continue;
            wmem_map_insert(special_mark, (void *) (uint64_t) i, g_strdup(mark->valuestring));
        }
    }
}

uint32_t map_name_to_state(gchar *name) {
    if (strcmp(name, "play") == 0) return PLAY;
    if (strcmp(name, "play_client") == 0) return PLAY;
    if (strcmp(name, "play_server") == 0) return 16 + PLAY;
    if (strcmp(name, "login") == 0) return LOGIN;
    if (strcmp(name, "login_client") == 0) return LOGIN;
    if (strcmp(name, "login_server") == 0) return 16 + LOGIN;
    if (strcmp(name, "configuration") == 0) return CONFIGURATION;
    if (strcmp(name, "configuration_client") == 0) return CONFIGURATION;
    if (strcmp(name, "configuration_server") == 0) return 16 + CONFIGURATION;
    return ~0u;
}

gchar *map_state_to_name(uint32_t state) {
    switch (state) {
        case PLAY:
            return "play_client";
        case PLAY + 16:
            return "play_server";
        case LOGIN:
            return "login_client";
        case LOGIN + 16:
            return "login_server";
        case CONFIGURATION:
            return "configuration_client";
        case CONFIGURATION + 16:
            return "configuration_server";
        default:
            return "<unknown>";
    }
}

protocol_dissector_set *create_protocol(uint32_t protocol_version) {
    cJSON *protocol_source = get_protocol_source(protocol_version);
    if (protocol_source == NULL) return NULL;
    protocol_dissector_set *set = wmem_alloc(wmem_epan_scope(), sizeof(protocol_dissector_set));
    set->protocol_version = protocol_version;
    set->dissectors_by_name = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    set->dissectors_by_state = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
    set->count_by_state = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
    set->registry_keys = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
    set->readable_names = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
    set->state_to_next = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
    set->state_to_next_side = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
    set->special_mark = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
    cJSON *now = protocol_source->child;
    while (now != NULL) {
        uint32_t state = map_name_to_state(now->string);
        if (state != ~0u) make_state_protocol(now, set, state);
        now = now->next;
    }
    return set;
}