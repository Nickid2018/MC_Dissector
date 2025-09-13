//
// Created by nickid2018 on 24-9-14.
//

#include "schema.h"
#include "protocol/protocol_data.h"
#include "utils/nbt.h"
#include "functions.h"
#include <errno.h>
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

extern char *pref_protocol_data_dir;

void destroy_protocol(protocol_dissector_set *dissector_set) {
    wmem_destroy_allocator(dissector_set->allocator);
    dissector_set->valid = false;
}

// PROTOCOL SUB-DISSECTORS ---------------------------------------------------------------------------------------------

#define DISSECT_PROTOCOL(fn) \
int32_t dissect_##fn(           \
    proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset, wmem_allocator_t *packet_alloc, \
    protocol_dissector *dissector, char *name, wmem_map_t *packet_saves, char **value \
)

// SMALL UTILITY FUNCTIONS ---------------------------------------------------------------------------------------------

void add_name(proto_item *item, char *name) {
    proto_item_prepend_text(item, "%s ", name);
}

int32_t add_invalid_data(proto_tree *tree, tvbuff_t *tvb, int offset, char *name, char *value) {
    if (tree) add_name(proto_tree_add_string(tree, hf_invalid_data, tvb, offset, 0, value), name);
    return DISSECT_ERROR;
}

// INTEGER SUB-DISSECTORS ----------------------------------------------------------------------------------------------

DISSECT_PROTOCOL(i8) {
    int8_t i8 = tvb_get_int8(tvb, offset);
    if (value) *value = wmem_strdup_printf(packet_alloc, "%d", i8);
    if (tree) add_name(proto_tree_add_int(tree, hf_int8, tvb, offset, 1, i8), name);
    return 1;
}

DISSECT_PROTOCOL(i16) {
    int16_t i16 = tvb_get_int16(tvb, offset, ENC_BIG_ENDIAN);
    if (value) *value = wmem_strdup_printf(packet_alloc, "%d", i16);
    if (tree) add_name(proto_tree_add_int(tree, hf_int16, tvb, offset, 2, i16), name);
    return 2;
}

DISSECT_PROTOCOL(i32) {
    int32_t i32 = tvb_get_int32(tvb, offset, ENC_BIG_ENDIAN);
    if (value) *value = wmem_strdup_printf(packet_alloc, "%d", i32);
    if (tree) add_name(proto_tree_add_int(tree, hf_int32, tvb, offset, 4, i32), name);
    return 4;
}

DISSECT_PROTOCOL(i64) {
    int64_t i64 = tvb_get_int64(tvb, offset, ENC_BIG_ENDIAN);
    if (value) *value = wmem_strdup_printf(packet_alloc, "%ld", i64);
    if (tree) add_name(proto_tree_add_int64(tree, hf_int64, tvb, offset, 8, i64), name);
    return 8;
}

DISSECT_PROTOCOL(u8) {
    uint8_t u8 = tvb_get_uint8(tvb, offset);
    if (value) *value = wmem_strdup_printf(packet_alloc, "%u", u8);
    if (tree) add_name(proto_tree_add_uint(tree, hf_uint8, tvb, offset, 1, u8), name);
    return 1;
}

DISSECT_PROTOCOL(u16) {
    uint16_t u16 = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
    if (value) *value = wmem_strdup_printf(packet_alloc, "%u", u16);
    if (tree) add_name(proto_tree_add_uint(tree, hf_uint16, tvb, offset, 2, u16), name);
    return 2;
}

DISSECT_PROTOCOL(u32) {
    uint32_t u32 = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
    if (value) *value = wmem_strdup_printf(packet_alloc, "%u", u32);
    if (tree) add_name(proto_tree_add_uint(tree, hf_uint32, tvb, offset, 4, u32), name);
    return 4;
}

DISSECT_PROTOCOL(u64) {
    uint64_t u64 = tvb_get_uint64(tvb, offset, ENC_BIG_ENDIAN);
    if (value) *value = wmem_strdup_printf(packet_alloc, "%lu", u64);
    if (tree) add_name(proto_tree_add_uint64(tree, hf_uint64, tvb, offset, 8, u64), name);
    return 8;
}

DISSECT_PROTOCOL(h8) {
    uint8_t u8 = tvb_get_uint8(tvb, offset);
    if (value) *value = wmem_strdup_printf(packet_alloc, "%u", u8);
    if (tree) add_name(proto_tree_add_uint(tree, hf_hint8, tvb, offset, 1, u8), name);
    return 1;
}

DISSECT_PROTOCOL(h16) {
    uint16_t u16 = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
    if (value) *value = wmem_strdup_printf(packet_alloc, "%u", u16);
    if (tree) add_name(proto_tree_add_uint(tree, hf_hint16, tvb, offset, 2, u16), name);
    return 2;
}

DISSECT_PROTOCOL(h32) {
    uint32_t u32 = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
    if (value) *value = wmem_strdup_printf(packet_alloc, "%u", u32);
    if (tree) add_name(proto_tree_add_uint(tree, hf_hint32, tvb, offset, 4, u32), name);
    return 4;
}

DISSECT_PROTOCOL(h64) {
    uint64_t u64 = tvb_get_uint64(tvb, offset, ENC_BIG_ENDIAN);
    if (value) *value = wmem_strdup_printf(packet_alloc, "%lu", u64);
    if (tree) add_name(proto_tree_add_uint64(tree, hf_hint64, tvb, offset, 8, u64), name);
    return 8;
}

DISSECT_PROTOCOL(varint) {
    int32_t result;
    int32_t length = read_var_int(tvb, offset, &result);
    if (length < 0) return add_invalid_data(tree, tvb, offset, name, "Invalid VarInt");
    if (value) *value = wmem_strdup_printf(packet_alloc, "%d", result);
    if (tree) add_name(proto_tree_add_int(tree, hf_varint, tvb, offset, length, result), name);
    return length;
}

DISSECT_PROTOCOL(varlong) {
    int64_t result;
    int32_t length = read_var_long(tvb, offset, &result);
    if (length < 0) return add_invalid_data(tree, tvb, offset, name, "Invalid VarLong");
    if (value) *value = wmem_strdup_printf(packet_alloc, "%ld", result);
    if (tree) add_name(proto_tree_add_int64(tree, hf_varlong, tvb, offset, length, result), name);
    return length;
}

// FLOAT POINTER NUMBER SUB-DISSECTORS ---------------------------------------------------------------------------------

DISSECT_PROTOCOL(f32) {
    float f32 = tvb_get_ieee_float(tvb, offset, ENC_BIG_ENDIAN);
    if (value) *value = wmem_strdup_printf(packet_alloc, "%f", f32);
    if (tree) add_name(proto_tree_add_float(tree, hf_float, tvb, offset, 4, f32), name);
    return 4;
}

DISSECT_PROTOCOL(f64) {
    double f64 = tvb_get_ieee_double(tvb, offset, ENC_BIG_ENDIAN);
    if (value) *value = wmem_strdup_printf(packet_alloc, "%f", f64);
    if (tree) add_name(proto_tree_add_double(tree, hf_double, tvb, offset, 8, f64), name);
    return 8;
}

// OTHER SIMPLE SUB-DISSECTORS -----------------------------------------------------------------------------------------

DISSECT_PROTOCOL(void) {
    return 0;
}

DISSECT_PROTOCOL(bool) {
    bool boolean = tvb_get_uint8(tvb, offset);
    if (value) *value = boolean ? "true" : "false";
    if (tree) add_name(proto_tree_add_boolean(tree, hf_boolean, tvb, offset, 1, boolean), name);
    return 1;
}

DISSECT_PROTOCOL(string) {
    int32_t len;
    int32_t length = read_var_int(tvb, offset, &len);
    if (length < 0) return add_invalid_data(tree, tvb, offset, name, "Invalid String");
    char *print = tvb_format_text(pinfo->pool, tvb, offset + length, len);
    if (value) *value = wmem_strdup(packet_alloc, print);
    if (tree) add_name(proto_tree_add_string(tree, hf_string, tvb, offset, len + length, print), name);
    return length + len;
}

DISSECT_PROTOCOL(buffer) {
    int32_t buffer_len;
    int32_t length = read_var_int(tvb, offset, &buffer_len);
    if (length < 0) return add_invalid_data(tree, tvb, offset, name, "Invalid Buffer");
    if (tree) {
        uint8_t *buffer = tvb_memdup(pinfo->pool, tvb, offset + length, buffer_len > 200 ? 200 : buffer_len);
        add_name(proto_tree_add_bytes(tree, hf_bytes, tvb, offset + length, buffer_len, buffer), name);
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
    if (value) *value = (char *) guids_resolve_guid_to_str(uuid, packet_alloc);
    if (tree) add_name(proto_tree_add_guid(tree, hf_uuid, tvb, offset, 16, uuid), name);
    return 16;
}

DISSECT_PROTOCOL(nbt) {
    bool is_new_nbt = wmem_map_lookup(get_global_data(pinfo), "nbt_any_type");

    int present = tvb_get_uint8(tvb, offset);
    if (!present) {
        if (tree) {
            proto_item *text = proto_tree_add_boolean(tree, hf_boolean, tvb, offset, 1, false);
            proto_item_set_text(text, "%s [optional nbt]: Not present", name);
        }
        return 1;
    }
    if (tree && pref_do_nbt_decode) return do_nbt_tree(tree, pinfo, tvb, offset, name, !is_new_nbt);

    int32_t len = is_new_nbt ? 1 : 0;
    int32_t len_nbt;
    if (is_new_nbt) len_nbt = count_nbt_length_with_type(tvb, offset + 1, present);
    else len_nbt = count_nbt_length(tvb, offset);
    if (tree)
        add_name(proto_tree_add_bytes(
                     tree, hf_bytes, tvb, offset + len, len_nbt,
                     tvb_memdup(pinfo->pool, tvb, offset + len, len_nbt > 200 ? 200 : len_nbt)
                 ), name);

    return len + len_nbt;
}

// COMPOSITE SUB-DISSECTORS --------------------------------------------------------------------------------------------

DISSECT_PROTOCOL(error) {
    char *error_message = wmem_map_lookup(dissector->dissect_arguments, "e");
    if (tree)
        add_name(proto_tree_add_string_format_value(
                     tree, hf_parsing_error, tvb, offset, 0,
                     "", "The protocol dissector failed to parse: %s",
                     error_message
                 ), name);
    return DISSECT_ERROR;
}

typedef struct name_and_dissector_struct {
    char *name;
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
            tree, pinfo, tvb, offset + total, packet_alloc,
            sub_dissector->dissector, sub_dissector->name, packet_saves, NULL
        );
        if (len == DISSECT_ERROR) return DISSECT_ERROR;
        total += len;
    }
    if (tree) proto_item_set_len(tree, total);
    return total;
}

DISSECT_PROTOCOL(array) {
    protocol_dissector *sub_dissector = wmem_map_lookup(dissector->dissect_arguments, "d");
    char *search_key = wmem_map_lookup(dissector->dissect_arguments, "k");
    protocol_dissector *get_count_dissector = wmem_map_lookup(dissector->dissect_arguments, "c");

    int64_t parsed_count = 0;
    int32_t total = 0;
    if (search_key) {
        char *searched_value = wmem_map_lookup(packet_saves, search_key);
        if (!searched_value) searched_value = search_key;
        char *end;
        errno = 0;
        parsed_count = strtoll(searched_value, &end, 10);
        if (errno == ERANGE) return add_invalid_data(tree, tvb, offset, name, "Array size is too large");
        if (searched_value == end) return add_invalid_data(tree, tvb, offset, name, "Invalid array size string");
    } else {
        char *saved_value;
        int32_t len = get_count_dissector->dissect_protocol(
            NULL, pinfo, tvb, offset, packet_alloc, get_count_dissector, "", packet_saves, &saved_value
        );
        if (len == DISSECT_ERROR) return DISSECT_ERROR;
        if (!saved_value)
            return add_invalid_data(tree, tvb, offset, name, "Can't receive value from source, protocol has error?");
        char *end;
        errno = 0;
        parsed_count = strtoll(saved_value, &end, 10);
        if (errno == ERANGE) return add_invalid_data(tree, tvb, offset, name, "Array size is too large");
        if (saved_value == end) return add_invalid_data(tree, tvb, offset, name, "Invalid array size string");
        total += len;
    }

    if (wmem_map_contains(dissector->dissect_arguments, "o")) {
        char *offset_count = wmem_map_lookup(dissector->dissect_arguments, "o");
        char *end;
        int64_t offset_number = strtoll(offset_count, &end, 10);
        parsed_count += offset_number;
    }

    if (tree)
        tree = proto_tree_add_subtree_format(
            tree, tvb, offset, 0, ett_mc, NULL, "%s (%ld entries)", name, parsed_count
        );
    for (int i = 0; i < parsed_count; i++) {
        char *name_format = wmem_strdup_printf(wmem_file_scope(), "%s[%d]", name, i);
        int32_t len = sub_dissector->dissect_protocol(
            tree, pinfo, tvb, offset + total, packet_alloc, sub_dissector, name_format, packet_saves, NULL
        );
        if (len == DISSECT_ERROR) return DISSECT_ERROR;
        total += len;
    }
    if (tree) proto_item_set_len(tree, total);

    return total;
}

DISSECT_PROTOCOL(option) {
    bool is_present = tvb_get_uint8(tvb, offset) != 0;
    if (!is_present) return 1;
    protocol_dissector *sub_dissector = wmem_map_lookup(dissector->dissect_arguments, "d");
    int32_t len = sub_dissector->dissect_protocol(
        tree, pinfo, tvb, offset + 1, packet_alloc, sub_dissector, name, packet_saves, value
    );
    if (len == DISSECT_ERROR) return DISSECT_ERROR;
    return len + 1;
}

DISSECT_PROTOCOL(mapper) {
    protocol_dissector *sub_dissector = wmem_map_lookup(dissector->dissect_arguments, "d");
    char *saved_value = NULL;
    int32_t len;
    if (sub_dissector != NULL) {
        len = sub_dissector->dissect_protocol(
            NULL, pinfo, tvb, offset, packet_alloc, sub_dissector, name, packet_saves, &saved_value
        );
        if (len == DISSECT_ERROR) return DISSECT_ERROR;
    } else {
        char *search_key = wmem_map_lookup(dissector->dissect_arguments, "v");
        saved_value = wmem_map_lookup(packet_saves, search_key);
        if (saved_value == NULL)
            return add_invalid_data(tree, tvb, offset, name, "No value found, protocol has error?");
        len = 0;
    }
    if (!saved_value)
        return add_invalid_data(tree, tvb, offset, name, "Can't receive value from source, protocol has error?");
    wmem_map_t *mapper = wmem_map_lookup(dissector->dissect_arguments, "m");
    char *mapped = wmem_map_lookup(mapper, saved_value);
    if (!mapped) mapped = wmem_strdup(wmem_file_scope(), saved_value);
    if (value) *value = wmem_strdup(packet_alloc, mapped);
    if (tree)
        add_name(proto_tree_add_string_format_value(
                     tree, hf_string, tvb, offset, len,
                     mapped, "%s (%s)", mapped, saved_value
                 ), name);
    return len;
}

DISSECT_PROTOCOL(switch) {
    char *key = wmem_map_lookup(dissector->dissect_arguments, "k");
    char *searched_value = wmem_map_lookup(packet_saves, key);
    if (!searched_value) return add_invalid_data(tree, tvb, offset, name, "Context has no specific key");
    wmem_map_t *mapper = wmem_map_lookup(dissector->dissect_arguments, "m");
    protocol_dissector *mapped = wmem_map_lookup(mapper, searched_value);
    if (!mapped) mapped = wmem_map_lookup(dissector->dissect_arguments, "d");
    if (!mapped) return add_invalid_data(tree, tvb, offset, name, "No compatible dissector found");
    return mapped->dissect_protocol(tree, pinfo, tvb, offset, packet_alloc, mapped, name, packet_saves, value);
}

typedef struct bit_field_struct {
    char *name;
    char *save_name;
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
                    wmem_strdup_printf(
                        packet_alloc,
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

DISSECT_PROTOCOL(save) {
    protocol_dissector *sub_dissector = wmem_map_lookup(dissector->dissect_arguments, "d");
    char *save_name = wmem_map_lookup(dissector->dissect_arguments, "s");
    char *saved_value;
    int32_t len = sub_dissector->dissect_protocol(
        tree, pinfo, tvb, offset, packet_alloc, sub_dissector, name, packet_saves, &saved_value
    );
    if (len == DISSECT_ERROR) return DISSECT_ERROR;
    wmem_map_insert(packet_saves, save_name, saved_value);
    return len;
}

DISSECT_PROTOCOL(global_save) {
    protocol_dissector *sub_dissector = wmem_map_lookup(dissector->dissect_arguments, "d");
    char *save_name = wmem_map_lookup(dissector->dissect_arguments, "s");
    char *saved_value;
    int32_t len = sub_dissector->dissect_protocol(
        tree, pinfo, tvb, offset, packet_alloc, sub_dissector, name, packet_saves, &saved_value
    );
    if (len == DISSECT_ERROR) return DISSECT_ERROR;
    wmem_map_t *global_data = get_global_data(pinfo);
    if (!wmem_map_contains(global_data, save_name))
        wmem_map_insert(global_data, save_name, saved_value);
    return len;
}

DISSECT_PROTOCOL(registry) {
    char *registry_name = wmem_map_lookup(dissector->dissect_arguments, "n");
    wmem_map_t *writable_registry = wmem_map_lookup(get_global_data(pinfo), "#writable_registry");
    wmem_map_t *writable_registry_size = wmem_map_lookup(get_global_data(pinfo), "#writable_registry_size");
    int32_t index;
    int32_t len = read_var_int(tvb, offset, &index);
    char *key;
    if (wmem_map_contains(dissector->dissect_arguments, "o")) {
        char *offset_count = wmem_map_lookup(dissector->dissect_arguments, "o");
        char *end;
        int64_t offset_number = strtoll(offset_count, &end, 10);
        index += (int32_t) offset_number;
    }
    if (writable_registry != NULL && wmem_map_contains(writable_registry, registry_name)) {
        char **data = wmem_map_lookup(writable_registry, registry_name);
        uint64_t count = (uint64_t) wmem_map_lookup(writable_registry_size, registry_name);
        if (index >= count || index < 0) {
            key = "<Unknown Registry Entry>";
        } else {
            key = data[index];
        }
    } else {
        uint32_t protocol_version = (uint64_t) wmem_map_lookup(get_global_data(pinfo), "protocol_version");
        key = index < 0 ? "<Unknown Registry Entry>" : get_registry_data(protocol_version, registry_name, index);
    }
    if (value) *value = wmem_strdup(packet_alloc, key);
    if (tree)
        add_name(proto_tree_add_string_format_value(
                     tree, hf_string, tvb, offset, len,
                     key, "%s (%d)", key, index
                 ), name);
    return len;
}

DISSECT_PROTOCOL(codec) {
    wmem_map_t *map = wmem_map_lookup(dissector->dissect_arguments, "d");
    char *search_key = wmem_map_lookup(dissector->dissect_arguments, "k");
    char *key = wmem_map_lookup(packet_saves, search_key);
    if (key == NULL) return add_invalid_data(tree, tvb, offset, name, "No value found, protocol has error?");
    protocol_dissector *sub = wmem_map_lookup(map, key);
    if (sub == NULL) {
        int64_t length = g_utf8_strlen(key, 400);
        int64_t split_pos = length - 1;
        for (; split_pos >= 0; split_pos--)
            if (key[split_pos] == '/' || key[split_pos] == ':')
                break;
        key = g_utf8_substring(key, split_pos + 1, length);
        sub = wmem_map_lookup(map, key);
    }
    if (sub == NULL) return add_invalid_data(tree, tvb, offset, name, "No codec found");
    return sub->dissect_protocol(tree, pinfo, tvb, offset, packet_alloc, sub, name, packet_saves, value);
}

DISSECT_PROTOCOL(top_bit_set_terminated_array) {
    uint8_t now;
    int32_t len = 0;
    protocol_dissector *sub_dissector = wmem_map_lookup(dissector->dissect_arguments, "d");
    if (tree) tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_mc, NULL, name);
    bool do_loop = true;
    while (do_loop) {
        now = tvb_get_uint8(tvb, offset + len);
        do_loop = (now & 0x80) != 0;
        uint32_t ord = now & 0x7F;
        int32_t sub_len = sub_dissector->dissect_protocol(
            tree, pinfo, tvb, offset + len, packet_alloc,
            sub_dissector, wmem_strdup_printf(wmem_file_scope(), "%s[%d]", name, ord), packet_saves, NULL
        );
        if (sub_len == DISSECT_ERROR) return DISSECT_ERROR;
        len += sub_len;
    }
    if (tree) proto_item_set_len(tree, len);
    return len;
}

DISSECT_PROTOCOL(entity_metadata_loop) {
    uint8_t end_val = (uint64_t) wmem_map_lookup(dissector->dissect_arguments, "e");
    protocol_dissector *sub_dissector = wmem_map_lookup(dissector->dissect_arguments, "d");
    if (tree) tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_mc, NULL, name);
    int32_t len = 0;
    int ord = 0;
    while (tvb_get_uint8(tvb, offset + len) != end_val) {
        int32_t sub_len = sub_dissector->dissect_protocol(
            tree, pinfo, tvb, offset + len, packet_alloc,
            sub_dissector, wmem_strdup_printf(wmem_file_scope(), "%s[%d]", name, ord), packet_saves, NULL
        );
        if (sub_len == DISSECT_ERROR) return DISSECT_ERROR;
        len += sub_len;
        ord++;
    }
    if (tree) proto_item_set_len(tree, len + 1);
    return len + 1;
}

DISSECT_PROTOCOL(fix_buffer) {
    int32_t buffer_len = (int32_t) (uint64_t) wmem_map_lookup(dissector->dissect_arguments, "s");
    if (tree) {
        uint8_t *buffer = tvb_memdup(pinfo->pool, tvb, offset, buffer_len > 200 ? 200 : buffer_len);
        add_name(proto_tree_add_bytes(tree, hf_bytes, tvb, offset, buffer_len, buffer), name);
    }
    return buffer_len;
}

// PARSING PROTOCOL SCHEMA ---------------------------------------------------------------------------------------------

protocol_dissector *make_protocol_dissector(
    wmem_allocator_t *allocator, cJSON *root, wmem_map_t *dissectors, uint32_t protocol_version,
    protocol_dissector *recursive_root
);

// PARSERS -------------------------------------------------------------------------------------------------------------

protocol_dissector *make_void(wmem_allocator_t *allocator) {
    protocol_dissector *simple_dissector = wmem_alloc(allocator, sizeof(protocol_dissector));
    simple_dissector->dissect_arguments = NULL;
    simple_dissector->dissect_protocol = dissect_void;
    return simple_dissector;
}

protocol_dissector *make_error(wmem_allocator_t *allocator, char *error_message) {
    protocol_dissector *error_dissector = wmem_alloc(allocator, sizeof(protocol_dissector));
    error_dissector->dissect_arguments = wmem_map_new(allocator, g_str_hash, g_str_equal);
    wmem_map_insert(error_dissector->dissect_arguments, "e", error_message);
    error_dissector->dissect_protocol = dissect_error;
    return error_dissector;
}

#define SIMPLE_PROTOCOL(name, func) \
if (strcmp(type, #name) == 0) { \
    if (wmem_map_contains(dissectors, #name)) return wmem_map_lookup(dissectors, #name); \
    protocol_dissector *dissector = make_simple(allocator, func); \
    wmem_map_insert(dissectors, #name, dissector); \
    return dissector; \
}

protocol_dissector *make_simple(wmem_allocator_t *allocator, DISSECT_FUNCTION_SIG(func)) {
    protocol_dissector *simple_dissector = wmem_alloc(allocator, sizeof(protocol_dissector));
    simple_dissector->dissect_arguments = NULL;
    simple_dissector->dissect_protocol = func;
    return simple_dissector;
}

#define COMPOSITE_PROTOCOL_DEFINE(fn) \
protocol_dissector *make_##fn(wmem_allocator_t *allocator, cJSON *params, wmem_map_t *dissectors, uint32_t protocol_version, protocol_dissector *recursive_root)
#define COMPOSITE_PROTOCOL(name, count) \
if (strcmp(type, #name) == 0 && args == count && composite_type) { \
    return make_##name(allocator, root, dissectors, protocol_version, recursive_root); \
}
#define RECURSIVE_ROOT recursive_root == NULL ? this_dissector : recursive_root

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(container) {
    cJSON *list = cJSON_GetArrayItem(params, 1);
    if (!cJSON_IsArray(list)) return make_error(allocator, "Container param needs to be a list");
    int count = cJSON_GetArraySize(list);
    protocol_dissector *this_dissector = wmem_alloc(allocator, sizeof(protocol_dissector));
    name_and_dissector **sub_dissectors = wmem_alloc(allocator, sizeof(name_and_dissector *) * count);
    for (int i = 0; i < count; i++) {
        cJSON *node = cJSON_GetArrayItem(list, i);
        cJSON *name_node = cJSON_GetObjectItem(node, "name");
        if (name_node == NULL) return make_error(allocator, "Lack of name for container object");
        if (!cJSON_IsString(name_node)) return make_error(allocator, "Invalid name for container object");
        char *name = wmem_strdup(allocator, name_node->valuestring);
        cJSON *type = cJSON_GetObjectItem(node, "type");
        if (type == NULL) return make_error(allocator, "Lack of type for container object");
        protocol_dissector *sub_dissector = make_protocol_dissector(
            allocator, type, dissectors, protocol_version, RECURSIVE_ROOT
        );
        name_and_dissector *data = wmem_alloc(allocator, sizeof(name_and_dissector));
        data->name = name;
        data->dissector = sub_dissector;
        sub_dissectors[i] = data;
    }
    this_dissector->dissect_arguments = wmem_map_new(allocator, g_str_hash, g_str_equal);
    wmem_map_insert(this_dissector->dissect_arguments, "d", sub_dissectors);
    wmem_map_insert(this_dissector->dissect_arguments, "s", (void *) (uint64_t) count);
    this_dissector->dissect_protocol = dissect_container;
    return this_dissector;
}

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(array) {
    cJSON *object = cJSON_GetArrayItem(params, 1);
    if (!cJSON_IsObject(object)) return make_error(allocator, "Array param needs to be a object");
    cJSON *type = cJSON_GetObjectItem(object, "type");
    if (type == NULL) return make_error(allocator, "Lack of type for array object");
    cJSON *count_type = cJSON_GetObjectItem(object, "countType");
    cJSON *count = cJSON_GetObjectItem(object, "count");
    if (count == NULL && count_type == NULL) return make_error(allocator, "Lack of count/countType for array object");
    protocol_dissector *this_dissector = wmem_alloc(allocator, sizeof(protocol_dissector));
    this_dissector->dissect_arguments = wmem_map_new(allocator, g_str_hash, g_str_equal);
    protocol_dissector *sub_dissector = make_protocol_dissector(
        allocator, type, dissectors, protocol_version, RECURSIVE_ROOT
    );
    wmem_map_insert(this_dissector->dissect_arguments, "d", sub_dissector);
    if (count_type != NULL) {
        protocol_dissector *count_type_dissect = make_protocol_dissector(
            allocator, count_type, dissectors, protocol_version, RECURSIVE_ROOT
        );
        wmem_map_insert(this_dissector->dissect_arguments, "c", count_type_dissect);
    } else {
        bool is_string = cJSON_IsString(count);
        bool is_number = cJSON_IsNumber(count);
        if (!is_string && !is_number) return make_error(allocator, "Invalid count for array object");
        if (is_string)
            wmem_map_insert(this_dissector->dissect_arguments, "k", count->valuestring);
        if (is_number)
            wmem_map_insert(
                this_dissector->dissect_arguments, "k",
                wmem_strdup_printf(allocator, "%d", (int) count->valuedouble)
            );
    }
    if (cJSON_HasObjectItem(object, "offset")) {
        cJSON *offset = cJSON_GetObjectItem(object, "offset");
        if (!cJSON_IsString(offset)) return make_error(allocator, "Array offset needs to be a string");
        wmem_map_insert(this_dissector->dissect_arguments, "o", wmem_strdup(allocator, offset->valuestring));
    }
    this_dissector->dissect_protocol = dissect_array;
    return this_dissector;
}

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(option) {
    cJSON *type = cJSON_GetArrayItem(params, 1);
    protocol_dissector *this_dissector = wmem_alloc(allocator, sizeof(protocol_dissector));
    this_dissector->dissect_arguments = wmem_map_new(allocator, g_str_hash, g_str_equal);
    protocol_dissector *sub_dissector = make_protocol_dissector(
        allocator, type, dissectors, protocol_version, RECURSIVE_ROOT
    );
    wmem_map_insert(this_dissector->dissect_arguments, "d", sub_dissector);
    this_dissector->dissect_protocol = dissect_option;
    return this_dissector;
}

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(mapper) {
    cJSON *object = cJSON_GetArrayItem(params, 1);
    if (!cJSON_IsObject(object)) return make_error(allocator, "Mapper param needs to be a object");
    cJSON *type = cJSON_GetObjectItem(object, "type");
    cJSON *var = cJSON_GetObjectItem(object, "var");
    if (type == NULL && var == NULL) return make_error(allocator, "Lack of type and var for mapper object");
    cJSON *mappings = cJSON_GetObjectItem(object, "mappings");
    cJSON *source = cJSON_GetObjectItem(object, "source");
    if (mappings == NULL && source == NULL)
        return make_error(allocator, "Lack of mappings and source for mapper object");
    wmem_map_t *map = wmem_map_new(allocator, g_str_hash, g_str_equal);
    if (mappings != NULL) {
        if (!cJSON_IsObject(mappings)) return make_error(allocator, "Invalid mappings for mapper object");
        cJSON *node = mappings->child;
        while (node != NULL) {
            if (!cJSON_IsString(node)) {
                wmem_free(allocator, map);
                return make_error(allocator, "Invalid mapping entry for mapper object");
            }
            wmem_map_insert(map, wmem_strdup(allocator, node->string), wmem_strdup(allocator, node->valuestring));
            node = node->next;
        }
    } else {
        if (!cJSON_IsString(source)) return make_error(allocator, "Invalid source for mapper object");
        char *file = build_indexed_file_name("mappings", source->valuestring, protocol_version);
        char *content = NULL;
        if (!g_file_get_contents(file, &content, NULL, NULL)) {
            ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot read file %s", file);
            g_free(file);
            wmem_free(allocator, map);
            return make_error(allocator, "Cannot read mapping file");
        }
        cJSON *json = cJSON_Parse(content);
        g_free(content);
        if (json == NULL) {
            const char *error = cJSON_GetErrorPtr();
            ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot parse file %s: %s", file, error);
            g_free(file);
            wmem_free(allocator, map);
            return make_error(allocator, wmem_strdup_printf(allocator, "Cannot parse mapping file: %s", error));
        }
        g_free(file);
        if (!cJSON_IsObject(json)) {
            cJSON_free(json);
            wmem_free(allocator, map);
            return make_error(allocator, "Mapping file is not an object");
        }
        cJSON *now = json->child;
        while (now != NULL) {
            if (!cJSON_IsString(now)) {
                wmem_free(allocator, map);
                return make_error(allocator, "Invalid mapping");
            }
            wmem_map_insert(map, wmem_strdup(allocator, now->string), wmem_strdup(allocator, now->valuestring));
            now = now->next;
        }
        cJSON_free(json);
    }
    protocol_dissector *this_dissector = wmem_alloc(allocator, sizeof(protocol_dissector));
    this_dissector->dissect_arguments = wmem_map_new(allocator, g_str_hash, g_str_equal);
    if (type != NULL) {
        protocol_dissector *sub_dissector = make_protocol_dissector(
            allocator, type, dissectors, protocol_version, RECURSIVE_ROOT
        );
        wmem_map_insert(this_dissector->dissect_arguments, "d", sub_dissector);
    } else {
        wmem_map_insert(this_dissector->dissect_arguments, "v", wmem_strdup(allocator, var->valuestring));
    }
    wmem_map_insert(this_dissector->dissect_arguments, "m", map);
    this_dissector->dissect_protocol = dissect_mapper;
    return this_dissector;
}

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(switch) {
    cJSON *object = cJSON_GetArrayItem(params, 1);
    if (!cJSON_IsObject(object)) return make_error(allocator, "Switch param needs to be a object");
    cJSON *key = cJSON_GetObjectItem(object, "compareTo");
    if (key == NULL) return make_error(allocator, "Lack of compareTo for switch object");
    if (!cJSON_IsString(key)) return make_error(allocator, "Invalid compareTo for switch object");
    cJSON *fields = cJSON_GetObjectItem(object, "fields");
    if (fields == NULL) return make_error(allocator, "Lack of fields for switch object");
    if (!cJSON_IsObject(fields)) return make_error(allocator, "Invalid fields for switch object");
    protocol_dissector *this_dissector = wmem_alloc(allocator, sizeof(protocol_dissector));
    wmem_map_t *map = wmem_map_new(allocator, g_str_hash, g_str_equal);
    cJSON *node = fields->child;
    while (node != NULL) {
        protocol_dissector *sub_dissector = make_protocol_dissector(
            allocator, node, dissectors, protocol_version, RECURSIVE_ROOT
        );
        wmem_map_insert(map, wmem_strdup(allocator, node->string), sub_dissector);
        node = node->next;
    }
    this_dissector->dissect_arguments = wmem_map_new(allocator, g_str_hash, g_str_equal);
    wmem_map_insert(this_dissector->dissect_arguments, "k", wmem_strdup(allocator, key->valuestring));
    wmem_map_insert(this_dissector->dissect_arguments, "m", map);
    if (cJSON_HasObjectItem(object, "default")) {
        cJSON *def = cJSON_GetObjectItem(object, "default");
        protocol_dissector *sub_dissector = make_protocol_dissector(
            allocator, def, dissectors, protocol_version, RECURSIVE_ROOT
        );
        wmem_map_insert(this_dissector->dissect_arguments, "d", sub_dissector);
    }
    this_dissector->dissect_protocol = dissect_switch;
    return this_dissector;
}

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(bitfield) {
    cJSON *list = cJSON_GetArrayItem(params, 1);
    if (!cJSON_IsArray(list)) return make_error(allocator, "Bitfield param needs to be a list");
    int count = cJSON_GetArraySize(list);
    protocol_dissector *this_dissector = wmem_alloc(allocator, sizeof(protocol_dissector));
    bit_field **bit_fields = wmem_alloc(allocator, sizeof(bit_field *) * count);
    for (int i = 0; i < count; i++) {
        cJSON *node = cJSON_GetArrayItem(list, i);
        cJSON *name_node = cJSON_GetObjectItem(node, "name");
        if (name_node == NULL) return make_error(allocator, "Lack of name for bitfield object");
        if (!cJSON_IsString(name_node)) return make_error(allocator, "Invalid name for bitfield object");
        char *name = wmem_strdup(allocator, name_node->valuestring);
        cJSON *size_node = cJSON_GetObjectItem(node, "size");
        if (size_node == NULL) return make_error(allocator, "Lack of size for bitfield object");
        if (!cJSON_IsNumber(size_node)) return make_error(allocator, "Invalid size for bitfield object");
        int size = (int) size_node->valuedouble;
        cJSON *signed_node = cJSON_GetObjectItem(node, "signed");
        if (signed_node != NULL && !cJSON_IsBool(signed_node))
            return make_error(allocator, "Invalid signed for bitfield object");
        bool signed_num = signed_node == NULL || cJSON_IsTrue(signed_node);
        cJSON *save_name = cJSON_GetObjectItem(node, "saveName");
        if (save_name != NULL && !cJSON_IsString(save_name))
            return make_error(allocator, "Invalid saveName for bitfield object");
        char *save = save_name == NULL ? NULL : wmem_strdup(allocator, save_name->valuestring);
        bit_field *field = wmem_alloc(allocator, sizeof(bit_field));
        field->name = name;
        field->counts = size;
        field->signed_number = signed_num;
        field->save_name = save;
        bit_fields[i] = field;
    }
    this_dissector->dissect_arguments = wmem_map_new(allocator, g_str_hash, g_str_equal);
    wmem_map_insert(this_dissector->dissect_arguments, "s", bit_fields);
    wmem_map_insert(this_dissector->dissect_arguments, "c", (void *) (uint64_t) count);
    this_dissector->dissect_protocol = dissect_bitfield;
    return this_dissector;
}

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(save) {
    cJSON *type = cJSON_GetArrayItem(params, 1);
    cJSON *name_node = cJSON_GetArrayItem(params, 2);
    if (!cJSON_IsString(name_node)) return make_error(allocator, "Save param 2 needs to be a string");
    char *name = wmem_strdup(allocator, name_node->valuestring);
    protocol_dissector *this_dissector = wmem_alloc(allocator, sizeof(protocol_dissector));
    this_dissector->dissect_arguments = wmem_map_new(allocator, g_str_hash, g_str_equal);
    protocol_dissector *sub_dissector = make_protocol_dissector(
        allocator, type, dissectors, protocol_version, RECURSIVE_ROOT
    );
    wmem_map_insert(this_dissector->dissect_arguments, "d", sub_dissector);
    wmem_map_insert(this_dissector->dissect_arguments, "s", name);
    this_dissector->dissect_protocol = dissect_save;
    return this_dissector;
}

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(global_save) {
    cJSON *type = cJSON_GetArrayItem(params, 1);
    cJSON *name_node = cJSON_GetArrayItem(params, 2);
    if (!cJSON_IsString(name_node)) return make_error(allocator, "Global Save param 2 needs to be a string");
    char *name = wmem_strdup(allocator, name_node->valuestring);
    protocol_dissector *this_dissector = wmem_alloc(allocator, sizeof(protocol_dissector));
    this_dissector->dissect_arguments = wmem_map_new(allocator, g_str_hash, g_str_equal);
    protocol_dissector *sub_dissector = make_protocol_dissector(
        allocator, type, dissectors, protocol_version, RECURSIVE_ROOT
    );
    wmem_map_insert(this_dissector->dissect_arguments, "d", sub_dissector);
    wmem_map_insert(this_dissector->dissect_arguments, "s", name);
    this_dissector->dissect_protocol = dissect_global_save;
    return this_dissector;
}

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(registry) {
    cJSON *name_node = cJSON_GetArrayItem(params, 1);
    if (!cJSON_IsString(name_node)) return make_error(allocator, "Registry param needs to be a string");
    char *name = wmem_strdup(allocator, name_node->valuestring);
    protocol_dissector *this_dissector = wmem_alloc(allocator, sizeof(protocol_dissector));
    this_dissector->dissect_arguments = wmem_map_new(allocator, g_str_hash, g_str_equal);
    wmem_map_insert(this_dissector->dissect_arguments, "n", name);
    this_dissector->dissect_protocol = dissect_registry;
    if (cJSON_GetArrayItem(params, 2) != NULL) {
        cJSON *offset = cJSON_GetArrayItem(params, 2);
        if (!cJSON_IsString(offset)) return make_error(allocator, "Registry offset needs to be a string");
        wmem_map_insert(this_dissector->dissect_arguments, "o", wmem_strdup(allocator, offset->valuestring));
    }
    return this_dissector;
}

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(reference) {
    cJSON *ref_node = cJSON_GetArrayItem(params, 1);
    if (!cJSON_IsString(ref_node)) return make_error(allocator, "Reference param needs to be a string");
    char *ref = ref_node->valuestring;

    char *cache_ref = wmem_strdup_printf(allocator, "ref_%s", ref);
    if (!wmem_map_contains(dissectors, cache_ref)) {
        char *file = build_protocol_file_name("structures", ref, protocol_version);

        char *content = NULL;
        if (!g_file_get_contents(file, &content, NULL, NULL)) {
            ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot read file %s", file);
            g_free(file);
            return make_error(allocator, "Cannot read referenced file");
        }

        cJSON *json = cJSON_Parse(content);
        g_free(content);
        if (json == NULL) {
            const char *error = cJSON_GetErrorPtr();
            ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot parse file %s: %s", file, error);
            g_free(file);
            return make_error(allocator, wmem_strdup_printf(allocator, "Cannot parse referenced file: %s", error));
        }
        g_free(file);

        protocol_dissector *this_dissector = make_void(allocator);
        wmem_map_insert(dissectors, cache_ref, this_dissector);
        protocol_dissector *dissector = make_protocol_dissector(allocator, json, dissectors, protocol_version, NULL);
        this_dissector->dissect_arguments = dissector->dissect_arguments;
        this_dissector->dissect_protocol = dissector->dissect_protocol;
        return this_dissector;
    } else {
        return wmem_map_lookup(dissectors, cache_ref);
    }
}

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(codec) {
    cJSON *ref_node = cJSON_GetArrayItem(params, 1);
    if (!cJSON_IsString(ref_node)) return make_error(allocator, "Codec param 1 needs to be a string");
    char *ref = ref_node->valuestring;
    cJSON *key_node = cJSON_GetArrayItem(params, 2);
    if (!cJSON_IsString(key_node)) return make_error(allocator, "Codec param 2 needs to be a string");
    char *key = key_node->valuestring;

    char *cache_ref = wmem_strdup_printf(allocator, "codec_%s", ref);
    if (!wmem_map_contains(dissectors, cache_ref)) {
        cJSON *registry = get_registry(protocol_version, ref);
        if (registry == NULL) return make_error(allocator, "Invalid registry");
        int entry_count = cJSON_GetArraySize(registry);
        wmem_map_t *map = wmem_map_new(allocator, g_str_hash, g_str_equal);
        for (int i = 0; i < entry_count; i++) {
            cJSON *registry_key = cJSON_GetArrayItem(registry, i);
            char *codec_name = wmem_strdup(allocator, registry_key->valuestring);
            char *cache_name = wmem_strdup_printf(allocator, "codec_%s_%s", ref, codec_name);
            char *file_name = g_strdup_printf("%s/%s", ref, codec_name);
            char *file = build_protocol_file_name("codec", file_name, protocol_version);
            g_free(file_name);
            char *content = NULL;
            if (!g_file_get_contents(file, &content, NULL, NULL)) {
                ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot read file %s", file);
                g_free(file);
                wmem_map_insert(map, codec_name, make_error(allocator, "Cannot read codec file"));
                continue;
            }
            cJSON *json = cJSON_Parse(content);
            g_free(content);
            if (json == NULL) {
                const char *error = cJSON_GetErrorPtr();
                ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot parse file %s: %s", file, error);
                g_free(file);
                wmem_map_insert(
                    map, codec_name,
                    make_error(allocator, wmem_strdup_printf(allocator, "Cannot parse codec file: %s", error))
                );
                continue;
            }
            g_free(file);
            protocol_dissector *this_dissector = wmem_alloc(allocator, sizeof(protocol_dissector));
            wmem_map_insert(dissectors, cache_name, this_dissector);
            protocol_dissector *sub = make_protocol_dissector(allocator, json, dissectors, protocol_version, NULL);
            this_dissector->dissect_arguments = sub->dissect_arguments;
            this_dissector->dissect_protocol = sub->dissect_protocol;
            cJSON_free(json);
            wmem_map_insert(map, codec_name, this_dissector);
        }

        protocol_dissector *this_dissector = wmem_alloc(allocator, sizeof(protocol_dissector));
        this_dissector->dissect_arguments = wmem_map_new(allocator, g_str_hash, g_str_equal);
        wmem_map_insert(this_dissector->dissect_arguments, "d", map);
        wmem_map_insert(this_dissector->dissect_arguments, "k", wmem_strdup(allocator, key));
        this_dissector->dissect_protocol = dissect_codec;
        wmem_map_insert(dissectors, cache_ref, this_dissector);
        return this_dissector;
    } else {
        return wmem_map_lookup(dissectors, cache_ref);
    }
}

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(fix_buffer) {
    cJSON *ref_node = cJSON_GetArrayItem(params, 1);
    if (!cJSON_IsNumber(ref_node)) return make_error(allocator, "fix_buffer param needs to be a number");
    int32_t len = (int32_t) ref_node->valuedouble;
    protocol_dissector *this_dissector = wmem_alloc(allocator, sizeof(protocol_dissector));
    this_dissector->dissect_arguments = wmem_map_new(allocator, g_str_hash, g_str_equal);
    wmem_map_insert(this_dissector->dissect_arguments, "s", (void *) (uint64_t) len);
    this_dissector->dissect_protocol = dissect_fix_buffer;
    return this_dissector;
}

#define FUNC_PROTOCOL(name, func) if (strcmp(ref, #name) == 0) this_dissector->dissect_protocol = func;

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(func) {
    cJSON *ref_node = cJSON_GetArrayItem(params, 1);
    if (!cJSON_IsString(ref_node)) return make_error(allocator, "Func name needs to be a string");
    char *ref = ref_node->valuestring;

    protocol_dissector *this_dissector = wmem_alloc(allocator, sizeof(protocol_dissector));
    this_dissector->dissect_arguments = wmem_map_new(allocator, g_direct_hash, g_direct_equal);
    this_dissector->dissect_protocol = NULL;

    FUNC_PROTOCOL(sync_entity_data, dissect_sync_entity_data)
    FUNC_PROTOCOL(record_entity_id, dissect_record_entity_id)
    FUNC_PROTOCOL(record_entity_id_player, dissect_record_entity_id_player)
    FUNC_PROTOCOL(record_entity_id_experience_orb, dissect_record_entity_id_experience_orb)
    FUNC_PROTOCOL(record_entity_id_painting, dissect_record_entity_id_painting)
    FUNC_PROTOCOL(display_protocol_version, dissect_display_protocol_version)
    FUNC_PROTOCOL(legacy_registry_holder, dissect_legacy_registry_holder)

    if (this_dissector->dissect_protocol == NULL) {
        wmem_free(allocator, this_dissector);
        return make_error(allocator, "Unknown func type");
    }

    int count = cJSON_GetArraySize(params);
    for (int i = 2; i < count; i++) {
        cJSON *node = cJSON_GetArrayItem(params, i);
        if (!cJSON_IsString(node)) return make_error(allocator, "Invalid func parameter");
        wmem_map_insert(
            this_dissector->dissect_arguments, (void *) (uint64_t) (i - 2),
            wmem_strdup(allocator, node->valuestring)
        );
    }

    return this_dissector;
}

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(top_bit_set_terminated_array) {
    cJSON *object = cJSON_GetArrayItem(params, 1);
    if (!cJSON_IsObject(object))
        return make_error(allocator, "top_bit_set_terminated_array param needs to be a object");
    cJSON *type = cJSON_GetObjectItem(object, "type");
    if (type == NULL) return make_error(allocator, "Lack of type for top_bit_set_terminated_array object");
    protocol_dissector *this_dissector = wmem_alloc(allocator, sizeof(protocol_dissector));
    this_dissector->dissect_arguments = wmem_map_new(allocator, g_str_hash, g_str_equal);
    protocol_dissector *sub = make_protocol_dissector(allocator, type, dissectors, protocol_version, RECURSIVE_ROOT);
    wmem_map_insert(this_dissector->dissect_arguments, "d", sub);
    this_dissector->dissect_protocol = dissect_top_bit_set_terminated_array;
    return this_dissector;
}

// NOLINTNEXTLINE
COMPOSITE_PROTOCOL_DEFINE(entity_metadata_loop) {
    cJSON *object = cJSON_GetArrayItem(params, 1);
    if (!cJSON_IsObject(object)) return make_error(allocator, "entity_metadata_loop param needs to be a object");
    cJSON *type = cJSON_GetObjectItem(object, "type");
    if (type == NULL) return make_error(allocator, "Lack of type for entity_metadata_loop object");
    cJSON *end_val = cJSON_GetObjectItem(object, "endVal");
    if (end_val == NULL) return make_error(allocator, "Lack of endVal for entity_metadata_loop object");
    if (!cJSON_IsNumber(end_val)) return make_error(allocator, "Invalid endVal for entity_metadata_loop object");
    uint8_t end = (uint8_t) end_val->valuedouble;
    protocol_dissector *this_dissector = wmem_alloc(allocator, sizeof(protocol_dissector));
    this_dissector->dissect_arguments = wmem_map_new(allocator, g_str_hash, g_str_equal);
    protocol_dissector *sub = make_protocol_dissector(allocator, type, dissectors, protocol_version, RECURSIVE_ROOT);
    wmem_map_insert(this_dissector->dissect_arguments, "d", sub);
    wmem_map_insert(this_dissector->dissect_arguments, "e", (void *) (uint64_t) end);
    this_dissector->dissect_protocol = dissect_entity_metadata_loop;
    return this_dissector;
}

// PROTOCOL PARSER -----------------------------------------------------------------------------------------------------

// NOLINTNEXTLINE
protocol_dissector *make_protocol_dissector(
    wmem_allocator_t *allocator, cJSON *root, wmem_map_t *dissectors, uint32_t protocol_version,
    protocol_dissector *recursive_root
) {
    bool composite_type = cJSON_IsArray(root);
    if (!composite_type && !cJSON_IsString(root)) return make_error(allocator, "Invalid protocol dissector type");
    if (composite_type && cJSON_GetArraySize(root) == 0)
        return make_error(allocator, "Invalid protocol composite dissector type");
    char *type = composite_type ? cJSON_GetArrayItem(root, 0)->valuestring : root->valuestring;
    if (type == NULL) return make_error(allocator, "Protocol dissector type is not a string");
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

    if (strcmp(type, "recursive") == 0 && !composite_type && recursive_root) return recursive_root;

    COMPOSITE_PROTOCOL(container, 1)
    COMPOSITE_PROTOCOL(array, 1)
    COMPOSITE_PROTOCOL(option, 1)
    COMPOSITE_PROTOCOL(mapper, 1)
    COMPOSITE_PROTOCOL(switch, 1)
    COMPOSITE_PROTOCOL(bitfield, 1)
    COMPOSITE_PROTOCOL(save, 2)
    COMPOSITE_PROTOCOL(global_save, 2)
    COMPOSITE_PROTOCOL(fix_buffer, 1)
    COMPOSITE_PROTOCOL(entity_metadata_loop, 1)
    COMPOSITE_PROTOCOL(top_bit_set_terminated_array, 1)
    COMPOSITE_PROTOCOL(reference, 1)
    COMPOSITE_PROTOCOL(codec, 2)

    if (get_settings_flag("registries")) {
        COMPOSITE_PROTOCOL(registry, 1)
        COMPOSITE_PROTOCOL(registry, 2)
    } else {
        SIMPLE_PROTOCOL(registry, dissect_varint)
    }

    if (strcmp(type, "func") == 0 && composite_type)
        return make_func(allocator, root, dissectors, protocol_version, recursive_root);

    return make_error(allocator, wmem_strdup_printf(
                          allocator, "Invalid protocol dissector type: %s%s", type, composite_type ? " (composite)" : ""
                      ));
}

void make_state_protocol(cJSON *root, protocol_dissector_set *set, uint32_t state) {
    int count = cJSON_GetArraySize(root);
    protocol_dissector **dissectors = wmem_alloc(set->allocator, sizeof(protocol_dissector *) * count);
    char **keys = wmem_alloc(set->allocator, sizeof(char *) * count);
    char **names = wmem_alloc(set->allocator, sizeof(char *) * count);
    wmem_map_t *state_switch = wmem_map_new(set->allocator, g_direct_hash, g_direct_equal);
    wmem_map_t *state_side = wmem_map_new(set->allocator, g_direct_hash, g_direct_equal);
    wmem_map_t *special_mark = wmem_map_new(set->allocator, g_direct_hash, g_direct_equal);
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
        void_dissector = make_void(set->allocator);
        wmem_map_insert(set->dissectors_by_name, "void", void_dissector);
    }

    for (int i = 0; i < count; i++) {
        dissectors[i] = void_dissector;
        keys[i] = "<unknown>";
        names[i] = "<unknown>";
        cJSON *dissector_data = cJSON_GetArrayItem(root, i);
        if (!cJSON_HasObjectItem(dissector_data, "key")) continue;
        if (!cJSON_HasObjectItem(dissector_data, "name")) continue;
        char *key = cJSON_GetObjectItem(dissector_data, "key")->valuestring;
        char *name = cJSON_GetObjectItem(dissector_data, "name")->valuestring;
        cJSON *type = cJSON_GetObjectItem(dissector_data, "type");
        protocol_dissector *dissector;
        if (type == NULL) {
            char *key_replaced = g_strdup(key);
            for (char *p = key_replaced; *p; p++)
                if (*p == '/')
                    *p = '_';
            char *file_key = g_strdup_printf("%s_%s", map_state_to_name(state), key_replaced);
            type = get_packet_source(set->protocol_version, file_key);
            g_free(file_key);
            g_free(key_replaced);
        }
        if (type == NULL)
            dissector = make_error(set->allocator, "Cannot find packet file");
        else
            dissector = make_protocol_dissector(
                set->allocator, type, set->dissectors_by_name, set->protocol_version, NULL
            );
        dissectors[i] = dissector;
        keys[i] = wmem_strdup(set->allocator, key);
        names[i] = wmem_strdup(set->allocator, name);
        if (cJSON_HasObjectItem(dissector_data, "stateNext")) {
            cJSON *state_to_next = cJSON_GetObjectItem(dissector_data, "stateNext");
            if (!cJSON_IsString(state_to_next)) continue;
            uint32_t next_state = map_name_to_state(state_to_next->valuestring) & 0xF;
            if (next_state == ~0u) continue;
            wmem_map_insert(state_switch, (void *) (uint64_t) i, (void *) (uint64_t) next_state);
            cJSON *state_side_node = cJSON_GetObjectItem(dissector_data, "stateSide");
            if (!cJSON_IsString(state_side_node)) continue;
            char *side = state_side_node->valuestring;
            uint32_t side_int = 0;
            if (strcmp(side, "client") == 0) side_int = 1;
            if (strcmp(side, "server") == 0) side_int = 2;
            if (strcmp(side, "all") == 0) side_int = 3;
            wmem_map_insert(state_side, (void *) (uint64_t) i, (void *) (uint64_t) side_int);
        }
        if (cJSON_HasObjectItem(dissector_data, "specialMark")) {
            cJSON *mark = cJSON_GetObjectItem(dissector_data, "specialMark");
            if (!cJSON_IsString(mark)) continue;
            wmem_map_insert(special_mark, (void *) (uint64_t) i, wmem_strdup(set->allocator, mark->valuestring));
        }
    }
}

uint32_t map_name_to_state(char *name) {
    if (strcmp(name, "play") == 0) return PLAY;
    if (strcmp(name, "play_client") == 0) return PLAY;
    if (strcmp(name, "play_server") == 0) return 16 + PLAY;
    if (strcmp(name, "login") == 0) return LOGIN;
    if (strcmp(name, "login_client") == 0) return LOGIN;
    if (strcmp(name, "login_server") == 0) return 16 + LOGIN;
    if (strcmp(name, "configuration") == 0) return CONFIGURATION;
    if (strcmp(name, "configuration_client") == 0) return CONFIGURATION;
    if (strcmp(name, "configuration_server") == 0) return 16 + CONFIGURATION;
    if (strcmp(name, "handshaking") == 0) return 16 + HANDSHAKE;
    if (strcmp(name, "handshaking_server") == 0) return 16 + HANDSHAKE;
    if (strcmp(name, "status") == 0) return STATUS;
    if (strcmp(name, "status_client") == 0) return STATUS;
    if (strcmp(name, "status_server") == 0) return 16 + STATUS;
    return ~0u;
}

char *map_state_to_name(uint32_t state) {
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

protocol_dissector_set *create_protocol_with_json(cJSON *protocol_source, uint32_t protocol_version) {
    if (protocol_source == NULL) return NULL;
    protocol_dissector_set *set = wmem_alloc(wmem_epan_scope(), sizeof(protocol_dissector_set));
    set->protocol_version = protocol_version;
    set->allocator = wmem_allocator_new(WMEM_ALLOCATOR_SIMPLE);
    set->dissectors_by_name = wmem_map_new(set->allocator, g_str_hash, g_str_equal);
    set->dissectors_by_state = wmem_map_new(set->allocator, g_direct_hash, g_direct_equal);
    set->count_by_state = wmem_map_new(set->allocator, g_direct_hash, g_direct_equal);
    set->registry_keys = wmem_map_new(set->allocator, g_direct_hash, g_direct_equal);
    set->readable_names = wmem_map_new(set->allocator, g_direct_hash, g_direct_equal);
    set->state_to_next = wmem_map_new(set->allocator, g_direct_hash, g_direct_equal);
    set->state_to_next_side = wmem_map_new(set->allocator, g_direct_hash, g_direct_equal);
    set->special_mark = wmem_map_new(set->allocator, g_direct_hash, g_direct_equal);
    set->valid = true;
    cJSON *now = protocol_source->child;
    while (now != NULL) {
        uint32_t state = map_name_to_state(now->string);
        if (state != ~0u) make_state_protocol(now, set, state);
        now = now->next;
    }
    return set;
}

protocol_dissector_set *create_protocol(uint32_t protocol_version) {
    return create_protocol_with_json(get_protocol_source(protocol_version), protocol_version);
}
