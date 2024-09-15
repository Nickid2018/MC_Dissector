//
// Created by nickid2018 on 24-9-14.
//

#include "schema.h"
#include "protocol/protocol_data.h"
#include "utils/nbt.h"
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

extern int ett_mc;
extern int proto_mcje;

extern int hf_invalid_data;

extern bool pref_do_nbt_decode;

#define DISSECT_FUNCTION_SIG(name) int32_t (*name)(proto_tree *,packet_info *,tvbuff_t *,int,protocol_dissector *,gchar *,wmem_map_t *,gchar **)

struct protocol_dissector_struct {
    wmem_map_t *dissect_arguments;

    DISSECT_FUNCTION_SIG(dissect_protocol);

    void (*destroy)(wmem_map_t *dissect_arguments);
};

struct protocol_dissector_set_struct {
    wmem_map_t *dissectors_by_name;
    wmem_map_t *dissectors_by_state;
    wmem_map_t *count_by_state;
    wmem_map_t *registry_keys;
    wmem_map_t *readable_names;
};

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

#define DISSECT_ERROR (1 << 31)

// SMALL UTILITY FUNCTIONS ---------------------------------------------------------------------------------------------

void add_name(proto_item *item, gchar *name) {
    proto_item_prepend_text(item, "%s ", name);
}

int32_t add_invalid_data(proto_tree *tree, tvbuff_t *tvb, int offset, gchar *name, gchar *value) {
    if (tree)
        add_name(
                proto_tree_add_string(tree, hf_invalid_data, tvb, offset, 0, value), name
        );
    return DISSECT_ERROR;
}

wmem_map_t *get_global_data(packet_info *pinfo) {
    conversation_t *conv = find_or_create_conversation(pinfo);
    mc_protocol_context *ctx = conversation_get_proto_data(conv, proto_mcje);
    return ctx->global_data;
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
    if (tree && pref_do_nbt_decode) return do_nbt_tree(tree, pinfo, tvb, offset + len, name, !is_new_nbt) + len;

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
    return add_invalid_data(
            tree, tvb, offset, name,
            g_strdup_printf("The protocol dissector failed to parse: %s", error_message)
    );
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
    wmem_free(wmem_epan_scope(), wmem_map_remove(dissect_arguments, "d"));
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
    g_free(saved_value);
    if (value) *value = g_strdup(mapped);
    if (tree) add_name(proto_tree_add_string(tree, hf_string, tvb, offset, len, mapped), name);
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
    protocol_dissector *sub_dissector = wmem_map_lookup(dissector->dissect_arguments, "d");
    uint32_t protocol_version = (uint64_t) wmem_map_lookup(get_global_data(pinfo), "protocol_version");
    gchar *saved_value = NULL;
    int32_t len = sub_dissector->dissect_protocol(
            NULL, pinfo, tvb, offset, sub_dissector, name, packet_saves, &saved_value
    );
    if (len == DISSECT_ERROR) return DISSECT_ERROR;
    if (!saved_value)
        return add_invalid_data(tree, tvb, offset, name, "Can't receive value from source, protocol has error?");
    gchar *end;
    errno = 0;
    uint32_t index = strtoll(saved_value, &end, 10);
    if (errno == ERANGE) return add_invalid_data(tree, tvb, offset, name, "Index is too large");
    if (saved_value == end) return add_invalid_data(tree, tvb, offset, name, "Invalid registry index");
    gchar *key = get_registry_data(protocol_version, registry_name, index);
    if (value) *value = g_strdup(key);
    if (tree) add_name(proto_tree_add_string(tree, hf_string, tvb, offset, len, key), name);
    return len;
}

DESTROY_DISSECTOR(registry) {
    g_free(wmem_map_remove(dissect_arguments, "n"));
}

// PARSING PROTOCOL SCHEMA ---------------------------------------------------------------------------------------------

protocol_dissector *make_error(gchar *error_message) {
    protocol_dissector *error_dissector = wmem_alloc(wmem_epan_scope(), sizeof(protocol_dissector));
    error_dissector->dissect_arguments = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    wmem_map_insert(error_dissector->dissect_arguments, "e", error_message);
    error_dissector->dissect_protocol = dissect_error;
    return error_dissector;
}

#define SIMPLE_PROTOCOL(name, func) if (strcmp(type, #name) == 0 && !composite_type) return make_simple(func);

protocol_dissector *make_simple(DISSECT_FUNCTION_SIG(func)) {
    protocol_dissector *simple_dissector = wmem_alloc(wmem_epan_scope(), sizeof(protocol_dissector));
    simple_dissector->dissect_arguments = NULL;
    simple_dissector->dissect_protocol = func;
    return simple_dissector;
}

protocol_dissector *make_protocol_dissector(cJSON *root) {
    bool composite_type = cJSON_IsArray(root);
    if (!composite_type && !cJSON_IsString(root)) return make_error("Invalid protocol dissector type");
    if (composite_type && cJSON_GetArraySize(root) < 2) return make_error("Invalid composite type");
    gchar *type = composite_type ? cJSON_GetArrayItem(root, 0)->valuestring : root->valuestring;

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
    SIMPLE_PROTOCOL(void, dissect_void)
    SIMPLE_PROTOCOL(bool, dissect_bool)
    SIMPLE_PROTOCOL(string, dissect_string)
    SIMPLE_PROTOCOL(buffer, dissect_buffer)
    SIMPLE_PROTOCOL(uuid, dissect_uuid)
    SIMPLE_PROTOCOL(nbt, dissect_nbt)
    SIMPLE_PROTOCOL(optional_nbt, dissect_optional_nbt)

    return make_error(
            g_strdup_printf("Unknown protocol dissector type: %s%s", type, composite_type ? "(composite)" : "")
    );
}

void make_state_protocol(cJSON *root, protocol_dissector_set *set, uint32_t state) {
    int count = cJSON_GetArraySize(root);
    protocol_dissector **dissectors = wmem_alloc(wmem_epan_scope(), sizeof(protocol_dissector *) * count);
    gchar **keys = wmem_alloc(wmem_epan_scope(), sizeof(gchar *) * count);
    gchar **names = wmem_alloc(wmem_epan_scope(), sizeof(gchar *) * count);
    wmem_map_insert(set->dissectors_by_state, (void *) (uint64_t) state, dissectors);
    wmem_map_insert(set->count_by_state, (void *) (uint64_t) state, (void *) (uint64_t) count);
    wmem_map_insert(set->registry_keys, (void *) (uint64_t) state, keys);
    wmem_map_insert(set->readable_names, (void *) (uint64_t) state, names);
    for (int i = 0; i < count; i++) {
        cJSON *dissector_data = cJSON_GetArrayItem(root, i);
        gchar *key = cJSON_GetObjectItem(dissector_data, "key")->valuestring;
        gchar *name = cJSON_GetObjectItem(dissector_data, "name")->valuestring;
        protocol_dissector *dissector = make_protocol_dissector(cJSON_GetObjectItem(dissector_data, "type"));
        dissectors[i] = dissector;
        keys[i] = key;
        names[i] = name;
    }
}

uint32_t map_name_to_state(gchar *name) {
    if (strcmp(name, "play_client") == 0) return PLAY;
    if (strcmp(name, "play_server") == 0) return 16 + PLAY;
    if (strcmp(name, "login_client") == 0) return LOGIN;
    if (strcmp(name, "login_server") == 0) return 16 + LOGIN;
    if (strcmp(name, "configuration_client") == 0) return CONFIGURATION;
    if (strcmp(name, "configuration_server") == 0) return 16 + CONFIGURATION;
    return ~0u;
}

protocol_dissector_set *create_protocol(uint32_t protocol_version) {
    protocol_dissector_set *set = wmem_alloc(wmem_epan_scope(), sizeof(protocol_dissector_set));
    set->dissectors_by_name = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    set->dissectors_by_state = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
    set->count_by_state = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
    set->registry_keys = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
    set->readable_names = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
    cJSON *protocol_source = get_protocol_source(protocol_version);
    cJSON *now = protocol_source->child;
    while (now != NULL) {
        uint32_t state = map_name_to_state(now->string);
        if (state != ~0u) make_state_protocol(now, set, state);
        now = now->next;
    }
    return set;
}