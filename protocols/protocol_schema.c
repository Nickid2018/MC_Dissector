//
// Created by Nickid2018 on 2023/7/13.
//

#include <stdlib.h>
#include "protocol_schema.h"
#include "protocol_data.h"
#include "protocol_je/je_dissect.h"
#include "protocol_be/be_dissect.h"

#define BYTES_MAX_LENGTH 200

struct _protocol_set {
    wmem_map_t *client_packet_map;
    wmem_map_t *server_packet_map;
    wmem_map_t *client_name_map;
    wmem_map_t *server_name_map;
};

struct _protocol_entry {
    guint id;
    gchar *name;
    protocol_field field;
};

struct _protocol_field {
    bool hf_resolved;
    gchar *name;
    gchar *display_name;
    int hf_index;
    wmem_map_t *additional_info;

    guint (*make_tree)(const guint8 *data, proto_tree *tree, tvbuff_t *tvb,
                       protocol_field field, guint offset, guint remaining, data_recorder recorder);
};

// ---------------------------------- Native Fields ----------------------------------
#define FIELD_MAKE_TREE(name) \
    guint make_tree_##name(const guint8 *data, proto_tree *tree, tvbuff_t *tvb, \
    protocol_field field, guint offset, guint remaining, data_recorder recorder)

FIELD_MAKE_TREE(var_int) {
    guint result;
    guint length = read_var_int(data + offset, remaining, &result);
    if (tree)
        proto_tree_add_uint(tree, field->hf_index, tvb, offset, length, record_uint(recorder, result));
    else
        record_uint(recorder, result);
    return length;
}

FIELD_MAKE_TREE(var_long) {
    guint64 result;
    guint length = read_var_long(data + offset, remaining, &result);
    if (tree)
        proto_tree_add_uint64(tree, field->hf_index, tvb, offset, length, record_uint64(recorder, result));
    else
        record_uint64(recorder, result);
    return length;
}

FIELD_MAKE_TREE(string) {
    guint8 *str;
    guint length = read_buffer(data + offset, &str);
    if (tree)
        proto_tree_add_string(tree, field->hf_index, tvb, offset, length, record(recorder, str));
    else
        record(recorder, str);
    return length;
}

FIELD_MAKE_TREE(var_buffer) {
    guint length;
    gint read = read_var_int(data + offset, 5, &length);
    if (tree) {
        if (length < BYTES_MAX_LENGTH)
            proto_tree_add_bytes(tree, field->hf_index, tvb, offset, length + read,
                                 tvb_memdup(wmem_packet_scope(), tvb, offset + read, length));
        else
            proto_tree_add_bytes(tree, field->hf_index, tvb, offset, length + read,
                                 tvb_memdup(wmem_packet_scope(), tvb, offset + read, BYTES_MAX_LENGTH));
    }
    return read + length;
}

#define SINGLE_LENGTH_FIELD_MAKE(name, len, func_add, func_parse, record) \
    FIELD_MAKE_TREE(name) {                                               \
        if (tree)                                                         \
            func_add(tree, field->hf_index, tvb, offset, len, record(recorder, func_parse(tvb, offset))); \
        else                                                              \
            record(recorder, func_parse(tvb, offset));                    \
        return len;                                                       \
    }

SINGLE_LENGTH_FIELD_MAKE(u8, 1, proto_tree_add_uint, tvb_get_guint8, record_uint)

SINGLE_LENGTH_FIELD_MAKE(u16, 2, proto_tree_add_uint, tvb_get_ntohs, record_uint)

SINGLE_LENGTH_FIELD_MAKE(u32, 4, proto_tree_add_uint, tvb_get_ntohl, record_uint)

SINGLE_LENGTH_FIELD_MAKE(u64, 8, proto_tree_add_uint64, tvb_get_ntoh64, record_uint64)

SINGLE_LENGTH_FIELD_MAKE(i8, 1, proto_tree_add_int, tvb_get_gint8, record_int)

SINGLE_LENGTH_FIELD_MAKE(i16, 2, proto_tree_add_int, tvb_get_ntohis, record_int)

SINGLE_LENGTH_FIELD_MAKE(i32, 4, proto_tree_add_int, tvb_get_ntohil, record_int)

SINGLE_LENGTH_FIELD_MAKE(i64, 8, proto_tree_add_int64, tvb_get_ntohi64, record_int64)

SINGLE_LENGTH_FIELD_MAKE(f32, 4, proto_tree_add_float, tvb_get_ntohieee_float, record_float)

SINGLE_LENGTH_FIELD_MAKE(f64, 8, proto_tree_add_double, tvb_get_ntohieee_double, record_double)

SINGLE_LENGTH_FIELD_MAKE(boolean, 1, proto_tree_add_boolean, tvb_get_guint8, record_bool)

#define DELEGATE_FIELD_MAKE(name) \
FIELD_MAKE_TREE(je_##name) { \
    return make_tree_##name(data, tree, tvb, field, offset, remaining, recorder, true); \
} \
FIELD_MAKE_TREE(be_##name) { \
    return make_tree_##name(data, tree, tvb, field, offset, remaining, recorder, false); \
}                                 \

#define DELEGATE_FIELD_MAKE_HEADER(name) \
guint make_tree_##name(const guint8 *data, proto_tree *tree, tvbuff_t *tvb, \
    protocol_field field, guint offset, guint remaining, data_recorder recorder, bool is_je)

FIELD_MAKE_TREE(rest_buffer) {
    if (tree) {
        if (remaining < BYTES_MAX_LENGTH)
            proto_tree_add_bytes(tree, field->hf_index, tvb, offset, remaining,
                                 tvb_memdup(wmem_packet_scope(), tvb, offset, remaining));
        else
            proto_tree_add_bytes(tree, field->hf_index, tvb, offset, remaining,
                                 tvb_memdup(wmem_packet_scope(), tvb, offset, BYTES_MAX_LENGTH));
    }
    return remaining;
}

FIELD_MAKE_TREE(uuid) {
    e_guid_t *uuid = wmem_new(wmem_packet_scope(), e_guid_t);
    tvb_get_guid(tvb, offset, uuid, 0);
    if (tree)
        proto_tree_add_guid(tree, field->hf_index, tvb, offset, 16, record(recorder, uuid));
    else
        record(recorder, uuid);
    return 16;
}

FIELD_MAKE_TREE(void) {
    return 0;
}

FIELD_MAKE_TREE(nbt) {
    guint length = count_nbt_length(data + offset);
    if (tree) {
        if (length < BYTES_MAX_LENGTH)
            proto_tree_add_bytes(tree, field->hf_index, tvb, offset, length,
                                 tvb_memdup(wmem_packet_scope(), tvb, offset, length));
        else
            proto_tree_add_bytes(tree, field->hf_index, tvb, offset, length,
                                 tvb_memdup(wmem_packet_scope(), tvb, offset, BYTES_MAX_LENGTH));
    }
    return length;
}

FIELD_MAKE_TREE(optional_nbt) {
    guint8 present = tvb_get_guint8(tvb, offset);
    if (present != 0) {
        guint length = count_nbt_length(data + offset);
        if (tree) {
            if (length < BYTES_MAX_LENGTH)
                proto_tree_add_bytes(tree, field->hf_index, tvb, offset, length,
                                     tvb_memdup(wmem_packet_scope(), tvb, offset, length));
            else
                proto_tree_add_bytes(tree, field->hf_index, tvb, offset, length,
                                     tvb_memdup(wmem_packet_scope(), tvb, offset, BYTES_MAX_LENGTH));
        }
        return length;
    } else
        return 1;
}

DELEGATE_FIELD_MAKE_HEADER(container) {
    bool not_top = wmem_map_lookup(field->additional_info, GINT_TO_POINTER(-1)) == NULL;
    gchar *now_record = record_get_recording(recorder);
    if (not_top)
        record_push(recorder);
    if (tree && not_top)
        tree = proto_tree_add_subtree(tree, tvb, offset, remaining,
                                      is_je ? ett_sub_je : ett_sub_be, NULL, field->display_name);
    guint length = GPOINTER_TO_UINT(wmem_map_lookup(field->additional_info, 0));
    guint total_length = 0;
    for (guint i = 1; i <= length; i++) {
        protocol_field sub_field = wmem_map_lookup(field->additional_info, GUINT_TO_POINTER(i));
        gchar *field_name = sub_field->name;
        bool is_anon = field_name != NULL && strcmp(field_name, "[unnamed]") == 0;
        if (is_anon && not_top) {
            record_pop(recorder);
            record_start(recorder, now_record);
            sub_field->make_tree(data, NULL, tvb, sub_field, offset, remaining, recorder);
            record_start(recorder, now_record);
            record_push(recorder);
        }
        record_start(recorder, sub_field->name);
        guint sub_length = sub_field->make_tree(data, tree, tvb, sub_field, offset, remaining, recorder);
        offset += sub_length;
        total_length += sub_length;
        remaining -= sub_length;
    }
    if (not_top) {
        proto_item_set_len(proto_tree_get_parent(tree), total_length);
        record_pop(recorder);
    }
    return total_length;
}

DELEGATE_FIELD_MAKE(container)

FIELD_MAKE_TREE(option) {
    bool is_present = tvb_get_guint8(tvb, offset) != 0;
    protocol_field sub_field = wmem_map_lookup(field->additional_info, 0);
    if (field->hf_resolved && field->hf_index != -1 && !sub_field->hf_resolved) {
        sub_field->hf_index = field->hf_index;
        sub_field->name = field->name;
        sub_field->hf_resolved = true;
    }
    if (is_present)
        return sub_field->make_tree(data, tree, tvb, sub_field, offset + 1, remaining - 1, recorder) + 1;
    else
        return 1;
}

FIELD_MAKE_TREE(buffer) {
    guint length = GPOINTER_TO_UINT(wmem_map_lookup(field->additional_info, 0));
    if (tree) {
        if (length < BYTES_MAX_LENGTH)
            proto_tree_add_bytes(tree, field->hf_index, tvb, offset + 1, length,
                                 tvb_memdup(wmem_packet_scope(), tvb, offset, length));
        else
            proto_tree_add_bytes(tree, field->hf_index, tvb, offset + 1, length,
                                 tvb_memdup(wmem_packet_scope(), tvb, offset, BYTES_MAX_LENGTH));
    }
    return length;
}

FIELD_MAKE_TREE(mapper) {
    protocol_field sub_field = wmem_map_lookup(field->additional_info, "__subfield");
    gchar *recording = record_get_recording(recorder);
    record_start(recorder, "__mapperValue");
    guint length = sub_field->make_tree(data, NULL, tvb, sub_field, offset, remaining, recorder);
    char *path[] = {"__mapperValue", NULL};
    gchar *map = record_query(recorder, path);
    gchar *map_name = wmem_map_lookup(field->additional_info, map);
    record_start(recorder, recording);
    record(recorder, map_name);
    if (tree)
        proto_tree_add_string(tree, field->hf_index, tvb, offset, length, map_name);
    return length;
}

DELEGATE_FIELD_MAKE_HEADER(array) {
    protocol_field sub_field = wmem_map_lookup(field->additional_info, GINT_TO_POINTER(1));
    if (field->hf_resolved && field->hf_index != -1 && !sub_field->hf_resolved) {
        sub_field->hf_index = field->hf_index;
        sub_field->hf_resolved = true;
    }
    char **len_data = wmem_map_lookup(field->additional_info, 0);
    guint len = 0;
    guint data_count = 0;
    if (len_data == NULL)
        len = read_var_int(data + offset, remaining, &data_count);
    else {
        char *end_ptr;
        data_count = strtol(record_query(recorder, len_data), &end_ptr, 10);
    }
    proto_tree *sub_tree = NULL;
    if (tree) {
        sub_tree = proto_tree_add_subtree(tree, tvb, offset, remaining,
                                          is_je ? ett_sub_je : ett_sub_be, NULL, field->display_name);
        proto_tree_add_uint(sub_tree, is_je ? hf_array_length_je : hf_array_length_be, tvb,
                            offset, len, data_count);
    }
    offset += len;
    remaining -= len;
    gchar *recording = record_get_recording(recorder);
    char *name_raw = sub_field->name;
    char *display_raw = sub_field->display_name;
    for (int i = 0; i < data_count; i++) {
        record_start(recorder, g_strconcat(recording, "[", g_strdup_printf("%d", i), "]", NULL));
        if (field->name != NULL)
            sub_field->name = g_strdup_printf("%s[%d]", field->name, i);
        else
            sub_field->name = g_strdup_printf("[%d]", i);
        sub_field->display_name = g_strdup_printf("[%d]", i);
        guint sub_length = sub_field->make_tree(data, sub_tree, tvb, sub_field, offset, remaining, recorder);
        offset += sub_length;
        len += sub_length;
        remaining -= sub_length;
    }
    sub_field->name = name_raw;
    sub_field->display_name = display_raw;
    if (tree)
        proto_item_set_len(sub_tree, len);
    return len;
}

DELEGATE_FIELD_MAKE(array)

FIELD_MAKE_TREE(bitfield) {
    int size = GPOINTER_TO_INT(wmem_map_lookup(field->additional_info, GINT_TO_POINTER(-1)));
    int *const *bitfields = wmem_map_lookup(field->additional_info, GINT_TO_POINTER(-2));
    int total_bytes = GPOINTER_TO_INT(wmem_map_lookup(field->additional_info, GINT_TO_POINTER(-3)));
    if (tree)
        for (int i = 0; i < size; i++) {
            int *hf_index = bitfields[i];
            if (hf_index != NULL)
                proto_tree_add_item(tree, *hf_index, tvb, offset, total_bytes, ENC_NA);
        }
    record_push(recorder);
    int offset_bit = 0;
    for (int i = 0; i < size; i++) {
        int len = GPOINTER_TO_INT(wmem_map_lookup(field->additional_info, GINT_TO_POINTER(i * 3)));
        bool signed_ = GPOINTER_TO_INT(wmem_map_lookup(field->additional_info, GINT_TO_POINTER(i * 3 + 1)));
        char *name = wmem_map_lookup(field->additional_info, GINT_TO_POINTER(i * 3 + 2));
        record_start(recorder, name);
        if (len <= 32) {
            guint read = tvb_get_bits(tvb, offset * 8 + offset_bit, len, ENC_BIG_ENDIAN);
            if (signed_)
                record_int(recorder, *(gint32 *) &read);
            else
                record_uint(recorder, read);
        } else {
            guint64 read = tvb_get_bits64(tvb, offset * 8 + offset_bit, len, ENC_BIG_ENDIAN);
            if (signed_)
                record_int64(recorder, *(gint64 *) &read);
            else
                record_uint64(recorder, read);
        }
        offset_bit += len;
    }
    record_pop(recorder);
    return (offset_bit + 7) / 8;
}

DELEGATE_FIELD_MAKE_HEADER(top_bit_set_terminated_array) {
    protocol_field sub_field = wmem_map_lookup(field->additional_info, 0);
    if (field->hf_resolved && field->hf_index != -1 && !sub_field->hf_resolved) {
        sub_field->hf_index = field->hf_index;
        sub_field->name = field->name;
        sub_field->hf_resolved = true;
    }
    guint8 now;
    guint len = 0;
    gchar *recording = record_get_recording(recorder);
    char *name_raw = sub_field->name;
    char *display_raw = sub_field->display_name;
    proto_tree *sub_tree = NULL;
    if (tree)
        sub_tree = proto_tree_add_subtree(tree, tvb, offset, remaining,
                                          is_je ? ett_sub_je : ett_sub_be, NULL, field->display_name);
    do {
        now = data[offset++];
        len++;
        guint ord = now & 0x7F;
        record_start(recorder, g_strconcat(recording, "[", g_strdup_printf("%d", ord), "]", NULL));
        if (field->name != NULL)
            sub_field->name = g_strdup_printf("%s[%d]", field->name, ord);
        else
            sub_field->name = g_strdup_printf("[%d]", ord);
        sub_field->display_name = g_strdup_printf("[%d]", ord);
        guint sub_length = sub_field->make_tree(data, sub_tree, tvb, sub_field, offset, remaining - len, recorder);
        offset += sub_length;
        len += sub_length;
    } while ((now & 0x80) != 0);
    sub_field->name = name_raw;
    sub_field->display_name = display_raw;
    if (tree)
        proto_item_set_len(sub_tree, len);
    return len;
}

DELEGATE_FIELD_MAKE(top_bit_set_terminated_array)

FIELD_MAKE_TREE(switch) {
    char **path = wmem_map_lookup(field->additional_info, "__path");
    void *key = record_query(recorder, path);
    protocol_field sub_field_choose = wmem_map_lookup(field->additional_info, key);
    if (sub_field_choose == NULL) // default
        sub_field_choose = wmem_map_lookup(field->additional_info, "default");
    if (sub_field_choose == NULL) // no case matched
        return 0;
    if (field->hf_resolved && field->hf_index != -1 && !sub_field_choose->hf_resolved) {
        sub_field_choose->hf_index = field->hf_index;
        sub_field_choose->name = field->name;
        sub_field_choose->hf_resolved = true;
    }
    char *display_name_raw = sub_field_choose->display_name;
    sub_field_choose->display_name = field->display_name;
    guint len = sub_field_choose->make_tree(data, tree, tvb, sub_field_choose, offset, remaining, recorder);
    sub_field_choose->display_name = display_name_raw;
    return len;
}

DELEGATE_FIELD_MAKE_HEADER(entity_metadata_loop) {
    protocol_field sub_field = wmem_map_lookup(field->additional_info, GINT_TO_POINTER(0));
    int end_val_1 = GPOINTER_TO_INT(wmem_map_lookup(field->additional_info, GINT_TO_POINTER(1)));
    guint8 end_val = *(guint8 *) &end_val_1;
    if (field->hf_resolved && field->hf_index != -1 && !sub_field->hf_resolved) {
        sub_field->hf_index = field->hf_index;
        sub_field->name = field->name;
        sub_field->hf_resolved = true;
    }
    int count = 0;
    guint len = 0;
    gchar *recording = record_get_recording(recorder);
    proto_tree *sub_tree = NULL;
    if (tree)
        sub_tree = proto_tree_add_subtree(tree, tvb, offset, remaining,
                                          is_je ? ett_sub_je : ett_sub_be, NULL, field->display_name);
    char *name_raw = sub_field->name;
    char *display_name_raw = sub_field->display_name;
    while (data[offset] != end_val) {
        record_start(recorder, g_strconcat(recording, "[", g_strdup_printf("%d", count), "]", NULL));
        if (field->name != NULL)
            sub_field->name = g_strdup_printf("%s[%d]", field->name, count);
        else
            sub_field->name = g_strdup_printf("[%d]", count);
        sub_field->display_name = g_strdup_printf("[%d]", count);
        guint sub_length = sub_field->make_tree(data, sub_tree, tvb, sub_field, offset, remaining - len, recorder);
        offset += sub_length;
        len += sub_length;
        count++;
    }
    sub_field->name = name_raw;
    sub_field->display_name = display_name_raw;
    if (tree)
        proto_item_set_len(sub_tree, len + 1);
    return len + 1;
}

DELEGATE_FIELD_MAKE(entity_metadata_loop)

FIELD_MAKE_TREE(basic_type) {
    int len = GPOINTER_TO_INT(wmem_map_lookup(field->additional_info, GINT_TO_POINTER(-2)));
    protocol_field sub_field = wmem_map_lookup(field->additional_info, GINT_TO_POINTER(-1));
    for (int i = 0; i < len; i++) {
        gchar *name = wmem_map_lookup(field->additional_info, GINT_TO_POINTER(i * 2));
        gchar *value = wmem_map_lookup(field->additional_info, GINT_TO_POINTER(i * 2 + 1));
        record_add_alias(recorder, name, value);
    }
    if (field->hf_resolved && field->hf_index != -1 && !sub_field->hf_resolved) {
        sub_field->hf_index = field->hf_index;
        sub_field->name = field->name;
        sub_field->hf_resolved = true;
    }
    char *display_name_raw = sub_field->display_name;
    sub_field->display_name = field->display_name;
    guint sub_length = sub_field->make_tree(data, tree, tvb, sub_field, offset, remaining, recorder);
    sub_field->display_name = display_name_raw;
    record_clear_alias(recorder);
    return sub_length;
}

// ------------------------------- End of Native Fields --------------------------------

wmem_map_t *native_make_tree_map = NULL;
wmem_map_t *native_unknown_fallback_map = NULL;
wmem_map_t *native_types = NULL;

#define ADD_NATIVE(json_name, make_name, unknown_flag, type_name) \
    wmem_map_insert(native_make_tree_map, #json_name, make_tree_##make_name); \
    wmem_map_insert(native_unknown_fallback_map, #json_name, #unknown_flag); \
    wmem_map_insert(native_types, #json_name, #type_name);

void init_schema_data() {
    native_make_tree_map = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    native_unknown_fallback_map = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    native_types = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);

    ADD_NATIVE(varint, var_int, uint, u32)
    ADD_NATIVE(optvarint, var_int, uint, u32)
    ADD_NATIVE(varlong, var_long, uint64, u64)
    ADD_NATIVE(string, string, string, string)
    ADD_NATIVE(u8, u8, uint, u8)
    ADD_NATIVE(u16, u16, uint, u16)
    ADD_NATIVE(u32, u32, uint, u32)
    ADD_NATIVE(u64, u64, uint64, u64)
    ADD_NATIVE(i8, i8, int, i8)
    ADD_NATIVE(i16, i16, int, i16)
    ADD_NATIVE(i32, i32, int, i32)
    ADD_NATIVE(i64, i64, int64, i64)
    ADD_NATIVE(bool, boolean, boolean, bool)
    ADD_NATIVE(f32, f32, float, f32)
    ADD_NATIVE(f64, f64, double, f64)
    ADD_NATIVE(UUID, uuid, uuid, uuid)
    ADD_NATIVE(restBuffer, rest_buffer, bytes, bytes)
    ADD_NATIVE(void, void, uint, u32)
    ADD_NATIVE(nbt, nbt, bytes, bytes)
    ADD_NATIVE(optionalNbt, optional_nbt, bytes, bytes)
}

int search_hf_index(bool is_je, wmem_list_t *path_array, gchar *name, wmem_list_t *additional_flags, gchar *type) {
    wmem_map_t *search_hf_map = is_je ? name_hf_map_je : name_hf_map_be;
    wmem_map_t *search_complex_name_map = is_je ? complex_name_map_je : complex_name_map_be;
    wmem_map_t *search_complex_hf_map = is_je ? complex_hf_map_je : complex_hf_map_be;

    if (path_array == NULL) {
        int get_name = GPOINTER_TO_INT(wmem_map_lookup(search_hf_map, name));
        if (get_name != 0)
            return get_name;
        gchar *mapped_name = wmem_map_lookup(search_complex_name_map, name);
        if (mapped_name != NULL) {
            get_name = GPOINTER_TO_INT(wmem_map_lookup(
                    wmem_map_lookup(search_complex_hf_map, mapped_name), type));
            if (get_name != 0)
                return get_name;
        }
        return -1;
    }

    wmem_list_frame_t *now;
    wmem_list_frame_t *now_flag = wmem_list_head(additional_flags);
    while (now_flag != NULL) {
        gchar *name_with_flag = g_strconcat(name, "[", wmem_list_frame_data(now_flag), "]", NULL);
        now = wmem_list_head(path_array);
        while (now != NULL) {
            int get_name = GPOINTER_TO_INT(wmem_map_lookup(search_hf_map,
                                                           name_with_flag +
                                                           GPOINTER_TO_UINT(wmem_list_frame_data(now))));
            if (get_name != 0)
                return get_name;
            gchar *mapped_name = wmem_map_lookup(search_complex_name_map, name_with_flag +
                                                                          GPOINTER_TO_UINT(wmem_list_frame_data(now)));
            if (mapped_name != NULL) {
                get_name = GPOINTER_TO_INT(wmem_map_lookup(
                        wmem_map_lookup(search_complex_hf_map, mapped_name), type));
                if (get_name != 0)
                    return get_name;
            }
            now = wmem_list_frame_next(now);
        }
        now_flag = wmem_list_frame_next(now_flag);
    }

    now = wmem_list_head(path_array);
    while (now != NULL) {
        int get_name = GPOINTER_TO_INT(wmem_map_lookup(search_hf_map,
                                                       name + GPOINTER_TO_UINT(wmem_list_frame_data(now))));
        if (get_name != 0)
            return get_name;
        gchar *mapped_name = wmem_map_lookup(search_complex_name_map, name +
                                                                      GPOINTER_TO_UINT(wmem_list_frame_data(now)));
        if (mapped_name != NULL) {
            get_name = GPOINTER_TO_INT(wmem_map_lookup(
                    wmem_map_lookup(search_complex_hf_map, mapped_name), type));
            if (get_name != 0)
                return get_name;
        }
        now = wmem_list_frame_next(now);
    }
    return -1;
}

gchar *search_name(bool is_je, wmem_list_t *path_array, gchar *name) {
    wmem_map_t *search_map = is_je ? component_map_je : component_map_be;
    if (path_array == NULL) {
        gchar *get_name = wmem_map_lookup(search_map, name);
        if (get_name != NULL)
            return get_name;
        return "unnamed";
    }

    wmem_list_frame_t *now = wmem_list_head(path_array);
    while (now != NULL) {
        gchar *get_name = wmem_map_lookup(search_map, name + GPOINTER_TO_UINT(wmem_list_frame_data(now)));
        if (get_name != NULL)
            return get_name;
        now = wmem_list_frame_next(now);
    }

    return "unnamed";
}

#define NAME_PUSH(x) \
    wmem_list_append(path_array, GUINT_TO_POINTER(path_length + 1)); \
    path_name = g_strconcat(path_name, "/", x, NULL);
#define NAME_POP \
    wmem_list_remove_frame(path_array, wmem_list_tail(path_array)); \
    path_name[path_length] = '\0';

protocol_field parse_protocol(wmem_list_t *path_array, gchar *path_name, wmem_list_t *additional_flags,
                              wmem_map_t *basic_types, cJSON *data, cJSON *types,
                              bool is_je, bool on_top) {
    if (data == NULL)
        return NULL;
    guint path_length = strlen(path_name);
    if (cJSON_IsString(data)) {
        char *type = data->valuestring;
        void *make_tree_func = wmem_map_lookup(native_make_tree_map, type);
        if (make_tree_func != NULL) {
            protocol_field field = wmem_new(wmem_file_scope(), protocol_field_t);
            field->hf_index = search_hf_index(is_je, path_array, path_name, additional_flags,
                                              wmem_map_lookup(native_types, type));
            if (field->hf_index != -1)
                field->hf_resolved = true;
            else {
                char *unknown_fallback = wmem_map_lookup(native_unknown_fallback_map, type);
                field->hf_index = GPOINTER_TO_INT(wmem_map_lookup(
                        is_je ? unknown_hf_map_je : unknown_hf_map_be, unknown_fallback));
                field->hf_resolved = false;
            }
            field->name = NULL;
            field->additional_info = NULL;
            field->make_tree = make_tree_func;
            return field;
        }
        protocol_field field = wmem_map_lookup(basic_types, type);
        if (field != NULL)
            return field;
        NAME_PUSH(type)
        field = parse_protocol(path_array, path_name, additional_flags, basic_types,
                               cJSON_GetObjectItem(types, data->valuestring),
                               types, is_je, false);
        NAME_POP
        return field;
    }
    if (cJSON_GetArraySize(data) != 2)
        return NULL;
    char *type = cJSON_GetArrayItem(data, 0)->valuestring;
    cJSON *fields = cJSON_GetArrayItem(data, 1);

    protocol_field field = wmem_new(wmem_file_scope(), protocol_field_t);
    field->additional_info = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    field->make_tree = NULL;
    field->name = NULL;
    field->hf_index = -1;
    field->hf_resolved = false;
    field->display_name = search_name(is_je, path_array, path_name);

    if (strcmp(type, "container") == 0) { // container
        field->make_tree = is_je ? make_tree_je_container : make_tree_be_container;
        int size = cJSON_GetArraySize(fields);
        wmem_map_insert(field->additional_info, 0, GINT_TO_POINTER(size));
        for (int i = 0; i < size; i++) {
            cJSON *field_data = cJSON_GetArrayItem(fields, i);
            cJSON *type_data = cJSON_GetObjectItem(field_data, "type");
            gchar *sub_field_name;
            if (cJSON_HasObjectItem(field_data, "name"))
                sub_field_name = strdup(cJSON_GetObjectItem(field_data, "name")->valuestring);
            else
                sub_field_name = "[unnamed]";
            NAME_PUSH(sub_field_name)
            protocol_field sub_field = parse_protocol(path_array, path_name, additional_flags, basic_types,
                                                      type_data, types, is_je, false);
            NAME_POP
            if (sub_field == NULL)
                return NULL;
            sub_field->name = sub_field_name;
            wmem_map_insert(field->additional_info, GINT_TO_POINTER(i + 1), sub_field);
        }
        if (on_top)
            wmem_map_insert(field->additional_info, GINT_TO_POINTER(-1), GINT_TO_POINTER(1));
        return field;
    } else if (strcmp(type, "option") == 0) { // option
        field->make_tree = make_tree_option;
        protocol_field sub_field = parse_protocol(path_array, path_name, additional_flags, basic_types,
                                                  fields, types, is_je, false);
        if (sub_field == NULL)
            return NULL;
        wmem_map_insert(field->additional_info, 0, sub_field);
        return field;
    } else if (strcmp(type, "buffer") == 0) { // buffer
        field->hf_index = search_hf_index(is_je, path_array, path_name, additional_flags, "bytes");
        if (field->hf_index != -1)
            field->hf_resolved = true;
        else
            field->hf_index = GPOINTER_TO_INT(wmem_map_lookup(
                    is_je ? unknown_hf_map_je : unknown_hf_map_be, "bytes"));
        if (cJSON_HasObjectItem(fields, "count")) {
            field->make_tree = make_tree_buffer;
            cJSON *count = cJSON_GetObjectItem(fields, "count");
            wmem_map_insert(field->additional_info, 0, GINT_TO_POINTER(count->valueint));
        } else
            field->make_tree = make_tree_var_buffer;
        return field;
    } else if (strcmp(type, "mapper") == 0) { // mapper
        field->additional_info = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
        cJSON *type_data = cJSON_GetObjectItem(fields, "type");
        protocol_field sub_field = parse_protocol(path_array, path_name, additional_flags, basic_types,
                                                  type_data, types, is_je, false);
        if (sub_field == NULL)
            return NULL;
        field->make_tree = make_tree_mapper;
        field->hf_index = search_hf_index(is_je, path_array, path_name, additional_flags, "string");
        if (field->hf_index != -1)
            field->hf_resolved = true;
        else
            field->hf_index = GPOINTER_TO_INT(wmem_map_lookup(
                    is_je ? unknown_hf_map_je : unknown_hf_map_be, "string"));
        wmem_map_insert(field->additional_info, "__subfield", sub_field);
        cJSON *mappings = cJSON_GetObjectItem(fields, "mappings");
        cJSON *now = mappings->child;
        while (now != NULL) {
            char *key = now->string;
            char *value = now->valuestring;
            wmem_map_insert(field->additional_info, strdup(key), strdup(value));
            now = now->next;
        }
        return field;
    } else if (strcmp(type, "array") == 0) { // array
        cJSON *count = cJSON_GetObjectItem(fields, "count");
        if (count != NULL)
            wmem_map_insert(field->additional_info, 0,
                            g_strsplit(count->valuestring, "/", 10));
        else {
            cJSON *count_type = cJSON_GetObjectItem(fields, "countType");
            if (count_type == NULL || strcmp(count_type->valuestring, "varint") != 0)
                return NULL;
        }

        cJSON *type_data = cJSON_GetObjectItem(fields, "type");
        protocol_field sub_field = parse_protocol(path_array, path_name, additional_flags, basic_types,
                                                  type_data, types, is_je, false);
        if (sub_field == NULL)
            return NULL;
        field->make_tree = is_je ? make_tree_je_array : make_tree_be_array;
        wmem_map_insert(field->additional_info, GINT_TO_POINTER(1), sub_field);
        return field;
    } else if (strcmp(type, "bitfield") == 0) {
        int size = cJSON_GetArraySize(fields);
        wmem_map_insert(field->additional_info, GINT_TO_POINTER(-1), GINT_TO_POINTER(size));
        char *bitmask_name = "";
        int total_bits = 0;
        for (int i = 0; i < size; i++) {
            cJSON *field_data = cJSON_GetArrayItem(fields, i);
            bool signed_ = cJSON_GetObjectItem(field_data, "signed")->valueint;
            int bits = cJSON_GetObjectItem(field_data, "size")->valueint;
            char *name = cJSON_GetObjectItem(field_data, "name")->valuestring;
            bitmask_name = g_strdup_printf("%s[%d]%s", bitmask_name, bits, name);
            wmem_map_insert(field->additional_info, GINT_TO_POINTER(i * 3), GINT_TO_POINTER(bits));
            wmem_map_insert(field->additional_info, GINT_TO_POINTER(i * 3 + 1), GINT_TO_POINTER(signed_));
            wmem_map_insert(field->additional_info, GINT_TO_POINTER(i * 3 + 2), strdup(name));
            total_bits += bits;
        }
        wmem_map_insert(field->additional_info, GINT_TO_POINTER(-3), GINT_TO_POINTER(total_bits / 8));
        int **hf_data = wmem_map_lookup(is_je ? bitmask_hf_map_je : bitmask_hf_map_be, bitmask_name);
        if (hf_data == NULL)
            return NULL;
        wmem_map_insert(field->additional_info, GINT_TO_POINTER(-2), hf_data);
        field->make_tree = make_tree_bitfield;
        field->hf_resolved = true;
        return field;
    } else if (strcmp(type, "topBitSetTerminatedArray") == 0) {
        protocol_field sub_field = parse_protocol(path_array, path_name, additional_flags, basic_types,
                                                  cJSON_GetObjectItem(fields, "type"),
                                                  types, is_je, false);
        if (sub_field == NULL)
            return NULL;
        wmem_map_insert(field->additional_info, 0, sub_field);
        field->make_tree = is_je ? make_tree_je_top_bit_set_terminated_array
                                 : make_tree_be_top_bit_set_terminated_array;
        return field;
    } else if (strcmp(type, "switch") == 0) {
        char *compare_data = cJSON_GetObjectItem(fields, "compareTo")->valuestring;
        char **compare_data_split = g_strsplit(strdup(compare_data), "/", 10);
        field->additional_info = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
        wmem_map_insert(field->additional_info, strdup("__path"), compare_data_split);
        if (cJSON_HasObjectItem(fields, "default")) {
            cJSON *default_data = cJSON_GetObjectItem(fields, "default");
            wmem_list_prepend(additional_flags, "default");
            protocol_field default_field = parse_protocol(path_array, path_name, additional_flags, basic_types,
                                                          default_data, types, is_je, false);
            wmem_list_remove_frame(additional_flags, wmem_list_head(additional_flags));
            if (default_field == NULL)
                return NULL;
            wmem_map_insert(field->additional_info, strdup("default"), default_field);
        }
        cJSON *cases = cJSON_GetObjectItem(fields, "fields");
        if (cases == NULL)
            return NULL;
        cJSON *now = cases->child;
        while (now != NULL) {
            char *key = now->string;
            wmem_list_prepend(additional_flags, key);
            protocol_field value = parse_protocol(path_array, path_name, additional_flags, basic_types,
                                                  now, types, is_je, false);
            wmem_list_remove_frame(additional_flags, wmem_list_head(additional_flags));
            if (value == NULL)
                return NULL;
            wmem_map_insert(field->additional_info, strdup(key), value);
            now = now->next;
        }
        field->make_tree = make_tree_switch;
        return field;
    } else if (strcmp(type, "entityMetadataLoop") == 0) {
        protocol_field sub_field = parse_protocol(path_array, path_name, additional_flags, basic_types,
                                                  cJSON_GetObjectItem(fields, "type"),
                                                  types, is_je, false);
        if (sub_field == NULL)
            return NULL;
        int end_val = cJSON_GetObjectItem(fields, "endVal")->valueint;
        wmem_map_insert(field->additional_info, GINT_TO_POINTER(0), sub_field);
        wmem_map_insert(field->additional_info, GINT_TO_POINTER(1), GINT_TO_POINTER(end_val));
        field->make_tree = is_je ? make_tree_je_entity_metadata_loop : make_tree_be_entity_metadata_loop;
        return field;
    } else if (cJSON_HasObjectItem(types, type)) {
        protocol_field_t *type_data = wmem_map_lookup(basic_types, type);
        if (type_data == NULL) {
            NAME_PUSH(type)
            type_data = parse_protocol(path_array, path_name, additional_flags, basic_types,
                                       cJSON_GetObjectItem(types, type), types, is_je, false);
            NAME_POP
        }
        if (type_data == NULL)
            return NULL;
        wmem_map_insert(field->additional_info, GINT_TO_POINTER(-1), type_data);
        cJSON *now = fields->child;
        int i = 0;
        while (now != NULL) {
            wmem_map_insert(field->additional_info, GINT_TO_POINTER(i * 2), g_strconcat("$", now->string, NULL));
            wmem_map_insert(field->additional_info, GINT_TO_POINTER(i * 2 + 1), strdup(now->valuestring));
            now = now->next;
            i++;
        }
        wmem_map_insert(field->additional_info, GINT_TO_POINTER(-2), GINT_TO_POINTER(i));
        field->make_tree = make_tree_basic_type;
        return field;
    }

    return NULL;
}

void make_simple_protocol(cJSON *data, cJSON *types, wmem_map_t *packet_map, wmem_map_t *name_map, bool is_je) {
    cJSON *packets = cJSON_GetObjectItem(data, "packet");
    // Path: [1].[0].type.[1].mappings
    cJSON *c1 = cJSON_GetArrayItem(packets, 1);
    cJSON *c2 = cJSON_GetArrayItem(c1, 0);
    cJSON *c3 = cJSON_GetObjectItem(c2, "type");
    cJSON *c4 = cJSON_GetArrayItem(c3, 1);
    cJSON *mappings = cJSON_GetObjectItem(c4, "mappings");
    cJSON *now = mappings->child;
    while (now != NULL) {
        char *packet_id_str = now->string;
        gchar *packet_name = strdup(now->valuestring);
        char *ptr;
        guint packet_id = (guint) strtol(packet_id_str + 2, &ptr, 16);
        wmem_map_insert(name_map, packet_name, GUINT_TO_POINTER(packet_id + 1));

        protocol_entry entry = wmem_new(wmem_file_scope(), protocol_entry_t);
        entry->id = packet_id;
        entry->name = packet_name;
        wmem_map_insert(packet_map, GUINT_TO_POINTER(packet_id), entry);

        gchar *packet_definition = g_strconcat("packet_", packet_name, NULL);
        cJSON *item = cJSON_GetObjectItem(data, packet_definition);

        if (item != NULL) {
            wmem_list_t *path_array = wmem_list_new(wmem_file_scope());
            wmem_list_append(path_array, 0);
            entry->field = parse_protocol(path_array, packet_name, wmem_list_new(wmem_file_scope()),
                                          wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal),
                                          item, types, is_je, true);
        } else {
            protocol_field field = wmem_new(wmem_file_scope(), protocol_field_t);
            field->make_tree = make_tree_void;
            entry->field = field;
        }
        g_free(packet_definition);

        now = now->next;
    }
}

protocol_set create_protocol_set(cJSON *types, cJSON *data, bool is_je) {
    protocol_set set = wmem_new(wmem_file_scope(), protocol_set_t);
    set->client_packet_map = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    set->server_packet_map = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    set->client_name_map = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
    set->server_name_map = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);

    cJSON *to_client = cJSON_GetObjectItem(cJSON_GetObjectItem(data, "toClient"), "types");
    cJSON *to_server = cJSON_GetObjectItem(cJSON_GetObjectItem(data, "toServer"), "types");
    make_simple_protocol(to_client, types, set->client_packet_map, set->client_name_map, is_je);
    make_simple_protocol(to_server, types, set->server_packet_map, set->server_name_map, is_je);

    return set;
}

gchar *get_packet_name(protocol_entry entry) {
    return entry == NULL ? "Unknown" : entry->name;
}

gint get_packet_id_by_entry(protocol_entry entry) {
    return entry == NULL ? -1 : (int) entry->id;
}

gint get_packet_id(protocol_set set, gchar *name, bool is_client) {
    wmem_map_t *name_map = is_client ? set->client_name_map : set->server_name_map;
    return GPOINTER_TO_INT(wmem_map_lookup(name_map, name)) - 1;
}

protocol_entry get_protocol_entry(protocol_set set, guint packet_id, bool is_client) {
    wmem_map_t *packet_map = is_client ? set->client_packet_map : set->server_packet_map;
    return wmem_map_lookup(packet_map, GUINT_TO_POINTER(packet_id));
}

bool make_tree(protocol_entry entry, proto_tree *tree, tvbuff_t *tvb, const guint8 *data, guint remaining) {
    if (entry->field != NULL) {
        data_recorder recorder = create_data_recorder();
        guint len = entry->field->make_tree(data, tree, tvb, entry->field, 1, remaining - 1, recorder);
        destroy_data_recorder(recorder);
        if (len != remaining - 1)
            proto_tree_add_string_format_value(tree, hf_invalid_data_je, tvb, 1, remaining - 1,
                                               "length mismatch", "Packet length mismatch, expected %d, got %d", len,
                                               remaining - 1);
        return true;
    }
    return false;
}