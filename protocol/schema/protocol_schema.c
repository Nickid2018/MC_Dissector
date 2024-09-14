//
// Created by Nickid2018 on 2023/7/13.
//

#include <stdlib.h>
#include "protocol_schema.h"
#include "protocol/protocol_data.h"
#include "protocol_je/je_dissect.h"
#include "protocol_be/be_dissect.h"
#include "protocol_functions.h"
#include "utils/nbt.h"
#include "mc_dissector.h"

#define BYTES_MAX_LENGTH 200

extern int hf_int8_je;
extern int hf_uint8_je;
extern int hf_int16_je;
extern int hf_uint16_je;
extern int hf_int_je;
extern int hf_uint_je;
extern int hf_int64_je;
extern int hf_uint64_je;
extern int hf_float_je;
extern int hf_double_je;
extern int hf_bytes_je;
extern int hf_string_je;
extern int hf_boolean_je;
extern int hf_uuid_je;
extern int hf_varint_je;
extern int hf_varlong_je;

extern int hf_invalid_data_je;

struct _protocol_set {
    wmem_map_t *client_packet_map;
    wmem_map_t *server_packet_map;
    wmem_map_t *client_name_map;
    wmem_map_t *server_name_map;
};

struct _protocol_entry {
    guint id;
    gchar *name;
    bool is_je;
    protocol_field field;
};

// ---------------------------------- Native Fields ----------------------------------
FIELD_MAKE_TREE(var_int) {
    gint result;
    gint length = read_var_int(tvb, offset, &result);
    guint record = record_uint(recorder, result);
    if (tree)
        proto_item_prepend_text(
                proto_tree_add_uint(tree, hf_varint_je, tvb, offset, length, record),
                "%s",
                field->name
        );
    return length;
}

FIELD_MAKE_TREE(var_long) {
    gint64 result;
    gint length = read_var_long(tvb, offset, &result);
    guint record = record_uint64(recorder, result);
    if (tree)
        proto_item_prepend_text(
                proto_tree_add_uint64(tree, hf_varlong_je, tvb, offset, length, record),
                "%s",
                field->name
        );
    return length;
}

FIELD_MAKE_TREE(string) {
    guint8 *str;
    gint length = read_buffer(tvb, offset, &str, pinfo->pool);
    char *record_str = record(recorder, str);
    if (tree)
        proto_item_prepend_text(
                proto_tree_add_string(tree, hf_string_je, tvb, offset, length, record_str),
                "%s",
                field->name
        );
    return length;
}

FIELD_MAKE_TREE(var_buffer) {
    gint length;
    gint read = read_var_int(tvb, offset, &length);
    if (tree)
        proto_item_prepend_text(
                proto_tree_add_bytes(
                        tree, hf_bytes_je, tvb, offset, length + read,
                        tvb_memdup(
                                pinfo->pool, tvb, offset + read,
                                length < BYTES_MAX_LENGTH ? length : BYTES_MAX_LENGTH
                        )
                ),
                "%s",
                field->name
        );
    return read + length;
}

SINGLE_LENGTH_FIELD_MAKE(u8, hf_uint8_je, 1, proto_tree_add_uint, tvb_get_uint8, record_uint)

SINGLE_LENGTH_FIELD_MAKE(u16, hf_uint16_je, 2, proto_tree_add_uint, tvb_get_ntohs, record_uint)

SINGLE_LENGTH_FIELD_MAKE(u32, hf_uint_je, 4, proto_tree_add_uint, tvb_get_ntohl, record_uint)

SINGLE_LENGTH_FIELD_MAKE(u64, hf_uint64_je, 8, proto_tree_add_uint64, tvb_get_ntoh64, record_uint64)

SINGLE_LENGTH_FIELD_MAKE(i8, hf_int8_je, 1, proto_tree_add_int, tvb_get_int8, record_int)

SINGLE_LENGTH_FIELD_MAKE(i16, hf_int16_je, 2, proto_tree_add_int, tvb_get_ntohis, record_int)

SINGLE_LENGTH_FIELD_MAKE(i32, hf_int_je, 4, proto_tree_add_int, tvb_get_ntohil, record_int)

SINGLE_LENGTH_FIELD_MAKE(i64, hf_int64_je, 8, proto_tree_add_int64, tvb_get_ntohi64, record_int64)

SINGLE_LENGTH_FIELD_MAKE(f32, hf_float_je, 4, proto_tree_add_float, tvb_get_ntohieee_float, record_float)

SINGLE_LENGTH_FIELD_MAKE(f64, hf_double_je, 8, proto_tree_add_double, tvb_get_ntohieee_double, record_double)

SINGLE_LENGTH_FIELD_MAKE(boolean, hf_boolean_je, 1, proto_tree_add_boolean, tvb_get_uint8, record_bool)

FIELD_MAKE_TREE(rest_buffer) {
    if (tree) {
        proto_item_prepend_text(
                proto_tree_add_bytes(
                        tree, hf_bytes_je, tvb, offset, remaining,
                        tvb_memdup(
                                pinfo->pool, tvb, offset,
                                remaining < BYTES_MAX_LENGTH ? remaining : BYTES_MAX_LENGTH
                        )
                ),
                "%s",
                field->name
        );
    }
    return remaining;
}

FIELD_MAKE_TREE(uuid) {
    e_guid_t *uuid = wmem_new(pinfo->pool, e_guid_t);
    tvb_get_guid(tvb, offset, uuid, 0);
    record(recorder, uuid);
    if (tree)
        proto_item_prepend_text(
                proto_tree_add_guid(tree, hf_uuid_je, tvb, offset, 16, uuid),
                "%s",
                field->name
        );
    return 16;
}

FIELD_MAKE_TREE(void) {
    return 0;
}

FIELD_MAKE_TREE(nbt) {
    if (pref_do_nbt_decode && is_je)
        return do_nbt_tree(tree, pinfo, tvb, offset, field->name, is_je, true);
    else {
        gint length = count_nbt_length(tvb, offset);
        if (tree)
            proto_item_prepend_text(
                    proto_tree_add_bytes(
                            tree, hf_bytes_je, tvb, offset, length,
                            tvb_memdup(
                                    pinfo->pool, tvb, offset,
                                    length < BYTES_MAX_LENGTH ? length : BYTES_MAX_LENGTH
                            )
                    ),
                    "%s",
                    field->name
            );
        return length;
    }
}

FIELD_MAKE_TREE(optional_nbt) {
    guint8 present = tvb_get_uint8(tvb, offset);
    if (present != TAG_END) {
        if (pref_do_nbt_decode && is_je)
            return do_nbt_tree(tree, pinfo, tvb, offset, field->name, is_je, true);
        else {
            gint length = count_nbt_length(tvb, offset);
            if (tree)
                proto_item_prepend_text(
                        proto_tree_add_bytes(
                                tree, hf_bytes_je, tvb, offset, length,
                                tvb_memdup(
                                        pinfo->pool, tvb, offset,
                                        length < BYTES_MAX_LENGTH ? length : BYTES_MAX_LENGTH
                                )
                        ),
                        "%s",
                        field->name
                );
            return length;
        }
    } else {
        if (tree) {
            proto_item *text = proto_tree_add_boolean(tree, hf_boolean_je, tvb, offset, 1, false);
            proto_item_set_text(text, "%s [optional nbt]: Not present", field->name);
        }
        return 1;
    }
}

FIELD_MAKE_TREE(nbt_any_type) {
    guint8 present = tvb_get_uint8(tvb, offset);
    if (present != TAG_END) {
        if (pref_do_nbt_decode && is_je)
            return do_nbt_tree(tree, pinfo, tvb, offset, field->name, is_je, false);
        else {
            gint length = count_nbt_length_with_type(tvb, offset + 1, present) + 1;
            if (tree)
                proto_item_prepend_text(
                        proto_tree_add_bytes(
                                tree, hf_bytes_je, tvb, offset, length,
                                tvb_memdup(
                                        pinfo->pool, tvb, offset,
                                        length < BYTES_MAX_LENGTH ? length : BYTES_MAX_LENGTH
                                )
                        ),
                        "%s",
                        field->name
                );
            return length;
        }
    } else {
        if (tree) {
            proto_item *text = proto_tree_add_boolean(tree, hf_boolean_je, tvb, offset, 1, false);
            proto_item_set_text(text, "%s [optional nbt]: Not present", field->name);
        }
        return 1;
    }
}

FIELD_MAKE_TREE(container) {
    bool not_top = wmem_map_lookup(field->additional_info, GINT_TO_POINTER(-1)) == NULL;
    gchar *now_record = record_get_recording(recorder);
    if (not_top)
        record_push(recorder);
    if (tree && not_top)
        tree = proto_tree_add_subtree(
                tree, tvb, offset, remaining,
                is_je ? ett_sub_je : ett_sub_be, NULL, field->name
        );
    gint length = GPOINTER_TO_UINT(wmem_map_lookup(field->additional_info, 0));
    gint total_length = 0;
    for (guint i = 1; i <= length; i++) {
        protocol_field sub_field = wmem_map_lookup(field->additional_info, GUINT_TO_POINTER(i));
        if (g_strcmp0(sub_field->name, "[unnamed]") == 0 && not_top) {
            record_pop(recorder);
            record_start(recorder, now_record);
            sub_field->make_tree(NULL, pinfo, tvb, extra, sub_field, offset, remaining, recorder, is_je);
            record_start(recorder, now_record);
            record_push(recorder);
        }
        record_start(recorder, sub_field->name);
        gint sub_length = sub_field->make_tree(tree, pinfo, tvb, extra, sub_field, offset, remaining, recorder, is_je);
        offset += sub_length;
        total_length += sub_length;
        remaining -= sub_length;
    }
    if (not_top) {
        if (tree)
            proto_item_set_len(proto_tree_get_parent(tree), total_length);
        record_pop(recorder);
    }
    return total_length;
}

FIELD_MAKE_TREE(option) {
    bool is_present = tvb_get_uint8(tvb, offset) != 0;
    protocol_field sub_field = wmem_map_lookup(field->additional_info, 0);
    sub_field->name = field->name;
    if (is_present)
        return sub_field->make_tree(tree, pinfo, tvb, extra, sub_field, offset + 1, remaining - 1, recorder, is_je) + 1;
    else {
        if (tree) {
            proto_item *text = proto_tree_add_boolean(tree, hf_boolean_je, tvb, offset, 1, false);
            proto_item_set_text(text, "%s [optional]: Not present", field->name);
        }
        return 1;
    }
}

FIELD_MAKE_TREE(buffer) {
    gint length = GPOINTER_TO_UINT(wmem_map_lookup(field->additional_info, 0));
    if (tree)
        proto_item_prepend_text(
                proto_tree_add_bytes(
                        tree, hf_bytes_je, tvb, offset, length,
                        tvb_memdup(
                                pinfo->pool, tvb, offset,
                                length < BYTES_MAX_LENGTH ? length : BYTES_MAX_LENGTH
                        )
                ),
                "%s",
                field->name
        );
    return length;
}

FIELD_MAKE_TREE(mapper) {
    protocol_field sub_field = wmem_map_lookup(field->additional_info, "__subfield");
    gchar *recording = record_get_recording(recorder);
    record_start(recorder, "__mapperValue");
    gint length = sub_field->make_tree(NULL, pinfo, tvb, extra, sub_field, offset, remaining, recorder, is_je);
    char *path[] = {"__mapperValue", NULL};
    gchar *map = record_query(recorder, path);
    gchar *map_name = wmem_map_lookup(field->additional_info, map);
    record_start(recorder, recording);
    record(recorder, map_name);
    if (tree)
        proto_item_prepend_text(
                proto_tree_add_string(tree, hf_string_je, tvb, offset, length, map_name),
                "%s",
                field->name
        );
    return length;
}

FIELD_MAKE_TREE(array) {
    protocol_field sub_field = wmem_map_lookup(field->additional_info, GINT_TO_POINTER(1));
    char **len_data = wmem_map_lookup(field->additional_info, 0);
    gint len = 0;
    gint data_count = 0;
    if (len_data == NULL)
        len = read_var_int(tvb, offset, &data_count);
    else {
        char *end_ptr;
        data_count = (gint) strtol(record_query(recorder, len_data), &end_ptr, 10);
    }
    proto_tree *sub_tree = NULL;
    if (tree) {
        sub_tree = proto_tree_add_subtree(
                tree, tvb, offset, remaining,
                is_je ? ett_sub_je : ett_sub_be, NULL,
                g_strdup_printf("%s (%d entries)", field->name, data_count)
        );
    }
    offset += len;
    remaining -= len;
    gchar *recording = record_get_recording(recorder);
    for (int i = 0; i < data_count; i++) {
        record_start(recorder, g_strconcat(recording, "[", g_strdup_printf("%d", i), "]", NULL));
        sub_field->name = g_strdup_printf("%s[%d]", field->name, i);
        gint sub_length = sub_field->make_tree(
                sub_tree, pinfo, tvb, extra, sub_field, offset, remaining, recorder,
                is_je
        );
        offset += sub_length;
        len += sub_length;
        remaining -= sub_length;
    }
    if (tree)
        proto_item_set_len(sub_tree, len);
    return len;
}

FIELD_MAKE_TREE(bitfield) {
    int size = GPOINTER_TO_INT(wmem_map_lookup(field->additional_info, GINT_TO_POINTER(-1)));
    record_push(recorder);
    int offset_bit = 0;
    for (int i = 0; i < size; i++) {
        int len = GPOINTER_TO_INT(wmem_map_lookup(field->additional_info, GINT_TO_POINTER(i * 3)));
        bool signed_number = GPOINTER_TO_INT(wmem_map_lookup(field->additional_info, GINT_TO_POINTER(i * 3 + 1)));
        char *name = wmem_map_lookup(field->additional_info, GINT_TO_POINTER(i * 3 + 2));
        record_start(recorder, name);
        if (len <= 32) {
            guint read = tvb_get_bits(tvb, offset * 8 + offset_bit, len, ENC_BIG_ENDIAN);
            if (signed_number) {
                record_int(recorder, *(gint32 *) &read);
                if (tree)
                    proto_item_append_text(
                            proto_tree_add_bits_item(
                                    tree, hf_int_je, tvb,
                                    offset * 8 + offset_bit, len,
                                    ENC_BIG_ENDIAN
                            ),
                            "%s",
                            g_strdup_printf(" <bitmask %s>", name)
                    );
            } else {
                record_uint(recorder, read);
                if (tree)
                    proto_item_append_text(
                            proto_tree_add_bits_item(
                                    tree, hf_uint_je, tvb,
                                    offset * 8 + offset_bit, len,
                                    ENC_BIG_ENDIAN
                            ),
                            "%s",
                            g_strdup_printf(" <bitmask %s>", name)
                    );
            }
        } else {
            guint64 read = tvb_get_bits64(tvb, offset * 8 + offset_bit, len, ENC_BIG_ENDIAN);
            if (signed_number) {
                record_int64(recorder, *(gint64 *) &read);
                if (tree)
                    proto_item_append_text(
                            proto_tree_add_bits_item(
                                    tree, hf_int64_je, tvb,
                                    offset * 8 + offset_bit, len,
                                    ENC_BIG_ENDIAN
                            ),
                            "%s",
                            g_strdup_printf(" <bitmask %s>", name)
                    );
            } else {
                record_uint64(recorder, read);
                if (tree)
                    proto_item_append_text(
                            proto_tree_add_bits_item(
                                    tree, hf_uint64_je, tvb,
                                    offset * 8 + offset_bit, len,
                                    ENC_BIG_ENDIAN
                            ),
                            "%s",
                            g_strdup_printf(" <bitmask %s>", name)
                    );
            }
        }
        offset_bit += len;
    }
    record_pop(recorder);
    return (offset_bit + 7) / 8;
}

FIELD_MAKE_TREE(top_bit_set_terminated_array) {
    protocol_field sub_field = wmem_map_lookup(field->additional_info, 0);
    guint8 now;
    gint len = 0;
    gchar *recording = record_get_recording(recorder);
    proto_tree *sub_tree = NULL;
    if (tree)
        sub_tree = proto_tree_add_subtree(
                tree, tvb, offset, remaining,
                is_je ? ett_sub_je : ett_sub_be, NULL, field->name
        );
    do {
        now = tvb_get_uint8(tvb, offset++);
        len++;
        guint ord = now & 0x7F;
        record_start(recorder, g_strconcat(recording, "[", g_strdup_printf("%d", ord), "]", NULL));
        sub_field->name = g_strdup_printf("%s[%d]", field->name, ord);
        gint sub_length = sub_field->make_tree(
                sub_tree, pinfo, tvb, extra, sub_field, offset, remaining - len,
                recorder, is_je
        );
        offset += sub_length;
        len += sub_length;
    } while ((now & 0x80) != 0);
    if (tree)
        proto_item_set_len(sub_tree, len);
    return len;
}

FIELD_MAKE_TREE(switch) {
    char **path = wmem_map_lookup(field->additional_info, "__path");
    void *key = record_query(recorder, path);
    protocol_field sub_field_choose = wmem_map_lookup(field->additional_info, key);
    if (sub_field_choose == NULL) // default
        sub_field_choose = wmem_map_lookup(field->additional_info, "default");
    if (sub_field_choose == NULL) // no case matched
        return 0;
    sub_field_choose->name = field->name;
    gint len = sub_field_choose->make_tree(
            tree, pinfo, tvb, extra, sub_field_choose, offset, remaining, recorder, is_je
    );
    return len;
}

FIELD_MAKE_TREE(entity_metadata_loop) {
    protocol_field sub_field = wmem_map_lookup(field->additional_info, GINT_TO_POINTER(0));
    int end_val_1 = GPOINTER_TO_INT(wmem_map_lookup(field->additional_info, GINT_TO_POINTER(1)));
    guint8 end_val = *(guint8 *) &end_val_1;
    int count = 0;
    gint len = 0;
    gchar *recording = record_get_recording(recorder);
    proto_tree *sub_tree = NULL;
    if (tree)
        sub_tree = proto_tree_add_subtree(
                tree, tvb, offset, remaining,
                is_je ? ett_sub_je : ett_sub_be, NULL, field->name
        );
    while (tvb_get_uint8(tvb, offset) != end_val) {
        record_start(recorder, g_strconcat(recording, "[", g_strdup_printf("%d", count), "]", NULL));
        sub_field->name = g_strdup_printf("%s[%d]", field->name, count);
        gint sub_length = sub_field->make_tree(
                sub_tree, pinfo, tvb, extra, sub_field, offset, remaining - len, recorder, is_je
        );
        offset += sub_length;
        len += sub_length;
        count++;
    }
    if (tree)
        proto_item_set_len(sub_tree, len + 1);
    return len + 1;
}

FIELD_MAKE_TREE(basic_type) {
    int len = GPOINTER_TO_INT(wmem_map_lookup(field->additional_info, GINT_TO_POINTER(-2)));
    protocol_field sub_field = wmem_map_lookup(field->additional_info, GINT_TO_POINTER(-1));
    for (int i = 0; i < len; i++) {
        gchar *name = wmem_map_lookup(field->additional_info, GINT_TO_POINTER(i * 2));
        gchar *value = wmem_map_lookup(field->additional_info, GINT_TO_POINTER(i * 2 + 1));
        record_add_alias(recorder, name, value);
    }
    sub_field->name = field->name;
    gint sub_length = sub_field->make_tree(tree, pinfo, tvb, extra, sub_field, offset, remaining, recorder, is_je);
    record_clear_alias(recorder);
    return sub_length;
}

// ------------------------------- End of Native Fields --------------------------------

wmem_map_t *native_make_tree_map = NULL;
wmem_map_t *native_types = NULL;

wmem_map_t *function_make_tree = NULL;

#define ADD_NATIVE(json_name, make_name, type_name) \
    wmem_map_insert(native_make_tree_map, #json_name, make_tree_##make_name); \
    wmem_map_insert(native_types, #json_name, #type_name);

#define ADD_FUNCTION(json_name, func_name) \
    wmem_map_insert(function_make_tree, #json_name, make_tree_##func_name);

void init_schema_data() {
    native_make_tree_map = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    native_types = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    function_make_tree = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);

    ADD_NATIVE(varint, var_int, u32)
    ADD_NATIVE(optvarint, var_int, u32)
    ADD_NATIVE(varlong, var_long, u64)
    ADD_NATIVE(string, string, string)
    ADD_NATIVE(u8, u8, u8)
    ADD_NATIVE(u16, u16, u16)
    ADD_NATIVE(u32, u32, u32)
    ADD_NATIVE(u64, u64, u64)
    ADD_NATIVE(i8, i8, i8)
    ADD_NATIVE(i16, i16, i16)
    ADD_NATIVE(i32, i32, i32)
    ADD_NATIVE(i64, i64, i64)
    ADD_NATIVE(bool, boolean, bool)
    ADD_NATIVE(f32, f32, f32)
    ADD_NATIVE(f64, f64, f64)
    ADD_NATIVE(UUID, uuid, uuid)
    ADD_NATIVE(restBuffer, rest_buffer, bytes)
    ADD_NATIVE(void, void, u32)
    ADD_NATIVE(nbt, nbt, bytes)
    ADD_NATIVE(optionalNbt, optional_nbt, bytes)

    ADD_FUNCTION(sync_entity_data, sync_entity_data)
    ADD_FUNCTION(record_entity_id, record_entity_id)
    ADD_FUNCTION(record_entity_id_player, record_entity_id_player)
    ADD_FUNCTION(record_entity_id_experience_orb, record_entity_id_experience_orb)
    ADD_FUNCTION(record_entity_id_painting, record_entity_id_painting)
    ADD_FUNCTION(entity_event, entity_event)
    ADD_FUNCTION(level_event, level_event)
}

// NOLINTNEXTLINE
protocol_field parse_protocol(wmem_map_t *basic_types, wmem_list_t *resolving_basics,
                              cJSON *data, cJSON *types, bool is_je, bool on_top,
                              protocol_settings settings) {
    if (data == NULL) {
        ws_log(
                "MC-Dissector",
                LOG_LEVEL_CRITICAL,
                "Invalid protocol data - Data is NULL"
        );
        return NULL;
    }

    if (cJSON_IsString(data)) {
        char *type = data->valuestring;
        void *make_tree_func = wmem_map_lookup(native_make_tree_map, type);
        if (make_tree_func != NULL) {
            protocol_field field = wmem_new(wmem_epan_scope(), protocol_field_t);
            field->name = "<unnamed>";
            field->additional_info = NULL;
            field->make_tree = make_tree_func;

            if (settings.nbt_any_type && g_strcmp0(type, "nbt") == 0)
                field->make_tree = make_tree_nbt_any_type;

            return field;
        }

        protocol_field field = wmem_map_lookup(basic_types, type);
        if (field != NULL)
            return field;

        if (wmem_list_find(resolving_basics, type) != NULL) { // recursive loop
            field = wmem_new(wmem_epan_scope(), protocol_field_t);
            wmem_map_insert(basic_types, type, field);
            protocol_field processed = parse_protocol(
                    basic_types, resolving_basics,
                    cJSON_GetObjectItem(types, data->valuestring), types, is_je, false, settings
            );
            wmem_map_remove(basic_types, type);
            if (processed == NULL) {
                return NULL;
            }
            *field = *processed;
        } else {
            wmem_list_append(resolving_basics, type);
            field = wmem_new(wmem_epan_scope(), protocol_field_t);
            protocol_field processed = parse_protocol(
                    basic_types, resolving_basics,
                    cJSON_GetObjectItem(types, data->valuestring), types, is_je, false, settings
            );
            wmem_list_remove(resolving_basics, type);
            if (processed == NULL) {
                return NULL;
            }
            *field = *processed;
        }

        return field;
    }
    if (cJSON_GetArraySize(data) != 2) {
        ws_log(
                "MC-Dissector",
                LOG_LEVEL_CRITICAL,
                "Invalid protocol data - Argument size not matches 2: %s",
                cJSON_Print(data)
        );
        return NULL;
    }
    char *type = cJSON_GetArrayItem(data, 0)->valuestring;
    cJSON *fields = cJSON_GetArrayItem(data, 1);

    protocol_field field = wmem_new(wmem_epan_scope(), protocol_field_t);
    field->additional_info = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
    field->make_tree = NULL;
    field->name = "[unnamed]";

    if (g_strcmp0(type, "function") == 0) {
        field->make_tree = wmem_map_lookup(function_make_tree, fields->valuestring);
        return field;
    } else if (g_strcmp0(type, "container") == 0) { // container
        field->make_tree = make_tree_container;
        int size = cJSON_GetArraySize(fields);
        wmem_map_insert(field->additional_info, 0, GINT_TO_POINTER(size));
        for (int i = 0; i < size; i++) {
            cJSON *field_data = cJSON_GetArrayItem(fields, i);
            cJSON *type_data = cJSON_GetObjectItem(field_data, "type");
            protocol_field sub_field = parse_protocol(
                    basic_types, resolving_basics, type_data, types, is_je, false, settings
            );
            if (sub_field == NULL)
                return NULL;
            if (cJSON_HasObjectItem(field_data, "name"))
                sub_field->name = g_strdup(cJSON_GetObjectItem(field_data, "name")->valuestring);
            wmem_map_insert(field->additional_info, GINT_TO_POINTER(i + 1), sub_field);
        }
        if (on_top)
            wmem_map_insert(field->additional_info, GINT_TO_POINTER(-1), GINT_TO_POINTER(1));
        return field;
    } else if (g_strcmp0(type, "option") == 0) { // option
        field->make_tree = make_tree_option;
        protocol_field sub_field = parse_protocol(
                basic_types, resolving_basics, fields, types, is_je, false, settings
        );
        if (sub_field == NULL)
            return NULL;
        wmem_map_insert(field->additional_info, 0, sub_field);
        return field;
    } else if (g_strcmp0(type, "buffer") == 0) { // buffer
        if (cJSON_HasObjectItem(fields, "count")) {
            field->make_tree = make_tree_buffer;
            cJSON *count = cJSON_GetObjectItem(fields, "count");
            wmem_map_insert(field->additional_info, 0, GINT_TO_POINTER(count->valueint));
        } else
            field->make_tree = make_tree_var_buffer;
        return field;
    } else if (g_strcmp0(type, "mapper") == 0) { // mapper
        field->additional_info = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
        cJSON *type_data = cJSON_GetObjectItem(fields, "type");
        protocol_field sub_field = parse_protocol(
                basic_types, resolving_basics, type_data, types, is_je, false, settings
        );
        if (sub_field == NULL)
            return NULL;
        field->make_tree = make_tree_mapper;
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
    } else if (g_strcmp0(type, "array") == 0) { // array
        cJSON *count = cJSON_GetObjectItem(fields, "count");
        if (count != NULL)
            wmem_map_insert(
                    field->additional_info, 0,
                    g_strsplit(count->valuestring, "/", 10)
            );
        else {
            cJSON *count_type = cJSON_GetObjectItem(fields, "countType");
            if (count_type == NULL || g_strcmp0(count_type->valuestring, "varint") != 0) {
                ws_log(
                        "MC-Dissector",
                        LOG_LEVEL_CRITICAL,
                        "Invalid protocol data - Array count type is invalid: %s",
                        cJSON_Print(data)
                );
                return NULL;
            }
        }

        cJSON *type_data = cJSON_GetObjectItem(fields, "type");
        protocol_field sub_field = parse_protocol(
                basic_types, resolving_basics, type_data, types, is_je, false, settings
        );
        if (sub_field == NULL)
            return NULL;
        field->make_tree = make_tree_array;
        wmem_map_insert(field->additional_info, GINT_TO_POINTER(1), sub_field);
        return field;
    } else if (g_strcmp0(type, "bitfield") == 0) {
        int size = cJSON_GetArraySize(fields);
        wmem_map_insert(field->additional_info, GINT_TO_POINTER(-1), GINT_TO_POINTER(size));
        int total_bits = 0;
        for (int i = 0; i < size; i++) {
            cJSON *field_data = cJSON_GetArrayItem(fields, i);
            bool signed_ = cJSON_GetObjectItem(field_data, "signed")->valueint;
            int bits = cJSON_GetObjectItem(field_data, "size")->valueint;
            char *name = cJSON_GetObjectItem(field_data, "name")->valuestring;
            wmem_map_insert(field->additional_info, GINT_TO_POINTER(i * 3), GINT_TO_POINTER(bits));
            wmem_map_insert(field->additional_info, GINT_TO_POINTER(i * 3 + 1), GINT_TO_POINTER(signed_));
            wmem_map_insert(field->additional_info, GINT_TO_POINTER(i * 3 + 2), strdup(name));
            total_bits += bits;
        }
        field->make_tree = make_tree_bitfield;
        return field;
    } else if (g_strcmp0(type, "topBitSetTerminatedArray") == 0) {
        protocol_field sub_field = parse_protocol(
                basic_types, resolving_basics, cJSON_GetObjectItem(fields, "type"), types, is_je, false, settings
        );
        if (sub_field == NULL)
            return NULL;
        wmem_map_insert(field->additional_info, 0, sub_field);
        field->make_tree = make_tree_top_bit_set_terminated_array;
        return field;
    } else if (g_strcmp0(type, "switch") == 0) {
        char *compare_data = cJSON_GetObjectItem(fields, "compareTo")->valuestring;
        char **compare_data_split = g_strsplit(strdup(compare_data), "/", 10);
        field->additional_info = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
        wmem_map_insert(field->additional_info, strdup("__path"), compare_data_split);
        if (cJSON_HasObjectItem(fields, "default")) {
            cJSON *default_data = cJSON_GetObjectItem(fields, "default");
            protocol_field default_field = parse_protocol(
                    basic_types, resolving_basics, default_data, types, is_je, false, settings
            );
            if (default_field == NULL)
                return NULL;
            wmem_map_insert(field->additional_info, strdup("default"), default_field);
        }
        cJSON *cases = cJSON_GetObjectItem(fields, "fields");
        if (cases == NULL) {
            ws_log(
                    "MC-Dissector",
                    LOG_LEVEL_CRITICAL,
                    "Invalid protocol data - Switch cases not found: %s",
                    cJSON_Print(data)
            );
            return NULL;
        }
        cJSON *now = cases->child;
        while (now != NULL) {
            char *key = now->string;
            protocol_field value = parse_protocol(
                    basic_types, resolving_basics, now, types, is_je, false, settings
            );
            if (value == NULL)
                return NULL;
            wmem_map_insert(field->additional_info, strdup(key), value);
            now = now->next;
        }
        field->make_tree = make_tree_switch;
        return field;
    } else if (g_strcmp0(type, "entityMetadataLoop") == 0) {
        protocol_field sub_field = parse_protocol(
                basic_types, resolving_basics, cJSON_GetObjectItem(fields, "type"), types, is_je, false, settings
        );
        if (sub_field == NULL)
            return NULL;
        int end_val = cJSON_GetObjectItem(fields, "endVal")->valueint;
        wmem_map_insert(field->additional_info, GINT_TO_POINTER(0), sub_field);
        wmem_map_insert(field->additional_info, GINT_TO_POINTER(1), GINT_TO_POINTER(end_val));
        field->make_tree = make_tree_entity_metadata_loop;
        return field;
    } else if (cJSON_HasObjectItem(types, type)) {
        protocol_field_t *type_data = wmem_map_lookup(basic_types, type);
        if (type_data == NULL) {
            type_data = parse_protocol(
                    basic_types, resolving_basics, cJSON_GetObjectItem(types, type), types, is_je, false, settings
            );
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

    ws_log(
            "MC-Dissector",
            LOG_LEVEL_ERROR,
            "Invalid protocol data - Unknown type: %s",
            cJSON_Print(data)
    );
    return NULL;
}

void make_simple_protocol(cJSON *data, cJSON *types, wmem_map_t *packet_map, wmem_map_t *name_map, bool is_je,
                          protocol_settings settings) {
    cJSON *packets = cJSON_GetObjectItem(data, "packet");
    // Path: [1].[0].type.[1].mappings
    cJSON *c1 = cJSON_GetArrayItem(packets, 1);
    cJSON *c2 = cJSON_GetArrayItem(c1, 0);
    cJSON *c3 = cJSON_GetObjectItem(c2, "type");
    cJSON *c4 = cJSON_GetArrayItem(c3, 1);
    cJSON *mappings = cJSON_GetObjectItem(c4, "mappings");
    cJSON *now = mappings->child;

    wmem_map_t *basic_types = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    wmem_list_t *resolving_basics = wmem_list_new(wmem_epan_scope());
    while (now != NULL) {
        char *packet_id_str = now->string;
        gchar *packet_name = strdup(now->valuestring);
        char *ptr;
        guint packet_id = (guint) strtol(packet_id_str + 2, &ptr, 16);
        wmem_map_insert(name_map, packet_name, GUINT_TO_POINTER(packet_id + 1));

        protocol_entry entry = wmem_new(wmem_epan_scope(), protocol_entry_t);
        entry->id = packet_id;
        entry->name = packet_name;
        entry->is_je = is_je;
        wmem_map_insert(packet_map, GUINT_TO_POINTER(packet_id), entry);

        gchar *packet_definition = g_strconcat("packet_", packet_name, NULL);
        cJSON *item = cJSON_GetObjectItem(data, packet_definition);

        if (item != NULL) {
            entry->field = parse_protocol(basic_types, resolving_basics, item, types, is_je, true, settings);
        } else {
            protocol_field field = wmem_new(wmem_epan_scope(), protocol_field_t);
            field->make_tree = make_tree_void;
            entry->field = field;
        }
        g_free(packet_definition);

        now = now->next;
    }
    wmem_free(wmem_epan_scope(), basic_types);
    wmem_destroy_list(resolving_basics);
}

protocol_set create_protocol_set(cJSON *types, cJSON *data, bool is_je, protocol_settings settings) {
    protocol_set set = wmem_new(wmem_epan_scope(), protocol_set_t);
    set->client_packet_map = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
    set->server_packet_map = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
    set->client_name_map = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    set->server_name_map = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);

    cJSON *to_client = cJSON_GetObjectItem(cJSON_GetObjectItem(data, "toClient"), "types");
    cJSON *to_server = cJSON_GetObjectItem(cJSON_GetObjectItem(data, "toServer"), "types");
    make_simple_protocol(to_client, types, set->client_packet_map, set->client_name_map, is_je, settings);
    make_simple_protocol(to_server, types, set->server_packet_map, set->server_name_map, is_je, settings);

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

bool make_tree(protocol_entry entry, proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, extra_data *extra,
               gint remaining) {
    if (entry->field != NULL) {
        data_recorder recorder = create_data_recorder(pinfo->pool);
        guint len = entry->field->make_tree(
                tree, pinfo, tvb, extra, entry->field, 1, remaining - 1, recorder,
                entry->is_je
        );
        if (len != remaining - 1)
            proto_tree_add_string_format_value(
                    tree, hf_invalid_data_je, tvb, 1, remaining - 1,
                    "length mismatch", "Packet length mismatch, expected %d, got %d", len,
                    remaining - 1
            );
        return true;
    }
    return false;
}