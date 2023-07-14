//
// Created by Nickid2018 on 2023/7/13.
//

#include <stdlib.h>
#include "protocol_schema.h"
#include "../protocol_data.h"

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
    gchar *name;
    int hf_index;
    wmem_array_t *additional_info;

    guint (*make_tree)(guint8 *data, proto_tree *tree, tvbuff_t *tvb,
                       protocol_field field, guint offset, guint remaining, data_recorder recorder);
};

// ---------------------------------- Native Fields ----------------------------------
#define FIELD_MAKE_TREE(name) \
    guint make_tree_##name(guint8 *data, proto_tree *tree, tvbuff_t *tvb, \
    protocol_field field, guint offset, guint remaining, data_recorder recorder)

FIELD_MAKE_TREE(var_int) {
    guint result;
    guint length = read_var_int(data + offset, remaining, &result);
    if (tree)
        proto_tree_add_uint(tree, field->hf_index, tvb, offset, length, result);
    return length;
}

FIELD_MAKE_TREE(var_long) {
    guint64 result;
    guint length = read_var_long(data + offset, remaining, &result);
    if (tree)
        proto_tree_add_uint64(tree, field->hf_index, tvb, offset, length, result);
    return length;
}

FIELD_MAKE_TREE(string) {
    guint8 *str;
    guint length = read_buffer(data + offset, &str);
    if (tree)
        proto_tree_add_string(tree, field->hf_index, tvb, offset, length, str);
    return length;
}

FIELD_MAKE_TREE(buffer) {
    guint8 *str;
    guint length = read_buffer(data + offset, &str);
    if (tree)
        proto_tree_add_bytes(tree, field->hf_index, tvb, offset, length, str);
    return length;
}

#define SINGLE_LENGTH_FIELD_MAKE(name, len, func_add, func_parse, record) \
    FIELD_MAKE_TREE(name) { \
        if (tree) \
            func_add(tree, field->hf_index, tvb, offset, len, record(recorder, func_parse(tvb, offset))); \
        else \
            record(recorder, func_parse(tvb, offset)); \
        return len; \
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

SINGLE_LENGTH_FIELD_MAKE(boolean, 1, proto_tree_add_boolean, tvb_get_guint8, record_uint)

FIELD_MAKE_TREE(rest_buffer) {
    if (tree)
        proto_tree_add_bytes(tree, field->hf_index, tvb, offset, remaining,
                             record(recorder, tvb_memdup(wmem_packet_scope(), tvb, offset, remaining)));
    return remaining;
}

FIELD_MAKE_TREE(uuid) {
    if (tree)
        proto_tree_add_guid(tree, field->hf_index, tvb, offset, 16,
                            record(recorder, tvb_memdup(wmem_packet_scope(), tvb, offset, 16)));
    return 16;
}

FIELD_MAKE_TREE(void) {
    return 0;
}

FIELD_MAKE_TREE(container) {
    bool not_top = field->name != NULL;
    if (not_top)
        record_push(recorder);
    if (tree && not_top) {
        // TODO
    }
    guint length = wmem_array_get_count(field->additional_info);
    for (guint i = 0; i < length; i++) {
        protocol_field sub_field = wmem_array_index(field->additional_info, i);
        record_start(recorder, sub_field->name);
        guint sub_length = sub_field->make_tree(data, tree, tvb, sub_field, offset, remaining, recorder);
        offset += sub_length;
        remaining -= sub_length;
    }
    if (not_top)
        record_pop(recorder);
}

// ------------------------------- End of Native Fields --------------------------------

wmem_map_t *native_make_tree_map = NULL;

#define ADD_NATIVE(json_name, make_name) \
    wmem_map_insert(native_make_tree_map, #json_name, make_tree_##make_name);

void init_schema_data() {
    native_make_tree_map = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);

    ADD_NATIVE(varint, var_int)
    ADD_NATIVE(varlong, var_long)
    ADD_NATIVE(string, string)
    ADD_NATIVE(buffer, buffer)
    ADD_NATIVE(u8, u8)
    ADD_NATIVE(u16, u16)
    ADD_NATIVE(u32, u32)
    ADD_NATIVE(u64, u64)
    ADD_NATIVE(i8, i8)
    ADD_NATIVE(i16, i16)
    ADD_NATIVE(i32, i32)
    ADD_NATIVE(i64, i64)
    ADD_NATIVE(bool, boolean)
    ADD_NATIVE(f32, f32)
    ADD_NATIVE(f64, f64)
    ADD_NATIVE(uuid, uuid)
    ADD_NATIVE(restBuffer, rest_buffer)
    ADD_NATIVE(void, void)
}

protocol_field parse_protocol(cJSON *data, cJSON *types) {
    if (cJSON_GetArraySize(data) != 2)
        return NULL;
    char *type = cJSON_GetArrayItem(data, 0)->valuestring;

    if (cJSON_HasObjectItem(types, type))
        return parse_protocol(cJSON_GetObjectItem(types, type), types);

    protocol_field field = wmem_new(wmem_file_scope(), protocol_field_t);
    field->additional_info = NULL;
    field->hf_index = -1;

    void *make_tree_func = wmem_map_lookup(native_make_tree_map, type);

    if (make_tree_func != NULL) {
        // natives
        field->make_tree = make_tree_func;
    } else {
        // container
        if (strcmp(type, "container") == 0) {
            cJSON *fields = cJSON_GetArrayItem(data, 1);
            field->additional_info = wmem_array_new(wmem_file_scope(), sizeof(protocol_field_t));
            field->make_tree = make_tree_container;
            int size = cJSON_GetArraySize(fields);
            for (int i = 0; i < size; i++) {
                cJSON *field_data = cJSON_GetArrayItem(fields, i);
                protocol_field sub_field = parse_protocol(field_data, types);
                if (sub_field == NULL)
                    return NULL;
                sub_field->name = strdup(cJSON_GetObjectItem(field_data, "name")->valuestring);
                wmem_array_append_one(field->additional_info, sub_field);
            }
        }
    }
}

void make_simple_protocol(cJSON *data, cJSON *types, wmem_map_t *packet_map, wmem_map_t *name_map) {
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
        entry->field = parse_protocol(cJSON_GetObjectItem(data, packet_definition), types);
        g_free(packet_definition);

        now = now->next;
    }
}

protocol_set create_protocol_set(cJSON *types, cJSON *data) {
    protocol_set set = wmem_new(wmem_file_scope(), protocol_set_t);
    set->client_packet_map = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    set->server_packet_map = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    set->client_name_map = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
    set->server_name_map = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);

    cJSON *to_client = cJSON_GetObjectItem(cJSON_GetObjectItem(data, "toClient"), "types");
    cJSON *to_server = cJSON_GetObjectItem(cJSON_GetObjectItem(data, "toServer"), "types");
    make_simple_protocol(to_client, types, set->client_packet_map, set->client_name_map);
    make_simple_protocol(to_server, types, set->server_packet_map, set->server_name_map);

    return set;
}

gchar *get_packet_name(protocol_entry entry) {
    return entry == NULL ? "Unknown" : entry->name;
}

gint get_packet_id_by_entry(protocol_entry entry) {
    return entry == NULL ? -1 : (int) entry->id;
}

gint get_packet_id(protocol_set set, gchar *name, bool is_client) {
    wmem_map_t *name_map = is_client ? set->client_packet_map : set->server_name_map;
    return GPOINTER_TO_INT(wmem_map_lookup(name_map, name)) - 1;
}

protocol_entry get_protocol_entry(protocol_set set, guint packet_id, bool is_client) {
    wmem_map_t *packet_map = is_client ? set->client_packet_map : set->server_packet_map;
    return wmem_map_lookup(packet_map, GUINT_TO_POINTER(packet_id));
}

void make_tree(protocol_entry entry, proto_tree *tree, tvbuff_t *tvb, guint8 *data, guint remaining, data_recorder recorder) {
    entry->field->make_tree(data, tree, tvb, entry->field, 0, remaining, recorder);
}