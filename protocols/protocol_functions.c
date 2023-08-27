//
// Created by Nickid2018 on 2023/8/27.
//

#ifdef MC_DISSECTOR_FUNCTION_FEATURE

#include <stdlib.h>
#include "strings_je.h"
#include "resources.h"
#include "protocol_functions.h"

wmem_map_t *entity_hierarchy;
wmem_map_t *entity_ids;

void init_entity_hierarchy() {
    entity_hierarchy = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    char **split = g_strsplit(RESOURCE_ENTITY_INHERIT_TREE, "\n", 1000);
    wmem_list_t *path_array = wmem_list_new(wmem_epan_scope());
    char *path = "";
    for (int i = 0; split[i] != NULL; i++) {
        char *now = split[i];
        wmem_list_frame_t *tail = wmem_list_tail(path_array);
        guint last_index;
        if (tail != NULL)
            last_index = GPOINTER_TO_UINT(wmem_list_frame_data(tail));
        else
            last_index = 0;
        if (strcmp(now, "-") == 0)
            wmem_list_remove(path_array, tail);
        else if (strcmp(now, "+") == 0)
            wmem_list_append(path_array, GUINT_TO_POINTER(strlen(path)));
        else {
            path = g_strconcat(g_strndup(path, last_index), "/", now, NULL);
            wmem_map_insert(entity_hierarchy, now, path);
        }
    }
    wmem_destroy_list(path_array);
    g_strfreev(split);
}

wmem_map_t *init_entity_ids(guint data_version) {
    char **lines = g_strsplit(RESOURCE_ENTITY_ID, "\n", 1000);
    int desc_counts = atoi(lines[0]);
    char **descs = g_strsplit(lines[1], " ", desc_counts);
    int versions = atoi(lines[2]);
    for (int i = versions - 1; i >= 0; i++) {
        char **version_data = g_strsplit(lines[3 + i * 2], " ", 2);
        int version_now = atoi(version_data[0]);
        if (version_now <= data_version) {
            int list_length = atoi(version_data[1]);
            g_strfreev(version_data);
            wmem_map_t *entity_id_data = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
            char **entity_id_list = g_strsplit(lines[4 + i * 2], " ", list_length);
            for (int in = 0; in < list_length; in++) {
                int entity_desc = atoi(entity_id_list[in]);
                char *entity_name = g_strdup(descs[entity_desc]);
                char *entity_id = g_strdup_printf("%d", in);
                wmem_map_insert(entity_id_data, entity_id, entity_name);
            }
            g_strfreev(entity_id_list);
            g_strfreev(lines);
            g_strfreev(descs);
            return entity_id_data;
        } else
            g_strfreev(version_data);
    }
    g_strfreev(lines);
    g_strfreev(descs);
    return wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
}

void init_protocol_functions() {
    init_entity_hierarchy();
    entity_ids = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
}

FIELD_MAKE_TREE(record_entity_id) {
    if (!extra->allow_write)
        return 0;
    char *id_path[] = {"entityId", NULL};
    gchar *id = record_query(recorder, id_path);
    char *type_path[] = {"type", NULL};
    gchar *type = record_query(recorder, type_path);
    wmem_map_t *entity_id_data = wmem_map_lookup(entity_ids, wmem_map_lookup(extra->data, "data_version"));
    if (entity_id_data == NULL) {
        entity_id_data = init_entity_ids(GPOINTER_TO_UINT(wmem_map_lookup(extra->data, "data_version")));
        wmem_map_insert(entity_ids, type, entity_id_data);
    }
    char *str_type = wmem_map_lookup(entity_id_data, type);
    wmem_map_t *entity_id_record = wmem_map_lookup(extra->data, "entity_id_record");
    if (entity_id_record == NULL) {
        entity_id_record = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
        wmem_map_insert(extra->data, "entity_id_record", entity_id_record);
    }
    wmem_map_insert(entity_id_record, id, str_type);
    if (tree)
        proto_tree_add_string(tree, get_string_je("entity_type_name", "string"), tvb, 0, 0, str_type);
    return 0;
}

FIELD_MAKE_TREE(sync_entity_data) {
    return 0;
}

#endif //MC_DISSECTOR_FUNCTION_FEATURE