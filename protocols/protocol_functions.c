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
            wmem_list_remove_frame(path_array, tail);
        else if (strcmp(now, "+") == 0)
            wmem_list_append(path_array, GUINT_TO_POINTER(strlen(path)));
        else {
            path = g_strconcat(g_strndup(path, last_index), "/", now, NULL);
            wmem_map_insert(entity_hierarchy, g_strdup(now), g_strdup(path + 1));
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
    wmem_map_t *entity_id_record = wmem_map_lookup(extra->data, "entity_id_record");
    if (entity_id_record == NULL) {
        entity_id_record = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
        wmem_map_insert(extra->data, "entity_id_record", entity_id_record);
    }
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
    wmem_map_insert(entity_id_record, id, str_type);
    if (tree)
        proto_tree_add_string(tree, get_string_je("entity_type_name", "string"), tvb, 0, 0, str_type);
    return 0;
}

FIELD_MAKE_TREE(record_entity_id_player) {
    wmem_map_t *entity_id_record = wmem_map_lookup(extra->data, "entity_id_record");
    if (entity_id_record == NULL) {
        entity_id_record = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
        wmem_map_insert(extra->data, "entity_id_record", entity_id_record);
    }
    char *id_path[] = {"entityId", NULL};
    gchar *id = record_query(recorder, id_path);
    wmem_map_insert(entity_id_record, id, "player");
    return 0;
}

FIELD_MAKE_TREE(record_entity_id_experience_orb) {
    wmem_map_t *entity_id_record = wmem_map_lookup(extra->data, "entity_id_record");
    if (entity_id_record == NULL) {
        entity_id_record = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
        wmem_map_insert(extra->data, "entity_id_record", entity_id_record);
    }
    char *id_path[] = {"entityId", NULL};
    gchar *id = record_query(recorder, id_path);
    wmem_map_insert(entity_id_record, id, "experience_orb");
    return 0;
}

FIELD_MAKE_TREE(sync_entity_data) {
    if (!tree)
        return 0;
    wmem_map_t *entity_id_record = wmem_map_lookup(extra->data, "entity_id_record");
    if (entity_id_record == NULL) {
        entity_id_record = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
        wmem_map_insert(extra->data, "entity_id_record", entity_id_record);
    }
    char *id_path[] = {"..", "entityId", NULL};
    gchar *id = record_query(recorder, id_path);
    char *key_path[] = {"key", NULL};
    gchar *key = record_query(recorder, key_path);
    guint data_version = GPOINTER_TO_UINT(wmem_map_lookup(extra->data, "data_version"));
    guint key_int = atoi(key);
    char *type = wmem_map_lookup(entity_id_record, id);
    if (type != NULL)
        proto_tree_add_string(tree, get_string_je("entity_type_name", "string"), tvb, 0, 0, type);
    else {
        proto_tree_add_string(tree, get_string_je("entity_type_name", "string"), tvb, 0, 0, "Unknown");
        return 0;
    }
    char *hierarchy = wmem_map_lookup(entity_hierarchy, type);
    if (hierarchy == NULL)
        hierarchy = "";
    char **split = g_strsplit(hierarchy, "/", 1000);
    char **split_sync_data = g_strsplit(RESOURCE_SYNC_ENTITY_DATA, "\n", 1000);
    char *found_name = NULL;
    for (int now = 0; split[now] != NULL && found_name == NULL; now++) {
        char *now_type = split[now];
        for (int i = 0; split_sync_data[i * 2] != NULL && found_name == NULL; i++) {
            if (strcmp(now_type, split_sync_data[i * 2]) == 0) {
                char *sync_data = split_sync_data[i * 2 + 1];
                char **split_sync_data_now = g_strsplit(sync_data, ",", 1000);
                for (int j = 0; split_sync_data_now[j] != NULL; j++) {
                    char *entry = split_sync_data_now[j];
                    char **split_entry = g_strsplit(entry, " ", 10);
                    bool flag = true;
                    for (int flag_index = 1; split_entry[flag_index] != NULL; flag_index++) {
                        int flag_now = atoi(split_entry[flag_index]);
                        if (flag_now > 0) {
                            if (flag_now > data_version)
                                flag = false;
                        } else {
                            if (-flag_now < data_version)
                                flag = false;
                        }
                    }
                    if (flag) {
                        if (key_int == 0) {
                            found_name = g_strdup(split_entry[0]);
                            g_strfreev(split_entry);
                            break;
                        } else
                            key_int--;
                    }
                    g_strfreev(split_entry);
                }
                g_strfreev(split_sync_data_now);
            }
        }
    }
    g_strfreev(split);
    g_strfreev(split_sync_data);
    if (found_name == NULL)
        found_name = "Unknown Sync Data!";
    proto_tree_add_string(tree, get_string_je("sync_entity_data", "string"), tvb, 0, 0, found_name);
    return 0;
}

#endif //MC_DISSECTOR_FUNCTION_FEATURE