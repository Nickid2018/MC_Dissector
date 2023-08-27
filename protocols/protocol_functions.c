//
// Created by Nickid2018 on 2023/8/27.
//

#ifdef MC_DISSECTOR_FUNCTION_FEATURE

#include "resources.h"
#include "protocol_functions.h"

wmem_map_t *entity_hierarchy;

void init_entity_hierarchy() {
    entity_hierarchy = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
    char **split = g_strsplit(RESOURCE_ENTITY_INHERIT_TREE, "\n", 1000);
    wmem_list_t *path_array = wmem_list_new(wmem_file_scope());
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

void init_protocol_functions() {
    init_entity_hierarchy();
}

FIELD_MAKE_TREE(record_entity_id) {
    if (!extra->allow_write)
        return 0;
    char *id_path[] = {"entityId", NULL};
    gchar *id = record_query(recorder, id_path);
    char *type_path[] = {"type", NULL};
    gchar *type = record_query(recorder, type_path);
    return 0;
}

FIELD_MAKE_TREE(sync_entity_data) {
    return 0;
}

#endif //MC_DISSECTOR_FUNCTION_FEATURE