//
// Created by Nickid2018 on 2023/8/27.
//

#ifdef MC_DISSECTOR_FUNCTION_FEATURE

#include <stdlib.h>
#include "resources.h"
#include "protocol_functions.h"
#include "protocol/storage/storage.h"

extern int hf_generated_je;

typedef struct {
    char *name;
    long min_version;
    long max_version;
} level_event_entry;

wmem_map_t *entity_ids;
wmem_map_t *entity_event;
wmem_map_t *level_event;

wmem_map_t *init_entity_ids(guint data_version) {
    char **lines = g_strsplit(RESOURCE_ENTITY_ID, "\n", 1000);
    int desc_counts = (int) strtol(lines[0], NULL, 10);
    char **descs = g_strsplit(lines[1], " ", desc_counts);
    int versions = (int) strtol(lines[2], NULL, 10);
    for (int i = versions - 1; i >= 0; i--) {
        char **version_data = g_strsplit(lines[3 + i * 2], " ", 2);
        long version_now = strtol(version_data[0], NULL, 10);
        if (version_now <= data_version) {
            int list_length = (int) strtol(version_data[1], NULL, 10);
            g_strfreev(version_data);
            wmem_map_t *entity_id_data = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
            char **entity_id_list = g_strsplit(lines[4 + i * 2], " ", list_length);
            for (int in = 0; in < list_length; in++) {
                long entity_desc = strtol(entity_id_list[in], NULL, 10);
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

void init_events() {
    entity_event = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    level_event = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    char **split = g_strsplit(RESOURCE_ENTITY_EVENT, "\n", 256);
    for (int i = 0; split[i] != NULL; i++) {
        char *now = split[i];
        wmem_map_insert(entity_event, g_strdup_printf("%d", i + 1), g_strdup(now));
    }
    g_strfreev(split);
    split = g_strsplit(RESOURCE_LEVEL_EVENT, "\n", 1000);
    for (int i = 0; split[i] != NULL; i++) {
        char *now = split[i];
        char **split_now = g_strsplit(now, " ", 2);
        char **versions = g_strsplit(split_now[0], "|", 3);
        char *event = versions[0];
        long min_version = 0, max_version = 0x7fffffff;
        if (versions[1] != NULL) {
            min_version = strtol(versions[1], NULL, 10);
            if (versions[2] != NULL)
                max_version = strtol(versions[2], NULL, 10);
        }
        wmem_list_t *event_data = wmem_map_lookup(level_event, event);
        if (event_data == NULL) {
            event_data = wmem_list_new(wmem_epan_scope());
            wmem_map_insert(level_event, g_strdup(event), event_data);
        }
        level_event_entry *entry = wmem_new(wmem_epan_scope(), level_event_entry);
        entry->name = g_strdup(split_now[1]);
        entry->min_version = min_version;
        entry->max_version = max_version;
        wmem_list_append(event_data, entry);
        g_strfreev(split_now);
        g_strfreev(versions);
    }
    g_strfreev(split);
}

void init_protocol_functions() {
    init_events();
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
    if (tree) {
        proto_item *item = proto_tree_add_string(tree, hf_generated_je, tvb, 0, 0, str_type);
        proto_item_set_generated(item);
        proto_item_prepend_text(item, "Entity Type");
    }
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

FIELD_MAKE_TREE(record_entity_id_painting) {
    wmem_map_t *entity_id_record = wmem_map_lookup(extra->data, "entity_id_record");
    if (entity_id_record == NULL) {
        entity_id_record = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
        wmem_map_insert(extra->data, "entity_id_record", entity_id_record);
    }
    char *id_path[] = {"entityId", NULL};
    gchar *id = record_query(recorder, id_path);
    wmem_map_insert(entity_id_record, id, "painting");
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
    guint protocol_version = GPOINTER_TO_UINT(wmem_map_lookup(extra->data, "protocol_version"));
    guint key_int = strtol(key, NULL, 10);
    char *type = wmem_map_lookup(entity_id_record, id);
    if (type != NULL) {
        proto_item *item = proto_tree_add_string(tree, hf_generated_je, tvb, 0, 0, type);
        proto_item_set_generated(item);
        proto_item_prepend_text(item, "Entity Type");
    } else {
        proto_item *item = proto_tree_add_string(tree, hf_generated_je, tvb, 0, 0, "Unknown");
        proto_item_set_generated(item);
        proto_item_prepend_text(item, "Entity Type");
        return 0;
    }
    gchar *found_name = get_entity_sync_data_name(protocol_version, type, key_int);
    if (found_name == NULL)
        found_name = "Unknown Sync Data!";
    proto_item *item = proto_tree_add_string(tree, hf_generated_je, tvb, 0, 0, found_name);
    proto_item_set_generated(item);
    proto_item_prepend_text(item, "Sync Data Type");
    return 0;
}

FIELD_MAKE_TREE(entity_event) {
    if (!tree)
        return 0;
    char *event_id_path[] = {"entityStatus", NULL};
    gchar *event_id = record_query(recorder, event_id_path);
    gchar *event_name = wmem_map_lookup(entity_event, event_id);
    if (event_name == NULL)
        event_name = "Unknown";
    proto_item *item = proto_tree_add_string(tree, hf_generated_je, tvb, 0, 0, event_name);
    proto_item_set_generated(item);
    proto_item_prepend_text(item, "Entity Event Type");
    return 0;
}

FIELD_MAKE_TREE(level_event) {
    if (!tree)
        return 0;
    char *event_id_path[] = {"effectId", NULL};
    gchar *event_id = record_query(recorder, event_id_path);
    wmem_list_t *event_data = wmem_map_lookup(level_event, event_id);
    char *event_name = "Unknown";
    if (event_data != NULL) {
        guint data_version = GPOINTER_TO_UINT(wmem_map_lookup(extra->data, "data_version"));
        wmem_list_frame_t *entry = wmem_list_head(event_data);
        while (entry != NULL) {
            level_event_entry *entry_data = wmem_list_frame_data(entry);
            if (entry_data->min_version <= data_version && data_version <= entry_data->max_version) {
                event_name = entry_data->name;
                break;
            }
            entry = wmem_list_frame_next(entry);
        }
    }
    proto_item *item = proto_tree_add_string(tree, hf_generated_je, tvb, 0, 0, event_name);
    proto_item_set_generated(item);
    proto_item_prepend_text(item, "Level Event Type");
    return 0;
}

#endif // MC_DISSECTOR_FUNCTION_FEATURE