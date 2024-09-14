//
// Created by Nickid2018 on 2023/8/27.
//

#include "protocol_functions.h"
#include "protocol/storage/storage.h"

extern int hf_generated;

FIELD_MAKE_TREE(record_entity_id) {
    if (!get_settings_flag("registries") && !get_settings_flag("entities"))
        return 0;
    wmem_map_t *entity_id_record = wmem_map_lookup(extra->data, "entity_id_record");
    if (entity_id_record == NULL) {
        entity_id_record = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
        wmem_map_insert(extra->data, "entity_id_record", entity_id_record);
    }
    char *id_path[] = {"entityId", NULL};
    gchar *id = record_query(recorder, id_path);
    char *type_path[] = {"type", NULL};
    gchar *type = record_query(recorder, type_path);
    guint protocol_version = GPOINTER_TO_UINT(wmem_map_lookup(extra->data, "protocol_version"));
    guint type_uint = strtol(type, NULL, 10);
    char *str_type = get_registry_data(protocol_version, "entity_type", type_uint);
    wmem_map_insert(entity_id_record, id, str_type);
    if (tree) {
        proto_item *item = proto_tree_add_string(tree, hf_generated, tvb, 0, 0, str_type);
        proto_item_set_generated(item);
        proto_item_prepend_text(item, "Entity Type");
    }
    return 0;
}

FIELD_MAKE_TREE(record_entity_id_player) {
    if (!get_settings_flag("registries") && !get_settings_flag("entities"))
        return 0;
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
    if (!get_settings_flag("registries") && !get_settings_flag("entities"))
        return 0;
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
    if (!get_settings_flag("registries") && !get_settings_flag("entities"))
        return 0;
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
    if (!tree || !get_settings_flag("entity_sync_datas"))
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
        proto_item *item = proto_tree_add_string(tree, hf_generated, tvb, 0, 0, type);
        proto_item_set_generated(item);
        proto_item_prepend_text(item, "Entity Type");
    } else {
        proto_item *item = proto_tree_add_string(tree, hf_generated, tvb, 0, 0, "Unknown");
        proto_item_set_generated(item);
        proto_item_prepend_text(item, "Entity Type");
        return 0;
    }
    gchar *found_name = get_entity_sync_data_name(protocol_version, type, key_int);
    if (found_name == NULL)
        found_name = "Unknown Sync Data!";
    proto_item *item = proto_tree_add_string(tree, hf_generated, tvb, 0, 0, found_name);
    proto_item_set_generated(item);
    proto_item_prepend_text(item, "Sync Data Type");
    return 0;
}

FIELD_MAKE_TREE(entity_event) {
    if (!tree || !get_settings_flag("events"))
        return 0;
    char *event_id_path[] = {"entityStatus", NULL};
    gchar *event_id = record_query(recorder, event_id_path);
    gchar *event_name = get_entity_event_data(
            GPOINTER_TO_UINT(wmem_map_lookup(extra->data, "protocol_version")),
            event_id
    );
    if (event_name == NULL)
        event_name = "Unknown";
    proto_item *item = proto_tree_add_string(tree, hf_generated, tvb, 0, 0, event_name);
    proto_item_set_generated(item);
    proto_item_prepend_text(item, "Entity Event Type");
    return 0;
}

FIELD_MAKE_TREE(level_event) {
    if (!tree || !get_settings_flag("events"))
        return 0;
    char *event_id_path[] = {"effectId", NULL};
    gchar *event_id = record_query(recorder, event_id_path);
    gchar *event_name = get_level_event_data(
            GPOINTER_TO_UINT(wmem_map_lookup(extra->data, "protocol_version")),
            event_id
    );
    if (event_name == NULL)
        event_name = "Unknown";
    proto_item *item = proto_tree_add_string(tree, hf_generated, tvb, 0, 0, event_name);
    proto_item_set_generated(item);
    proto_item_prepend_text(item, "Level Event Type");
    return 0;
}