//
// Created by nickid2018 on 24-9-20.
//

#include <epan/conversation.h>
#include "functions.h"
#include "protocol/storage/storage.h"
#include "protocol/protocol_data.h"

extern int hf_generated;
extern int hf_invalid_data;

DISSECT_PROTOCOL(record_entity_id) {
    if (!get_settings_flag("registries") && !get_settings_flag("entities"))
        return 0;
    wmem_map_t *entity_id_record = wmem_map_lookup(get_global_data(pinfo), "#entity_id_record");
    if (entity_id_record == NULL) {
        entity_id_record = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
        wmem_map_insert(get_global_data(pinfo), "#entity_id_record", entity_id_record);
    }
    gchar *entity_id = wmem_map_lookup(packet_saves, "entity_id");
    gchar *str_type = wmem_map_lookup(packet_saves, "entity_type");
    wmem_map_insert(entity_id_record, entity_id, str_type);
    return 0;
}

DISSECT_PROTOCOL(record_entity_id_player) {
    if (!get_settings_flag("registries") && !get_settings_flag("entities"))
        return 0;
    wmem_map_t *entity_id_record = wmem_map_lookup(get_global_data(pinfo), "#entity_id_record");
    if (entity_id_record == NULL) {
        entity_id_record = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
        wmem_map_insert(get_global_data(pinfo), "#entity_id_record", entity_id_record);
    }
    gchar *entity_id = wmem_map_lookup(packet_saves, "entity_id");
    wmem_map_insert(entity_id_record, entity_id, "player");
    return 0;
}

DISSECT_PROTOCOL(record_entity_id_experience_orb) {
    if (!get_settings_flag("registries") && !get_settings_flag("entities"))
        return 0;
    wmem_map_t *entity_id_record = wmem_map_lookup(get_global_data(pinfo), "#entity_id_record");
    if (entity_id_record == NULL) {
        entity_id_record = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
        wmem_map_insert(get_global_data(pinfo), "#entity_id_record", entity_id_record);
    }
    gchar *entity_id = wmem_map_lookup(packet_saves, "entity_id");
    wmem_map_insert(entity_id_record, entity_id, "experience_orb");
    return 0;
}

DISSECT_PROTOCOL(record_entity_id_painting) {
    if (!get_settings_flag("registries") && !get_settings_flag("entities"))
        return 0;
    wmem_map_t *entity_id_record = wmem_map_lookup(get_global_data(pinfo), "#entity_id_record");
    if (entity_id_record == NULL) {
        entity_id_record = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
        wmem_map_insert(get_global_data(pinfo), "#entity_id_record", entity_id_record);
    }
    gchar *entity_id = wmem_map_lookup(packet_saves, "entity_id");
    wmem_map_insert(entity_id_record, entity_id, "painting");
    return 0;
}

DISSECT_PROTOCOL(sync_entity_data) {
    if (!tree || !get_settings_flag("entity_sync_datas"))
        return 0;
    wmem_map_t *entity_id_record = wmem_map_lookup(get_global_data(pinfo), "#entity_id_record");
    if (entity_id_record == NULL) {
        entity_id_record = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
        wmem_map_insert(get_global_data(pinfo), "#entity_id_record", entity_id_record);
    }
    gchar *entity_id = wmem_map_lookup(packet_saves, "entity_id");
    char *type = wmem_map_lookup(entity_id_record, entity_id);
    if (type != NULL) {
        proto_item *item = proto_tree_add_string(tree, hf_generated, tvb, 0, 0, type);
        proto_item_set_generated(item);
        proto_item_prepend_text(item, "Entity Type ");
    } else {
        proto_item *item = proto_tree_add_string(tree, hf_generated, tvb, 0, 0, "Unknown");
        proto_item_set_generated(item);
        proto_item_prepend_text(item, "Entity Type ");
        return 0;
    }
    gchar *sync_id = wmem_map_lookup(packet_saves, "sync_id");
    gchar *end;
    int64_t sync = strtol(sync_id, &end, 10);
    uint32_t protocol_version = (uint64_t) wmem_map_lookup(get_global_data(pinfo), "protocol_version");
    gchar *found_name = get_entity_sync_data_name(protocol_version, type, sync);
    if (found_name == NULL)
        found_name = "Unknown Sync Data!";
    proto_item *item = proto_tree_add_string(tree, hf_generated, tvb, 0, 0, found_name);
    proto_item_set_generated(item);
    proto_item_prepend_text(item, "Sync Data Type ");
    return 0;
}