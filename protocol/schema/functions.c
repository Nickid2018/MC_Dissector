//
// Created by nickid2018 on 24-9-20.
//

#include <epan/conversation.h>
#include "functions.h"
#include "protocol/storage/storage.h"
#include "protocol/protocol_data.h"
#include "utils/nbt.h"

extern int hf_generated_je;
extern int hf_invalid_data_je;

DISSECT_PROTOCOL(record_entity_id) {
    if (!get_settings_flag("registries") && !get_settings_flag("entities"))
        return 0;
    wmem_map_t *entity_id_record = wmem_map_lookup(get_global_data(pinfo), "#entity_id_record");
    if (entity_id_record == NULL) {
        entity_id_record = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
        wmem_map_insert(get_global_data(pinfo), "#entity_id_record", entity_id_record);
    }
    char *entity_id = wmem_map_lookup(packet_saves, "entity_id");
    char *entity_type = wmem_map_lookup(packet_saves, "entity_type");
    wmem_map_insert(
        entity_id_record,
        wmem_strdup(wmem_file_scope(), entity_id),
        wmem_strdup(wmem_file_scope(), entity_type)
    );
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
    char *entity_id = wmem_map_lookup(packet_saves, "entity_id");
    wmem_map_insert(entity_id_record, wmem_strdup(wmem_file_scope(), entity_id), "player");
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
    char *entity_id = wmem_map_lookup(packet_saves, "entity_id");
    wmem_map_insert(entity_id_record, wmem_strdup(wmem_file_scope(), entity_id), "experience_orb");
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
    char *entity_id = wmem_map_lookup(packet_saves, "entity_id");
    wmem_map_insert(entity_id_record, wmem_strdup(wmem_file_scope(), entity_id), "painting");
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
    char *entity_id = wmem_map_lookup(packet_saves, "entity_id");
    char *type = wmem_map_lookup(entity_id_record, entity_id);
    if (type != NULL) {
        proto_item *item = proto_tree_add_string(tree, hf_generated_je, tvb, 0, 0, type);
        proto_item_set_generated(item);
        proto_item_prepend_text(item, "Entity Type ");
    } else {
        proto_item *item = proto_tree_add_string(tree, hf_generated_je, tvb, 0, 0, "Unknown");
        proto_item_set_generated(item);
        proto_item_prepend_text(item, "Entity Type ");
        return 0;
    }
    char *sync_id = wmem_map_lookup(packet_saves, "sync_id");
    char *end;
    int64_t sync = strtol(sync_id, &end, 10);
    uint32_t protocol_version = (uint64_t) wmem_map_lookup(get_global_data(pinfo), "protocol_version");
    char *found_name = get_entity_sync_data_name(dissector->settings->storage, protocol_version, type, sync);
    if (found_name == NULL)
        found_name = "Unknown Sync Data!";
    proto_item *item = proto_tree_add_string(tree, hf_generated_je, tvb, 0, 0, found_name);
    proto_item_set_generated(item);
    proto_item_prepend_text(item, "Sync Data Type ");
    return 0;
}

DISSECT_PROTOCOL(display_protocol_version) {
    if (!tree) return 0;
    char *protocol_version_str = wmem_map_lookup(packet_saves, "protocol_version");
    char *end;
    uint32_t protocol_version = strtoll(protocol_version_str, &end, 10);
    char **java_versions = get_mapped_readable_versions(dissector->settings->storage, protocol_version);
    proto_item *item;
    if (java_versions == NULL || java_versions[0] == NULL) {
        item = proto_tree_add_string(tree, hf_generated_je, tvb, 0, 0, "Unknown Protocol Version");
    } else {
        char *java_version = g_strjoinv(", ", java_versions);
        g_strfreev(java_versions);
        item = proto_tree_add_string(tree, hf_generated_je, tvb, 0, 0, wmem_strdup(wmem_file_scope(), java_version));
        g_free(java_version);
    }
    proto_item_set_generated(item);
    proto_item_prepend_text(item, "Game Version ");
    return 0;
}

DISSECT_PROTOCOL(legacy_registry_holder) {
    wmem_map_t *writable_registry = wmem_map_lookup(get_global_data(pinfo), "#writable_registry");
    wmem_map_t *writable_registry_size = wmem_map_lookup(get_global_data(pinfo), "#writable_registry_size");
    if (writable_registry == NULL) {
        writable_registry = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
        wmem_map_insert(get_global_data(pinfo), "#writable_registry", writable_registry);
    }
    if (writable_registry_size == NULL) {
        writable_registry_size = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
        wmem_map_insert(get_global_data(pinfo), "#writable_registry_size", writable_registry_size);
    }
    // 0A 00 00
    offset += 3;
    while (tvb_get_int8(tvb, offset) == TAG_COMPOUND) {
        offset++;
        int32_t name_length = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
        offset += 2;
        char *registry_name = tvb_format_text(wmem_file_scope(), tvb, offset, name_length);
        int64_t length = g_utf8_strlen(registry_name, 400);
        int64_t split_pos = length - 1;
        for (; split_pos >= 0; split_pos--)
            if (registry_name[split_pos] == '/' || registry_name[split_pos] == ':')
                break;
        char *registry = g_utf8_substring(registry_name, split_pos + 1, length);
        char *copy = wmem_strdup(wmem_file_scope(), registry);
        g_free(registry);
        registry = copy;
        offset += name_length;
        // 08 00 04 74 79 70 65 = STRING type
        offset += 7;
        // Skip type name
        offset += count_je_nbt_length_with_type(tvb, offset,TAG_STRING);
        // 09 00 05 76 61 6C 75 65 0A = ARRAY value
        offset += 9;
        int32_t array_length = tvb_get_int32(tvb, offset, ENC_BIG_ENDIAN);
        offset += 4;
        char **data = wmem_alloc(wmem_file_scope(), sizeof(char *) * array_length);
        for (int i = 0; i < array_length; i++) {
            // 08 00 04 6E 61 6D 65 = STRING name
            offset += 7;
            int32_t item_length = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            offset += 2;
            char *item = tvb_format_text(wmem_file_scope(), tvb, offset, item_length);
            offset += item_length;
            // 03 00 02 69 64 XX XX XX XX = INT id
            offset += 9;
            // 0A 00 07 65 6C 65 6D 65 6E 74 = COMPOUND element
            offset += 10;
            // Skip compound
            offset += count_je_nbt_length_with_type(tvb, offset, TAG_COMPOUND);
            // TAG_END
            offset += 1;
            char *sub = g_utf8_substring(item, 10, g_utf8_strlen(item, 400));
            data[i] = wmem_strdup(wmem_file_scope(), sub);
            g_free(sub);
        }
        wmem_map_insert(writable_registry, registry, data);
        wmem_map_insert(writable_registry_size, registry, (void *) (uint64_t) array_length);
        // TAG_END
        offset += 1;
    }
    return 0;
}
