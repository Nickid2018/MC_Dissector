//
// Created by nickid2018 on 24-7-13.
//

#ifndef MC_DISSECTOR_STORAGE_H
#define MC_DISSECTOR_STORAGE_H

#include "cJSON.h"
#include "mc_dissector.h"

void clear_storage();

gchar **get_mapped_java_versions(uint32_t protocol_version);

int32_t get_data_version(gchar *java_version);

gchar *get_index(uint32_t protocol_version, gchar *item);

gchar *build_indexed_file_name(gchar *root, gchar *item, uint32_t protocol_version);

cJSON *get_protocol_source(uint32_t protocol_version);

gchar *get_entity_sync_data_name(uint32_t protocol_version, gchar *entity_id, uint32_t index);

gchar *get_registry_data(uint32_t protocol_version, gchar *registry, uint32_t index);

bool get_settings_flag(gchar *name);

bool is_compatible_protocol_data();

#endif //MC_DISSECTOR_STORAGE_H
