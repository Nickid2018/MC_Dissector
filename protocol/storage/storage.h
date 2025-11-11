//
// Created by nickid2018 on 24-7-13.
//

#ifndef MC_DISSECTOR_STORAGE_H
#define MC_DISSECTOR_STORAGE_H

#include "cJSON.h"
#include "protocol/schema/schema.h"

void clear_storage();

char **get_mapped_java_versions(uint32_t protocol_version);

int32_t get_data_version(char *java_version);

char *get_index(uint32_t protocol_version, char *item);

char *build_indexed_file_name(char *root, char *item, uint32_t protocol_version);

char *build_protocol_file_name(char *root, char *item, uint32_t protocol_version);

cJSON *get_protocol_source(uint32_t protocol_version);

cJSON *get_packet_source(uint32_t protocol_version, char *packet);

char *get_entity_sync_data_name(uint32_t protocol_version, char *entity_id, uint32_t index);

cJSON *get_registry(uint32_t protocol_version, char *registry);

char *get_registry_data(uint32_t protocol_version, char *registry, uint32_t index);

protocol_dissector_set *get_initial_protocol();

protocol_dissector_set *get_protocol_set(uint32_t protocol_version);

bool get_settings_flag(char *name);

bool is_compatible_protocol_data();

#endif //MC_DISSECTOR_STORAGE_H
