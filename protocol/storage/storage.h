//
// Created by nickid2018 on 24-7-13.
//

#ifndef MC_DISSECTOR_STORAGE_H
#define MC_DISSECTOR_STORAGE_H

#include "cJSON.h"
#include "protocol/schema/schema.h"

typedef struct protocol_storage_struct protocol_storage;

protocol_storage *create_storage(char *root, protocol_dissector_settings *settings);

void clear_storage(protocol_storage *storage);

char **get_mapped_readable_versions(protocol_storage *storage, uint32_t protocol_version);

int32_t get_data_version(protocol_storage *storage, char *version);

char *get_index(protocol_storage *storage, uint32_t protocol_version, char *item);

char *build_indexed_file_name(protocol_storage *storage, char *root, char *item, uint32_t protocol_version);

char *build_protocol_file_name(protocol_storage *storage, char *root, char *item, uint32_t protocol_version);

cJSON *get_protocol_source(protocol_storage *storage, uint32_t protocol_version);

cJSON *get_packet_source(protocol_storage *storage, uint32_t protocol_version, char *packet);

char *get_entity_sync_data_name(protocol_storage *storage, uint32_t protocol_version, char *entity_id, uint32_t index);

cJSON *get_registry(protocol_storage *storage, uint32_t protocol_version, char *registry);

char *get_registry_data(protocol_storage *storage, uint32_t protocol_version, char *registry, uint32_t index);

protocol_dissector_set *get_initial_protocol(protocol_storage *storage);

protocol_dissector_set *get_protocol_set(protocol_storage *storage, uint32_t protocol_version);

// Global storage

bool get_settings_flag(char *name);

bool is_compatible_protocol_data();

#endif //MC_DISSECTOR_STORAGE_H
