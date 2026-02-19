//
// Created by nickid2018 on 24-9-14.
//

#ifndef MC_DISSECTOR_SCHEMA_H
#define MC_DISSECTOR_SCHEMA_H

#include <epan/proto.h>
#include <cJSON.h>

enum FieldsIndex {
    hf_int8 = 0,
    hf_uint8,
    hf_hint8,
    hf_int16,
    hf_uint16,
    hf_hint16,
    hf_int32,
    hf_uint32,
    hf_hint32,
    hf_varint,
    hf_int64,
    hf_uint64,
    hf_hint64,
    hf_varlong,
    hf_float,
    hf_double,
    hf_bytes,
    hf_string,
    hf_boolean,
    hf_uuid,
    hf_generated,
    hf_invalid_data,
    hf_parsing_error,
    hf_ignored_packet,
};

typedef struct protocol_dissector_struct protocol_dissector;
typedef struct protocol_dissector_set_struct protocol_dissector_set;
typedef struct protocol_dissector_settings_struct protocol_dissector_settings;

#define DISSECT_FUNCTION_SIG(name) int32_t (*name)(proto_tree *,packet_info *,tvbuff_t *,int,wmem_allocator_t *,protocol_dissector *,char *,wmem_map_t *,gchar **)

struct protocol_dissector_struct {
    protocol_dissector_settings *settings;
    wmem_map_t *dissect_arguments;

    DISSECT_FUNCTION_SIG(dissect_protocol);
};

struct protocol_dissector_set_struct {
    wmem_map_t *state_to_next;
    wmem_map_t *state_to_next_side;
    wmem_map_t *special_mark;
    wmem_map_t *dissectors_by_name;
    wmem_map_t *dissectors_by_state;
    wmem_map_t *count_by_state;
    wmem_map_t *registry_keys;
    wmem_map_t *readable_names;

    wmem_allocator_t *allocator;
    protocol_dissector_settings *settings;

    uint32_t protocol_version;
    bool valid;
};

struct protocol_dissector_settings_struct {
    // Dissector settings
    int hf_indexes[hf_ignored_packet + 1];
    int ett_tree;
    int endian;

    // Abstract states
    int total_states;
    char **state_names;

    // Storage
    void *storage;
};

#define DISSECT_ERROR (1 << 31)

protocol_dissector_set *create_protocol_with_json(
    cJSON *protocol_source, protocol_dissector_settings *settings, uint32_t protocol_version
);

protocol_dissector_set *create_protocol(uint32_t protocol_version, protocol_dissector_settings *settings);

void destroy_protocol(protocol_dissector_set *dissector_set);

#endif //MC_DISSECTOR_SCHEMA_H
