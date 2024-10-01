//
// Created by nickid2018 on 24-9-14.
//

#ifndef MC_DISSECTOR_SCHEMA_H
#define MC_DISSECTOR_SCHEMA_H

#include <epan/proto.h>
#include <cJSON.h>

typedef struct protocol_dissector_struct protocol_dissector;
typedef struct protocol_dissector_set_struct protocol_dissector_set;

#define DISSECT_FUNCTION_SIG(name) int32_t (*name)(proto_tree *,packet_info *,tvbuff_t *,int,wmem_allocator_t *,protocol_dissector *,char *,wmem_map_t *,gchar **)

struct protocol_dissector_struct {
    wmem_map_t *dissect_arguments;

    DISSECT_FUNCTION_SIG(dissect_protocol);
};

struct protocol_dissector_set_struct {
    uint32_t protocol_version;
    wmem_map_t *state_to_next;
    wmem_map_t *state_to_next_side;
    wmem_map_t *special_mark;
    wmem_map_t *dissectors_by_name;
    wmem_map_t *dissectors_by_state;
    wmem_map_t *count_by_state;
    wmem_map_t *registry_keys;
    wmem_map_t *readable_names;

    wmem_allocator_t *allocator;
};

#define DISSECT_ERROR (1 << 31)

uint32_t map_name_to_state(char *name);

char *map_state_to_name(uint32_t state);

protocol_dissector_set *create_protocol(uint32_t protocol_version);

void destroy_protocol(protocol_dissector_set *dissector_set);

#endif //MC_DISSECTOR_SCHEMA_H
