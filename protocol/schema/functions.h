//
// Created by nickid2018 on 24-9-20.
//

#ifndef MC_DISSECTOR_FUNCTIONS_H
#define MC_DISSECTOR_FUNCTIONS_H

#include "schema.h"

#define DISSECT_PROTOCOL(fn) \
int32_t dissect_##fn(           \
    proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset, wmem_allocator_t *packet_alloc, \
    protocol_dissector *dissector, char *name, wmem_map_t *packet_saves, char **value \
)

DISSECT_PROTOCOL(record_entity_id);

DISSECT_PROTOCOL(record_entity_id_player);

DISSECT_PROTOCOL(record_entity_id_experience_orb);

DISSECT_PROTOCOL(record_entity_id_painting);

DISSECT_PROTOCOL(sync_entity_data);

#endif //MC_DISSECTOR_FUNCTIONS_H
