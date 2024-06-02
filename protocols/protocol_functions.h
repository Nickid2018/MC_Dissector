//
// Created by Nickid2018 on 2023/8/27.
//


#ifndef MC_DISSECTOR_PROTOCOL_FUNCTIONS_H
#define MC_DISSECTOR_PROTOCOL_FUNCTIONS_H

#include "protocol_schema.h"

#define FIELD_MAKE_TREE(name) \
gint make_tree_##name(proto_tree *tree, tvbuff_t *tvb, extra_data *extra, protocol_field field, gint offset, gint remaining, data_recorder recorder, bool is_je)

#define SINGLE_LENGTH_FIELD_MAKE(name, len, func_add, func_parse, record) \
    FIELD_MAKE_TREE(name) {                                               \
        if (tree)                                                         \
            func_add(tree, field->hf_index, tvb, offset, len, record(recorder, func_parse(tvb, offset))); \
        else                                                              \
            record(recorder, func_parse(tvb, offset));                    \
        return len;                                                       \
    }

#ifdef MC_DISSECTOR_FUNCTION_FEATURE

void init_protocol_functions();

FIELD_MAKE_TREE(record_entity_id);

FIELD_MAKE_TREE(record_entity_id_player);

FIELD_MAKE_TREE(record_entity_id_experience_orb);

FIELD_MAKE_TREE(record_entity_id_painting);

FIELD_MAKE_TREE(sync_entity_data);

FIELD_MAKE_TREE(entity_event);

FIELD_MAKE_TREE(level_event);

#endif //MC_DISSECTOR_FUNCTION_FEATURE

#endif //MC_DISSECTOR_PROTOCOL_FUNCTIONS_H
