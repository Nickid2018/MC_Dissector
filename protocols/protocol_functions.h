//
// Created by Nickid2018 on 2023/8/27.
//


#ifndef MC_DISSECTOR_PROTOCOL_FUNCTIONS_H
#define MC_DISSECTOR_PROTOCOL_FUNCTIONS_H

#include "protocol_schema.h"

#define FIELD_MAKE_TREE(name) \
    guint make_tree_##name(const guint8 *data, proto_tree *tree, tvbuff_t *tvb, extra_data *extra, \
    protocol_field field, guint offset, guint remaining, data_recorder recorder)

#define SINGLE_LENGTH_FIELD_MAKE(name, len, func_add, func_parse, record) \
    FIELD_MAKE_TREE(name) {                                               \
        if (tree)                                                         \
            func_add(tree, field->hf_index, tvb, offset, len, record(recorder, func_parse(tvb, offset))); \
        else                                                              \
            record(recorder, func_parse(tvb, offset));                    \
        return len;                                                       \
    }

#define DELEGATE_FIELD_MAKE(name) \
FIELD_MAKE_TREE(je_##name) { \
    return make_tree_##name(data, tree, tvb, extra, field, offset, remaining, recorder, true); \
} \
FIELD_MAKE_TREE(be_##name) { \
    return make_tree_##name(data, tree, tvb, extra, field, offset, remaining, recorder, false); \
}

#define DELEGATE_FIELD_MAKE_HEADER(name) \
guint make_tree_##name(const guint8 *data, proto_tree *tree, tvbuff_t *tvb, extra_data *extra,\
    protocol_field field, guint offset, guint remaining, data_recorder recorder, bool is_je)

#ifdef MC_DISSECTOR_FUNCTION_FEATURE

void init_protocol_functions();

FIELD_MAKE_TREE(record_entity_id);

FIELD_MAKE_TREE(record_entity_id_player);

FIELD_MAKE_TREE(record_entity_id_experience_orb);

FIELD_MAKE_TREE(record_entity_id_painting);

FIELD_MAKE_TREE(sync_entity_data);

FIELD_MAKE_TREE(entity_event);

#endif //MC_DISSECTOR_FUNCTION_FEATURE

#endif //MC_DISSECTOR_PROTOCOL_FUNCTIONS_H
