//
// Created by Nickid2018 on 2023/7/13.
//

#ifndef MC_DISSECTOR_PROTOCOL_SCHEMA_H
#define MC_DISSECTOR_PROTOCOL_SCHEMA_H

#include <epan/proto.h>
#include "../cJSON/cJSON.h"
#include "data_recorder.h"

typedef struct _protocol_set protocol_set_t, *protocol_set;
typedef struct _protocol_entry protocol_entry_t, *protocol_entry;
typedef struct _protocol_field protocol_field_t, *protocol_field;

void init_schema_data();

protocol_set create_protocol_set(cJSON *types, cJSON *data);

gchar *get_packet_name(protocol_entry entry);

gint get_packet_id_by_entry(protocol_entry entry);

gint get_packet_id(protocol_set set, gchar *name, bool is_client);

protocol_entry get_protocol_entry(protocol_set set, guint packet_id, bool is_client);

void make_tree(protocol_entry entry, proto_tree *tree, tvbuff_t *tvb, guint8 *data, guint remaining, data_recorder recorder);

#endif //MC_DISSECTOR_PROTOCOL_SCHEMA_H
