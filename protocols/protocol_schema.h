//
// Created by Nickid2018 on 2023/7/13.
//

#ifndef MC_DISSECTOR_PROTOCOL_SCHEMA_H
#define MC_DISSECTOR_PROTOCOL_SCHEMA_H

#include <epan/proto.h>
#include "../cJSON/cJSON.h"

struct _protocol_set;
typedef struct _protocol_set *protocol_set;
struct _protocol_entry;
typedef struct _protocol_entry *protocol_entry;

protocol_set create_protocol_set(cJSON *types, cJSON *data);

gchar *get_packet_name(protocol_entry entry);

gint get_packet_id(protocol_set set, gchar *name, bool is_client);

protocol_entry get_protocol_entry(protocol_set set, guint packet_id, bool is_client);

guint get_field_offset(protocol_entry entry, guint8 *data);

#endif //MC_DISSECTOR_PROTOCOL_SCHEMA_H
