//
// Created by Nickid2018 on 2023/7/13.
//

#include "protocol_schema.h"

struct _protocol_set {
    wmem_map_t *packet_map;
};

struct _protocol_entry {
    guint id;
    gchar *name;
    wmem_array_t *field_array;
};

protocol_set create_protocol_set(cJSON *types, cJSON *data) {
    protocol_set set = wmem_new(wmem_file_scope(), struct _protocol_set);
    set->packet_map = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    return set;
}