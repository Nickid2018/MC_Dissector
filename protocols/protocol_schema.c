//
// Created by Nickid2018 on 2023/7/13.
//

#include <stdlib.h>
#include "protocol_schema.h"

struct _protocol_set {
    wmem_map_t *client_packet_map;
    wmem_map_t *server_packet_map;
    wmem_map_t *client_name_map;
    wmem_map_t *server_name_map;
};

struct _protocol_entry {
    guint id;
    gchar *name;
    wmem_array_t *field_array;
};

void make_simple_protocol(cJSON *data, cJSON *types, wmem_map_t *packet_map, wmem_map_t *name_map) {
    cJSON *packets = cJSON_GetObjectItem(data, "packet");
    // Path: [1].[0].type.[1].mappings
    cJSON *c1 = cJSON_GetArrayItem(packets, 1);
    cJSON *c2 = cJSON_GetArrayItem(c1, 0);
    cJSON *c3 = cJSON_GetObjectItem(c2, "type");
    cJSON *c4 = cJSON_GetArrayItem(c3, 1);
    cJSON *mappings = cJSON_GetObjectItem(c4, "mappings");
    cJSON *now = mappings->child;
    while (now != NULL) {
        char *packet_id_str = now->string;
        gchar *packet_name = strdup(now->valuestring);
        char *ptr;
        guint packet_id = (guint) strtol(packet_id_str + 2, &ptr, 16);
        wmem_map_insert(name_map, packet_name, GUINT_TO_POINTER(packet_id + 1));

        protocol_entry entry = wmem_new(wmem_epan_scope(), struct _protocol_entry);
        entry->id = packet_id;
        entry->name = packet_name;
        wmem_map_insert(packet_map, GUINT_TO_POINTER(packet_id), entry);

        now = now->next;
    }
}

protocol_set create_protocol_set(cJSON *types, cJSON *data) {
    protocol_set set = wmem_new(wmem_epan_scope(), struct _protocol_set);
    set->client_packet_map = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
    set->server_packet_map = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
    set->client_name_map = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    set->server_name_map = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);

    cJSON *to_client = cJSON_GetObjectItem(cJSON_GetObjectItem(data, "toClient"), "types");
    cJSON *to_server = cJSON_GetObjectItem(cJSON_GetObjectItem(data, "toServer"), "types");
    make_simple_protocol(to_client, types, set->client_packet_map, set->client_name_map);
    make_simple_protocol(to_server, types, set->server_packet_map, set->server_name_map);

    return set;
}

gchar *get_packet_name(protocol_entry entry) {
    return entry == NULL ? "Unknown" : entry->name;
}

gint get_packet_id(protocol_set set, gchar *name, bool is_client) {
    wmem_map_t *name_map = is_client ? set->client_packet_map : set->server_name_map;
    return GPOINTER_TO_INT(wmem_map_lookup(name_map, name)) - 1;
}

protocol_entry get_protocol_entry(protocol_set set, guint packet_id, bool is_client) {
    wmem_map_t *packet_map = is_client ? set->client_packet_map : set->server_packet_map;
    return wmem_map_lookup(packet_map, GUINT_TO_POINTER(packet_id));
}

guint get_field_offset(protocol_entry entry, guint8 *data) {

}