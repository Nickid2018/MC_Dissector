//
// Created by nickid2018 on 24-7-13.
//

#ifndef MC_DISSECTOR_STORAGE_H
#define MC_DISSECTOR_STORAGE_H

#include "protocol/schema/protocol_schema.h"

typedef struct _protocol_je_set {
    protocol_set login;
    protocol_set play;
    protocol_set configuration;
} *protocol_je_set;

void clear_storage();

gchar **get_mapped_java_versions(guint protocol_version);

gint get_data_version(gchar *java_version);

gchar *get_readable_packet_name(bool to_client, gchar *packet_name);

protocol_je_set get_protocol_set_je(guint protocol_version, protocol_settings settings);

gchar *get_entity_sync_data_name(guint protocol_version, gchar *entity_id, guint index);

gchar *get_registry_data(guint protocol_version, gchar *registry, guint index);

gchar *get_level_event_data(guint protocol_version, gchar *index);

gchar *get_entity_event_data(guint protocol_version, gchar *index);

#endif //MC_DISSECTOR_STORAGE_H
