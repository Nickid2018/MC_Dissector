//
// Created by nickid2018 on 24-7-13.
//

#ifndef MC_DISSECTOR_STORAGE_H
#define MC_DISSECTOR_STORAGE_H

#include <glib.h>
#include "protocol/schema/protocol_schema.h"

typedef struct _protocol_je_set {
    protocol_set login;
    protocol_set play;
    protocol_set configuration;
} *protocol_je_set;

void clear_storage();

gchar **get_mapped_java_versions(guint protocol_version);

gint get_data_version(gchar *java_version);

protocol_je_set get_protocol_set_je(guint protocol_version, protocol_settings settings);

#endif //MC_DISSECTOR_STORAGE_H
