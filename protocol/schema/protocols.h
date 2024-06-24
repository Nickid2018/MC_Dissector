//
// Created by Nickid2018 on 2023/7/13.
//

#ifndef MC_DISSECTOR_PROTOCOLS_H
#define MC_DISSECTOR_PROTOCOLS_H

#include <epan/proto.h>
#include "protocol_schema.h"

extern GArray *data_version_list_je;

typedef struct _protocol_je_set {
    protocol_set login;
    protocol_set play;
    protocol_set configuration;
} *protocol_je_set;

void init_je();

gchar *get_java_version_name(guint protocol_version);

gchar *get_java_version_name_unchecked(guint protocol_version);

gint get_java_data_version(gchar *java_version);

gchar *get_java_version_name_by_data_version(guint data_version);

guint find_nearest_java_protocol(guint data_version);

protocol_je_set get_protocol_je_set(gchar *java_version);

#endif //MC_DISSECTOR_PROTOCOLS_H
