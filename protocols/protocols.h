//
// Created by Nickid2018 on 2023/7/13.
//

#ifndef MC_DISSECTOR_PROTOCOLS_H
#define MC_DISSECTOR_PROTOCOLS_H

#include <epan/proto.h>
#include "protocol_schema.h"

#define TAG_END        0
#define TAG_BYTE       1
#define TAG_SHORT      2
#define TAG_INT        3
#define TAG_LONG       4
#define TAG_FLOAT      5
#define TAG_DOUBLE     6
#define TAG_BYTE_ARRAY 7
#define TAG_STRING     8
#define TAG_LIST       9
#define TAG_COMPOUND   10
#define TAG_INT_ARRAY  11
#define TAG_LONG_ARRAY 12

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

guint count_nbt_length(const guint8 *data);

#endif //MC_DISSECTOR_PROTOCOLS_H
