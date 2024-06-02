//
// Created by Nickid2018 on 2023/7/14.
//

#ifndef MC_DISSECTOR_DATA_RECORDER_H
#define MC_DISSECTOR_DATA_RECORDER_H

#include <epan/proto.h>

typedef struct _data_recorder data_recorder_t, *data_recorder;

data_recorder create_data_recorder(wmem_allocator_t *allocator);

void destroy_data_recorder(data_recorder recorder);

void record_start(data_recorder recorder, gchar *name);

void *record(data_recorder recorder, void *data);

guint32 record_bool(data_recorder recorder, guint32 data);

guint32 record_uint(data_recorder recorder, guint32 data);

guint64 record_uint64(data_recorder recorder, guint64 data);

gint32 record_int(data_recorder recorder, gint32 data);

gint64 record_int64(data_recorder recorder, gint64 data);

float record_float(data_recorder recorder, float data);

double record_double(data_recorder recorder, double data);

void record_push(data_recorder recorder);

void record_pop(data_recorder recorder);

void *record_query(data_recorder recorder, gchar **path);

gchar *record_get_recording(data_recorder recorder);

void record_add_alias(data_recorder recorder, gchar *name, gchar *alias);

void record_clear_alias(data_recorder recorder);

#endif //MC_DISSECTOR_DATA_RECORDER_H
