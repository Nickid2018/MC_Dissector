//
// Created by Nickid2018 on 2023/7/14.
//

#include "data_recorder.h"

struct _data_recorder {
    wmem_map_t *store_map;
    gchar *recording_path;
    gchar *recording;
    wmem_map_t *alias_map;
};

data_recorder create_data_recorder() {
    data_recorder recorder = wmem_new(wmem_packet_scope(), data_recorder_t);
    recorder->store_map = wmem_map_new(wmem_packet_scope(), g_str_hash, g_str_equal);
    recorder->alias_map = wmem_map_new(wmem_packet_scope(), g_str_hash, g_str_equal);
    recorder->recording_path = "";
    recorder->recording = NULL;
    return recorder;
}

void destroy_data_recorder(data_recorder recorder) {
    wmem_free(wmem_packet_scope(), recorder);
}

void record_start(data_recorder recorder, gchar *name) {
    recorder->recording = name;
}

void *record(data_recorder recorder, void *data) {
    if (recorder->recording == NULL)
        return data;
    wmem_map_insert(recorder->store_map, g_strconcat(recorder->recording_path, "/", recorder->recording, NULL), data);
    return data;
}

guint32 record_bool(data_recorder recorder, guint32 data) {
    if (recorder->recording == NULL)
        return data;
    wmem_map_insert(recorder->store_map, g_strconcat(recorder->recording_path, "/", recorder->recording, NULL),
                    data == 0 ? "false" : "true");
    return data;
}

guint32 record_uint(data_recorder recorder, guint32 data) {
    if (recorder->recording == NULL)
        return data;
    wmem_map_insert(recorder->store_map, g_strconcat(recorder->recording_path, "/", recorder->recording, NULL),
                    g_strdup_printf("%u", data));
    return data;
}

guint64 record_uint64(data_recorder recorder, guint64 data) {
    if (recorder->recording == NULL)
        return data;
    wmem_map_insert(recorder->store_map, g_strconcat(recorder->recording_path, "/", recorder->recording, NULL),
                    g_strdup_printf("%llu", data));
    return data;
}

gint32 record_int(data_recorder recorder, gint32 data) {
    if (recorder->recording == NULL)
        return data;
    wmem_map_insert(recorder->store_map, g_strconcat(recorder->recording_path, "/", recorder->recording, NULL),
                    g_strdup_printf("%d", data));
    return data;
}

gint64 record_int64(data_recorder recorder, gint64 data) {
    if (recorder->recording == NULL)
        return data;
    wmem_map_insert(recorder->store_map, g_strconcat(recorder->recording_path, "/", recorder->recording, NULL),
                    g_strdup_printf("%lld", data));
    return data;
}

float record_float(data_recorder recorder, float data) {
    if (recorder->recording == NULL)
        return data;
    wmem_map_insert(recorder->store_map, g_strconcat(recorder->recording_path, "/", recorder->recording, NULL),
                    g_strdup_printf("%f", data));
    return data;
}

double record_double(data_recorder recorder, double data) {
    if (recorder->recording == NULL)
        return data;
    wmem_map_insert(recorder->store_map, g_strconcat(recorder->recording_path, "/", recorder->recording, NULL),
                    g_strdup_printf("%lf", data));
    return data;
}

void record_push(data_recorder recorder) {
    if (recorder->recording == NULL)
        return;
    recorder->recording_path = g_strconcat(recorder->recording_path, "/", recorder->recording, NULL);
    recorder->recording = NULL;
}

void record_pop(data_recorder recorder) {
    guint index;
    for (index = strlen(recorder->recording_path) - 1;; index--)
        if (recorder->recording_path[index] == '/')
            break;
    recorder->recording_path[index] = '\0';
    recorder->recording = NULL;
}

void *record_query(data_recorder recorder, gchar **path) {
    gchar *recording_path = strdup(recorder->recording_path);
    for (int i = 0; i < 10; i++) {
        gchar *key = path[i];
        if (key == NULL)
            break;
        gchar *alias = wmem_map_lookup(recorder->alias_map, key);
        if (alias != NULL)
            key = alias;
        if (strcmp(key, "..") == 0) {
            guint index;
            for (index = strlen(recording_path) - 1;; index--)
                if (recording_path[index] == '/')
                    break;
            recording_path[index] = '\0';
        } else
            recording_path = g_strconcat(recording_path, "/", key, NULL);
    }
    void *data = wmem_map_lookup(recorder->store_map, recording_path);
    g_free(recording_path);
    return data == NULL ? "" : data;
}

gchar *record_get_recording(data_recorder recorder) {
    return recorder->recording;
}

void record_add_alias(data_recorder recorder, gchar *name, gchar *alias) {
    wmem_map_insert(recorder->alias_map, name, alias);
}

void record_clear_alias(data_recorder recorder) {
    wmem_free(wmem_packet_scope(), recorder->alias_map);
    recorder->alias_map = wmem_map_new(wmem_packet_scope(), g_str_hash, g_str_equal);
}