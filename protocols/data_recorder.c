//
// Created by Nickid2018 on 2023/7/14.
//

#include "data_recorder.h"

struct _data_recorder {
    wmem_stack_t *stack;
    wmem_stack_t *restore_stack;
    wmem_map_t *current;
    gchar *recording;
};

data_recorder create_data_recorder() {
    data_recorder recorder = wmem_new(wmem_packet_scope(), data_recorder_t);
    recorder->stack = wmem_stack_new(wmem_packet_scope());
    recorder->restore_stack = NULL;
    recorder->current = wmem_map_new(wmem_packet_scope(), g_str_hash, g_str_equal);
    wmem_stack_push(recorder->stack, recorder->current);
    recorder->recording = NULL;
}

void record_start(data_recorder recorder, gchar *name) {
    recorder->recording = name;
}

void *record(data_recorder recorder, void *data) {
    if (recorder->recording == NULL)
        return data;
    wmem_map_insert(recorder->current, recorder->recording, data);
    recorder->recording = NULL;
    return data;
}

guint32 record_uint(data_recorder recorder, guint32 data) {
    if (recorder->recording == NULL)
        return data;
    wmem_map_insert(recorder->current, recorder->recording, GUINT_TO_POINTER(data));
    recorder->recording = NULL;
    return data;
}

guint64 record_uint64(data_recorder recorder, guint64 data) {
    if (recorder->recording == NULL)
        return data;
    wmem_map_insert(recorder->current, recorder->recording, GUINT_TO_POINTER(data));
    recorder->recording = NULL;
    return data;
}

gint32 record_int(data_recorder recorder, gint32 data) {
    if (recorder->recording == NULL)
        return data;
    wmem_map_insert(recorder->current, recorder->recording, GINT_TO_POINTER(data));
    recorder->recording = NULL;
    return data;
}

gint64 record_int64(data_recorder recorder, gint64 data) {
    if (recorder->recording == NULL)
        return data;
    wmem_map_insert(recorder->current, recorder->recording, GINT_TO_POINTER(data));
    recorder->recording = NULL;
    return data;
}

float record_float(data_recorder recorder, float data) {
    if (recorder->recording == NULL)
        return data;
    wmem_map_insert(recorder->current, recorder->recording, GUINT_TO_POINTER(*((gint32 *) &data)));
    recorder->recording = NULL;
    return data;
}

double record_double(data_recorder recorder, double data) {
    if (recorder->recording == NULL)
        return data;
    wmem_map_insert(recorder->current, recorder->recording, GUINT_TO_POINTER(*((gint64 *) &data)));
    recorder->recording = NULL;
    return data;
}

void record_push(data_recorder recorder) {
    if (recorder->recording == NULL)
        return;
    wmem_map_t *next = wmem_map_lookup(recorder->current, recorder->recording);
    if (next == NULL) {
        next = wmem_map_new(wmem_packet_scope(), g_str_hash, g_str_equal);
        wmem_map_insert(recorder->current, recorder->recording, next);
    }
    wmem_stack_push(recorder->stack, next);
    recorder->current = next;
    recorder->recording = NULL;
}

void record_pop(data_recorder recorder) {
    wmem_stack_pop(recorder->stack);
    recorder->current = wmem_stack_peek(recorder->stack);
    recorder->recording = NULL;
}

void record_store(data_recorder recorder) {
    if (recorder->restore_stack != NULL)
        wmem_destroy_stack(recorder->restore_stack);
    recorder->restore_stack = wmem_stack_new(wmem_packet_scope());
    wmem_list_frame_t *now = wmem_list_head(recorder->stack);
    while (now != NULL) {
        wmem_list_append(recorder->restore_stack, wmem_list_frame_data(now));
        now = wmem_list_frame_next(now);
    }
}

void record_restore(data_recorder recorder) {
    if (recorder->restore_stack == NULL)
        return;
    wmem_destroy_stack(recorder->stack);
    recorder->stack = recorder->restore_stack;
    recorder->restore_stack = NULL;
}

void *query(data_recorder recorder, int path_len, ...) {
    va_list args;
    va_start(args, path_len);
    record_store(recorder);
    void *result = recorder->current;
    for (int i = 0; i < path_len - 1; i++) {
        gchar *key = va_arg(args, gchar *);
        if (strcmp(key, "..") == 0) {
            record_pop(recorder);
            result = recorder->current;
        } else {
            result = wmem_map_lookup(result, key);
            if (result == NULL)
                break;
            record_start(recorder, key);
            record_push(recorder);
        }
    }
    gchar *key = va_arg(args, gchar *);
    if (result != NULL && strcmp(key, "..") != 0)
        result = wmem_map_lookup(result, key);
    else
        result = NULL;
    record_restore(recorder);
    va_end(args);
    return result;
}