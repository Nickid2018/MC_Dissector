//
// Created by Nickid2018 on 2023/7/13.
//

#include "protocols.h"
#include "protocolVersions.h"
#include "protocolSchemas.h"

wmem_map_t *protocol_version_map_je = NULL;
wmem_map_t *data_version_map_je = NULL;
wmem_map_t *data_version_rev_map_je = NULL;
GArray *data_version_list_je = NULL;
wmem_map_t *protocol_raw_map_je = NULL;
wmem_map_t *protocol_schema_je = NULL;

gint compare_int(gconstpointer a, gconstpointer b) {
    return *(gint *) (a) - *(gint *) (b);
}

gint get_java_data_version_unchecked(gchar *java_version);

void init_je() {
    data_version_map_je = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    data_version_rev_map_je = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
    protocol_version_map_je = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
    cJSON *json = cJSON_Parse(PROTOCOL_VERSIONS_JE);
    int size = cJSON_GetArraySize(json);
    for (int i = 0; i < size; i++) {
        cJSON *item = cJSON_GetArrayItem(json, i);
        if (cJSON_GetObjectItem(item, "usesNetty")->valueint == 0)
            continue;
        cJSON *version = cJSON_GetObjectItem(item, "version");
        if (version == NULL)
            continue;
        guint protocol_version = (guint) version->valueint;
        cJSON *data_version_obj = cJSON_GetObjectItem(item, "dataVersion");
        if (data_version_obj == NULL)
            continue;
        gint data_version = data_version_obj->valueint;
        gchar *name = g_strdup(cJSON_GetObjectItem(item, "minecraftVersion")->valuestring);
        wmem_list_t *map_values = wmem_map_lookup(protocol_version_map_je, GUINT_TO_POINTER(protocol_version));
        if (map_values == NULL) {
            map_values = wmem_list_new(wmem_epan_scope());
            wmem_map_insert(protocol_version_map_je, GUINT_TO_POINTER(protocol_version), map_values);
        }
        wmem_list_append(map_values, name);
        wmem_map_insert(data_version_map_je, name, GINT_TO_POINTER(data_version + 1));
        wmem_map_insert(data_version_rev_map_je, GINT_TO_POINTER(data_version), name);
    }
    cJSON_Delete(json);

    data_version_list_je = g_array_new(FALSE, FALSE, sizeof(guint));
    protocol_schema_je = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    protocol_raw_map_je = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    for (int i = 0; i < JE_PROTOCOL_SIZE; i++) {
        const char *name = JE_PROTOCOLS[i * 2];
        const char *raw = JE_PROTOCOLS[i * 2 + 1];
        gchar *g_name = g_strdup(name);
        gint data_version = get_java_data_version_unchecked(g_name);
        if (data_version == -1)
            continue;
        g_array_append_val(data_version_list_je, data_version);
        wmem_map_insert(protocol_raw_map_je, g_name, g_strdup(raw));
    }
    g_array_sort(data_version_list_je, compare_int);
}

gchar *get_java_version_name(guint protocol_version) {
    wmem_list_t *map_values = wmem_map_lookup(protocol_version_map_je, GUINT_TO_POINTER(protocol_version));
    if (map_values == NULL)
        return "Unknown";
    wmem_list_frame_t *frame = wmem_list_head(map_values);
    gchar *name = wmem_list_frame_data(frame);
    wmem_list_frame_t *next_frame = wmem_list_frame_next(frame);
    while (next_frame != NULL) {
        name = g_strconcat(name, ", ", wmem_list_frame_data(next_frame), NULL);
        next_frame = wmem_list_frame_next(next_frame);
    }
    return name;
}

gchar *get_java_version_name_unchecked(guint protocol_version) {
    wmem_list_t *map_values = wmem_map_lookup(protocol_version_map_je, GUINT_TO_POINTER(protocol_version));
    if (map_values == NULL)
        return "Unknown";
    return wmem_list_frame_data(wmem_list_head(map_values));
}

inline gint get_java_data_version_unchecked(gchar *java_version) {
    return GPOINTER_TO_INT(wmem_map_lookup(data_version_map_je, java_version)) - 1;
}

gint get_java_data_version(gchar *java_version) {
    return get_java_data_version_unchecked(java_version);
}

gchar *get_java_version_name_by_data_version(guint data_version) {
    gchar *data = wmem_map_lookup(data_version_rev_map_je, GUINT_TO_POINTER(data_version));
    return data == NULL ? "Unknown" : data;
}

guint find_nearest_java_protocol(guint data_version) {
    for (int cursor = 0; cursor < data_version_list_je->len; cursor++) {
        guint data = g_array_index(data_version_list_je, guint, cursor);
        if (data > data_version)
            return g_array_index(data_version_list_je, guint, cursor - 1);
        if (data == data_version)
            return data;
    }
    return g_array_index(data_version_list_je, guint, data_version_list_je->len - 1);
}

protocol_je_set get_protocol_je_set(gchar *java_version) {
    protocol_je_set cached = wmem_map_lookup(protocol_schema_je, java_version);
    if (cached != NULL)
        return cached;
    gchar *raw = wmem_map_lookup(protocol_raw_map_je, java_version);
    if (raw == NULL)
        return NULL;
    cJSON *json = cJSON_Parse(raw);
    cJSON *types = cJSON_GetObjectItem(json, "types");
    cJSON *login = cJSON_GetObjectItem(json, "login");
    cJSON *play = cJSON_GetObjectItem(json, "play");
    cJSON *config = cJSON_GetObjectItem(json, "configuration");

    protocol_settings settings = {
            get_java_data_version(java_version) >= 3567
    };

    protocol_je_set result = wmem_new(wmem_epan_scope(), struct _protocol_je_set);
    protocol_set login_set = create_protocol_set(types, login, true, settings);
    protocol_set play_set = create_protocol_set(types, play, true, settings);
    result->login = login_set;
    result->play = play_set;
    if (config != NULL) {
        protocol_set config_set = create_protocol_set(types, config, true, settings);
        result->configuration = config_set;
    }

    cJSON_Delete(json);
    wmem_map_insert(protocol_schema_je, java_version, result);
    return result;
}

