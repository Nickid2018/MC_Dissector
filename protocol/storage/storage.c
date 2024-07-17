//
// Created by nickid2018 on 24-7-13.
//

#include "storage.h"

extern gchar *pref_protocol_data_dir;

cJSON *cached_versions = NULL;
cJSON *cached_protocol_data_mapping = NULL;

#define JSON_CACHED(name, path) \
void ensure_cached_##name() { \
    if (cached_##name == NULL) { \
        gchar *file = g_build_filename(pref_protocol_data_dir, path, NULL); \
        gchar *content = NULL; \
        if (g_file_get_contents(file, &content, NULL, NULL)) { \
            cached_##name = cJSON_Parse(content); \
            g_free(content); \
        } else { \
            ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot read file %s", file); \
        } \
        g_free(file); \
    } \
}

#define DATA_CACHED_UINT(name) \
wmem_map_t *cached_##name; \
void *get_cached_##name(guint version) { \
    if (cached_##name == NULL) \
        return NULL; \
    return wmem_map_lookup(cached_##name, GUINT_TO_POINTER(version)); \
}                    \
void set_cached_##name(guint version, void *value) { \
    if (cached_##name == NULL) \
        cached_##name = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal); \
    wmem_map_insert(cached_##name, GUINT_TO_POINTER(version), value); \
}

#define DATA_CACHED_STR(name) \
wmem_map_t *cached_##name; \
void *get_cached_##name(gchar *java_version) { \
    if (cached_##name == NULL) \
        return NULL; \
    return wmem_map_lookup(cached_##name, java_version); \
}                    \
void set_cached_##name(gchar *java_version, void *value) { \
    if (cached_##name == NULL) \
        cached_##name = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal); \
    wmem_map_insert(cached_##name, java_version, value); \
}

#define CLEAR_CACHED_JSON(name) \
if (cached_##name != NULL) { \
    cJSON_Delete(cached_##name); \
    cached_##name = NULL; \
}

#define CLEAR_CACHED_DATA(name) \
if (cached_##name != NULL) { \
    wmem_free(wmem_epan_scope(), cached_##name); \
    cached_##name = NULL; \
}

JSON_CACHED(versions, "java_edition/versions.json")

JSON_CACHED(protocol_data_mapping, "java_edition/protocol_mapping.json")

DATA_CACHED_UINT(protocol)

void clear_storage() {
    CLEAR_CACHED_JSON(versions)
    CLEAR_CACHED_JSON(protocol_data_mapping)
    CLEAR_CACHED_DATA(protocol)
}

gchar **get_mapped_java_versions(guint protocol_version) {
    ensure_cached_versions();
    GStrvBuilder *builder = g_strv_builder_new();
    for (int i = 0; i < cJSON_GetArraySize(cached_versions); i++) {
        cJSON *item = cJSON_GetArrayItem(cached_versions, i);
        cJSON *version = cJSON_GetObjectItem(item, "protocol_version");
        if (version == NULL || version->valueint != protocol_version)
            continue;
        cJSON *name = cJSON_GetObjectItem(item, "version");
        if (name == NULL)
            continue;
        g_strv_builder_add(builder, name->valuestring);
    }
    return g_strv_builder_end(builder);
}

gint get_data_version(gchar *java_version) {
    ensure_cached_versions();
    for (int i = 0; i < cJSON_GetArraySize(cached_versions); i++) {
        cJSON *item = cJSON_GetArrayItem(cached_versions, i);
        cJSON *name = cJSON_GetObjectItem(item, "version");
        if (name == NULL || g_strcmp0(name->valuestring, java_version) != 0)
            continue;
        cJSON *data_version = cJSON_GetObjectItem(item, "data_version");
        if (data_version == NULL)
            return -1;
        return data_version->valueint;
    }
    return -1;
}

protocol_je_set get_protocol_set_je(guint protocol_version, protocol_settings settings) {
    ensure_cached_protocol_data_mapping();
    protocol_je_set cached = get_cached_protocol(protocol_version);
    if (cached != NULL)
        return cached;

    gchar *find_key = g_strdup_printf("%d", protocol_version);
    cJSON *found = cJSON_GetObjectItem(cached_protocol_data_mapping, find_key);
    g_free(find_key);
    if (found == NULL)
        return NULL;

    gchar *file = g_build_filename(pref_protocol_data_dir, "java_edition/protocols", found->valuestring, "protocol.json", NULL);
    gchar *content = NULL;
    if (!g_file_get_contents(file, &content, NULL, NULL)) {
        ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot read file %s", file);
        g_free(file);
        return NULL;
    }

    cJSON *json = cJSON_Parse(content);
    g_free(content);

    cJSON *types = cJSON_GetObjectItem(json, "types");
    cJSON *login = cJSON_GetObjectItem(json, "login");
    cJSON *play = cJSON_GetObjectItem(json, "play");
    cJSON *config = cJSON_GetObjectItem(json, "configuration");

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
    set_cached_protocol(protocol_version, result);
    return result;
}