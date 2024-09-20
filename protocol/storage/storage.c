//
// Created by nickid2018 on 24-7-13.
//

#include "storage.h"
#include "protocol/schema/schema.h"

extern gchar *pref_protocol_data_dir;

#define JSON_CACHED(name, path) \
cJSON* cached_##name = NULL; \
void ensure_cached_##name() { \
    if (cached_##name == NULL) { \
        gchar *file = g_build_filename(pref_protocol_data_dir, path, NULL); \
        gchar *content = NULL; \
        if (g_file_get_contents(file, &content, NULL, NULL)) { \
            cached_##name = cJSON_Parse(content); \
            g_free(content); \
            if (cached_##name == NULL) \
                ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot parse file %s: %s", file, cJSON_GetErrorPtr()); \
        } else { \
            ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot read file %s", file); \
        } \
        g_free(file); \
    } \
}

#define DATA_CACHED_UINT(name) \
wmem_map_t *cached_##name = NULL; \
void *get_cached_##name(guint version) { \
    if (cached_##name == NULL) \
        return NULL; \
    return wmem_map_lookup(cached_##name, GUINT_TO_POINTER(version)); \
} \
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
} \
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

#define CLEAR_CACHED_DATA(name, func) \
if (cached_##name != NULL) {          \
    wmem_map_foreach_remove(cached_##name, func, NULL); \
    wmem_free(wmem_epan_scope(), cached_##name); \
    cached_##name = NULL; \
}

JSON_CACHED(settings, "settings.json")

JSON_CACHED(versions, "java_edition/versions.json")

JSON_CACHED(packet_names, "java_edition/packet_names.json")

DATA_CACHED_UINT(protocol)

DATA_CACHED_UINT(entity_sync_data)

DATA_CACHED_UINT(level_event)

DATA_CACHED_UINT(entity_event)

DATA_CACHED_STR(registry_data)

wmem_map_t *index_mappings;

void ensure_init_index_mappings() {
    if (index_mappings) return;
    index_mappings = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
    gchar *file = g_build_filename(pref_protocol_data_dir, "java_edition/indexes.csv", NULL);
    gchar *content = NULL;
    if (!g_file_get_contents(file, &content, NULL, NULL)) {
        ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot read file %s", file);
        g_free(file);
        return;
    }
    g_free(file);

    gchar **split_lines = g_strsplit(content, "\n", 10000);
    gchar **header = g_strsplit(split_lines[0], ",", 1000);
    gchar *now_line;
    for (int i = 1; (now_line = split_lines[i]) != NULL; i++) {
        gchar **now_line_split = g_strsplit(now_line, ",", 10000);
        wmem_map_t *map = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
        wmem_map_insert(index_mappings, g_strdup(now_line_split[0]), map);
        gchar *now_value;
        for (int j = 1; (now_value = now_line_split[j]) != NULL; j++)
            wmem_map_insert(map, header[j], now_value);
        g_strfreev(now_line_split);
    }
    g_strfreev(split_lines);
    g_free(content);
}

gchar *get_index(uint32_t protocol_version, gchar *item) {
    ensure_init_index_mappings();
    wmem_map_t *version_index = wmem_map_lookup(index_mappings, (const void *) (uint64_t) protocol_version);
    return wmem_map_lookup(version_index, item);
}

gchar *build_indexed_file_name(gchar *root, gchar *item, uint32_t protocol_version) {
    gchar *index = get_index(protocol_version, item);
    gchar *file_name = g_strdup_printf("%s.json", item);
    gchar *path;
    if (index == NULL)
        path = g_build_filename(pref_protocol_data_dir, root, item, file_name, NULL);
    else
        path = g_build_filename(pref_protocol_data_dir, root, item, index, file_name, NULL);
    g_free(file_name);
    return path;
}

gboolean clean_json(gpointer key _U_, gpointer value, gpointer user_data _U_) {
    cJSON_Delete(value);
    return true;
}

void clear_storage() {
    CLEAR_CACHED_JSON(settings)
    CLEAR_CACHED_JSON(versions)
    CLEAR_CACHED_JSON(packet_names)
    CLEAR_CACHED_DATA(protocol, clean_json)
    CLEAR_CACHED_DATA(entity_sync_data, clean_json)
    CLEAR_CACHED_DATA(level_event, clean_json)
    CLEAR_CACHED_DATA(entity_event, clean_json)
    CLEAR_CACHED_DATA(registry_data, clean_json)
}

gchar **get_mapped_java_versions(uint32_t protocol_version) {
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

int32_t get_data_version(gchar *java_version) {
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

cJSON *get_protocol_source(uint32_t protocol_version) {
    cJSON *cached = get_cached_protocol(protocol_version);
    if (cached != NULL)
        return cached;

    gchar *file = g_build_filename(
            pref_protocol_data_dir,
            "java_edition/indexed_data",
            get_index(protocol_version, "protocol"),
            "protocol.json",
            NULL
    );
    gchar *content = NULL;
    if (!g_file_get_contents(file, &content, NULL, NULL)) {
        ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot read file %s", file);
        g_free(file);
        return NULL;
    }

    cJSON *json = cJSON_Parse(content);
    g_free(content);
    if (json == NULL)
        ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot parse file %s: %s", file, cJSON_GetErrorPtr());
    g_free(file);

    return json;
}

gchar *get_entity_sync_data_name(uint32_t protocol_version, gchar *entity_id, uint32_t index) {
    cJSON *cached = get_cached_entity_sync_data(protocol_version);
    if (cached == NULL) {
        gchar *file = g_build_filename(
                pref_protocol_data_dir,
                "java_edition/indexed_data",
                get_index(protocol_version, "entity_sync_data"),
                "entity_sync_data.json",
                NULL
        );
        gchar *content = NULL;
        if (!g_file_get_contents(file, &content, NULL, NULL)) {
            ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot read file %s", file);
            g_free(file);
            return NULL;
        }

        cached = cJSON_Parse(content);
        g_free(content);
        g_free(file);
        set_cached_entity_sync_data(protocol_version, cached);
    }

    cJSON *data = cJSON_GetArrayItem(cJSON_GetObjectItem(cached, entity_id), (int) index);
    if (data == NULL)
        return NULL;
    return data->valuestring;
}

gchar *get_registry_data(uint32_t protocol_version, gchar *registry, uint32_t index) {
    gchar *cache_key = g_strdup_printf("%s/%d", registry, protocol_version);
    cJSON *cached = get_cached_registry_data(cache_key);
    if (cached == NULL) {
        gchar *file_name = g_strdup_printf("%s.json", registry);
        gchar *file = g_build_filename(
                pref_protocol_data_dir,
                "java_edition/indexed_data",
                get_index(protocol_version, registry),
                "registries",
                file_name,
                NULL
        );
        g_free(file_name);
        gchar *content = NULL;
        if (!g_file_get_contents(file, &content, NULL, NULL)) {
            ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot read file %s", file);
            g_free(file);
            g_free(cache_key);
            return NULL;
        }
        g_free(file);
        cached = cJSON_Parse(content);
        g_free(content);
        set_cached_registry_data(cache_key, cached);
    }

    cJSON *data = cJSON_GetArrayItem(cached, (int) index);
    if (data == NULL)
        return "<Unknown Registry Entry>";
    return data->valuestring;
}

bool get_settings_flag(gchar *name) {
    ensure_cached_settings();
    cJSON *flag = cJSON_GetObjectItem(cached_settings, name);
    return flag != NULL && flag->type == cJSON_True;
}

bool is_compatible_protocol_data() {
    ensure_cached_settings();
    cJSON *version = cJSON_GetObjectItem(cached_settings, "version");
    return version != NULL && g_strcmp0(version->valuestring, PROTOCOL_DATA_VERSION) == 0;
}