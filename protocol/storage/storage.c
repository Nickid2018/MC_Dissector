//
// Created by nickid2018 on 24-7-13.
//

#include "storage.h"
#include "mc_dissector.h"

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

JSON_CACHED(protocol_data_mapping, "java_edition/protocol_mapping.json")

JSON_CACHED(entity_sync_data_mapping, "java_edition/entity_sync_data_mapping.json")

JSON_CACHED(level_event_data_mapping, "java_edition/level_event_mapping.json")

JSON_CACHED(entity_event_data_mapping, "java_edition/entity_event_mapping.json")

JSON_CACHED(packet_names, "java_edition/packet_names.json")

DATA_CACHED_UINT(protocol)

DATA_CACHED_UINT(entity_sync_data)

DATA_CACHED_UINT(level_event)

DATA_CACHED_UINT(entity_event)

DATA_CACHED_STR(registry_data_mapping)

DATA_CACHED_STR(registry_data)

gboolean nop(gpointer key _U_, gpointer value _U_, gpointer user_data _U_) {
    return true;
}

gboolean clean_json(gpointer key _U_, gpointer value, gpointer user_data _U_) {
    cJSON_Delete(value);
    return true;
}

void clear_storage() {
    CLEAR_CACHED_JSON(settings)
    CLEAR_CACHED_JSON(versions)
    CLEAR_CACHED_JSON(protocol_data_mapping)
    CLEAR_CACHED_JSON(entity_sync_data_mapping)
    CLEAR_CACHED_JSON(level_event_data_mapping)
    CLEAR_CACHED_JSON(entity_event_data_mapping)
    CLEAR_CACHED_JSON(packet_names)
    CLEAR_CACHED_DATA(protocol, nop)
    CLEAR_CACHED_DATA(entity_sync_data, clean_json)
    CLEAR_CACHED_DATA(level_event, clean_json)
    CLEAR_CACHED_DATA(entity_event, clean_json)
    CLEAR_CACHED_DATA(registry_data_mapping, clean_json)
    CLEAR_CACHED_DATA(registry_data, clean_json)
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

gchar *get_readable_packet_name(bool to_client, gchar *packet_name) {
    ensure_cached_packet_names();
    cJSON *found = cJSON_GetObjectItem(
            cJSON_GetObjectItem(cached_packet_names, to_client ? "toClient" : "toServer"),
            packet_name
    );
    if (found == NULL)
        return packet_name;
    return found->valuestring;
}

protocol_je_set get_protocol_set_je(guint protocol_version, protocol_settings settings) {
    protocol_je_set cached = get_cached_protocol(protocol_version);
    if (cached != NULL)
        return cached;

    ensure_cached_protocol_data_mapping();
    gchar *find_key = g_strdup_printf("%d", protocol_version);
    cJSON *found = cJSON_GetObjectItem(cached_protocol_data_mapping, find_key);
    g_free(find_key);
    if (found == NULL)
        return NULL;

    gchar *file = g_build_filename(pref_protocol_data_dir, "java_edition/indexed_data", found->valuestring,
                                   "protocol.json", NULL);
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

gchar *get_entity_sync_data_name(guint protocol_version, gchar *entity_id, guint index) {
    cJSON *cached = get_cached_entity_sync_data(protocol_version);
    if (cached == NULL) {
        ensure_cached_entity_sync_data_mapping();
        gchar *find_key = g_strdup_printf("%d", protocol_version);
        cJSON *found = cJSON_GetObjectItem(cached_entity_sync_data_mapping, find_key);
        g_free(find_key);
        if (found == NULL)
            return NULL;

        gchar *file = g_build_filename(
                pref_protocol_data_dir,
                "java_edition/indexed_data",
                found->valuestring,
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
        set_cached_entity_sync_data(protocol_version, cached);
    }

    cJSON *data = cJSON_GetArrayItem(cJSON_GetObjectItem(cached, entity_id), (int) index);
    if (data == NULL)
        return NULL;
    return data->valuestring;
}

gchar *get_registry_data(guint protocol_version, gchar *registry, guint index) {
    gchar *cache_key = g_strdup_printf("%s/%d", registry, protocol_version);
    cJSON *cached = get_cached_registry_data(cache_key);
    if (cached == NULL) {
        cJSON *mapping = get_cached_registry_data_mapping(registry);
        if (mapping == NULL) {
            gchar *file_name = g_strdup_printf("%s_mapping.json", registry);
            gchar *file = g_build_filename(
                    pref_protocol_data_dir,
                    "java_edition/registry_mapping",
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
            mapping = cJSON_Parse(content);
            g_free(content);
            set_cached_registry_data_mapping(registry, mapping);
        }

        gchar *find_key = g_strdup_printf("%d", protocol_version);
        cJSON *found = cJSON_GetObjectItem(mapping, find_key);
        g_free(find_key);
        if (found == NULL) {
            g_free(cache_key);
            return NULL;
        }

        gchar *file_name = g_strdup_printf("%s.json", registry);
        gchar *file = g_build_filename(
                pref_protocol_data_dir,
                "java_edition/indexed_data",
                found->valuestring,
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

gchar *get_level_event_data(guint protocol_version, gchar *index) {
    cJSON *cached = get_cached_level_event(protocol_version);
    if (cached == NULL) {
        ensure_cached_level_event_data_mapping();
        gchar *find_key = g_strdup_printf("%d", protocol_version);
        cJSON *found = cJSON_GetObjectItem(cached_level_event_data_mapping, find_key);
        g_free(find_key);
        if (found == NULL)
            return NULL;

        gchar *file = g_build_filename(
                pref_protocol_data_dir,
                "java_edition/indexed_data",
                found->valuestring,
                "level_event.json",
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
        set_cached_level_event(protocol_version, cached);
    }

    cJSON *data = cJSON_GetObjectItem(cached, index);
    if (data == NULL)
        return NULL;
    return data->valuestring;
}

gchar *get_entity_event_data(guint protocol_version, gchar *index) {
    cJSON *cached = get_cached_entity_event(protocol_version);
    if (cached == NULL) {
        ensure_cached_entity_event_data_mapping();
        gchar *find_key = g_strdup_printf("%d", protocol_version);
        cJSON *found = cJSON_GetObjectItem(cached_entity_event_data_mapping, find_key);
        g_free(find_key);
        if (found == NULL)
            return NULL;

        gchar *file = g_build_filename(
                pref_protocol_data_dir,
                "java_edition/indexed_data",
                found->valuestring,
                "entity_event.json",
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
        set_cached_entity_event(protocol_version, cached);
    }

    cJSON *data = cJSON_GetObjectItem(cached, index);
    if (data == NULL)
        return NULL;
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