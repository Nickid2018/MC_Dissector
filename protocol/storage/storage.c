//
// Created by nickid2018 on 24-7-13.
//

#include "mc_dissector.h"
#include "storage.h"

extern char *pref_protocol_data_dir;

#define CACHED_HEADER(type, name) type cached_##name;

struct protocol_storage_struct {
    char *root;
    protocol_dissector_settings *settings;

    CACHED_HEADER(cJSON *, versions)
    CACHED_HEADER(wmem_map_t *, index_mappings)
    CACHED_HEADER(wmem_map_t *, protocol_mappings)
    CACHED_HEADER(wmem_map_t *, protocol)
    CACHED_HEADER(wmem_map_t *, entity_sync_data)
    CACHED_HEADER(wmem_map_t *, registry_data)
    protocol_dissector_set *initial_set;
};

protocol_storage *create_storage(char *root, protocol_dissector_settings *settings) {
    protocol_storage *storage = wmem_new(wmem_epan_scope(), protocol_storage);
    storage->root = root;
    storage->settings = settings;
    settings->storage = storage;

    storage->cached_versions = NULL;
    storage->cached_index_mappings = NULL;
    storage->cached_protocol_mappings = NULL;
    storage->cached_protocol = NULL;
    storage->cached_entity_sync_data = NULL;
    storage->cached_registry_data = NULL;
    storage->initial_set = NULL;
    return storage;
}

#define JSON_CACHED(name, path) \
void ensure_cached_##name(protocol_storage *storage) { \
    if (storage->cached_##name == NULL) { \
        char *file = g_build_filename(pref_protocol_data_dir, storage->root, path, NULL); \
        char *content = NULL; \
        if (g_file_get_contents(file, &content, NULL, NULL)) { \
            storage->cached_##name = cJSON_Parse(content); \
            g_free(content); \
            if (storage->cached_##name == NULL) \
                ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot parse file %s: %s", file, cJSON_GetErrorPtr()); \
        } else { \
            ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot read file %s", file); \
        } \
        g_free(file); \
    } \
}

#define ENSURE_CSV_CACHED(name, path) \
void ensure_cached_##name(protocol_storage *storage) { \
    if (storage->cached_##name != NULL) return; \
    char *file = g_build_filename(pref_protocol_data_dir, storage->root, path, NULL); \
    storage->cached_##name = read_csv(file); \
    g_free(file); \
}

#define DATA_CACHED_UINT(name) \
void *get_cached_##name(protocol_storage *storage, uint32_t version) { \
    if (storage->cached_##name == NULL) \
        return NULL; \
    return wmem_map_lookup(storage->cached_##name, GUINT_TO_POINTER(version)); \
} \
void set_cached_##name(protocol_storage *storage, uint32_t version, void *value) { \
    if (storage->cached_##name == NULL) \
        storage->cached_##name = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal); \
    wmem_map_insert(storage->cached_##name, GUINT_TO_POINTER(version), value); \
}

#define DATA_CACHED_STR(name) \
wmem_map_t *cached_##name; \
void *get_cached_##name(protocol_storage *storage, char *java_version) { \
    if (storage->cached_##name == NULL) \
        return NULL; \
    return wmem_map_lookup(storage->cached_##name, java_version); \
} \
void set_cached_##name(protocol_storage *storage, char *java_version, void *value) { \
    if (storage->cached_##name == NULL) \
        storage->cached_##name = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal); \
    wmem_map_insert(storage->cached_##name, java_version, value); \
}

#define CLEAR_CACHED_JSON(name) \
if (storage->cached_##name != NULL) { \
    cJSON_Delete(storage->cached_##name); \
    storage->cached_##name = NULL; \
}

#define CLEAR_CACHED_DATA(name, func) \
if (storage->cached_##name != NULL) {          \
    wmem_map_foreach_remove(storage->cached_##name, func, NULL); \
    wmem_free(wmem_epan_scope(), storage->cached_##name); \
    storage->cached_##name = NULL; \
}

JSON_CACHED(versions, "versions.json")

DATA_CACHED_UINT(protocol)

DATA_CACHED_UINT(entity_sync_data)

DATA_CACHED_STR(registry_data)

wmem_map_t *read_csv(char *path) {
    wmem_map_t *csv = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);

    char *content = NULL;
    if (!g_file_get_contents(path, &content, NULL, NULL)) {
        ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot read file %s", path);
        return NULL;
    }

    char **split_lines = g_strsplit(content, "\n", 10000);
    char **header = g_strsplit(split_lines[0], ",", 1000);
    char *now_line;
    for (int i = 0; (now_line = header[i]) != NULL; i++)
        header[i] = g_strstrip(now_line);
    for (int i = 1; (now_line = split_lines[i]) != NULL; i++) {
        char **now_line_split = g_strsplit(now_line, ",", 10000);
        if (now_line_split == NULL) continue;
        wmem_map_t *map = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
        char *end;
        uint64_t protocol_version = strtol(g_strstrip(now_line_split[0]), &end, 10);
        wmem_map_insert(csv, (void *) protocol_version, map);
        char *now_value;
        for (int j = 1; (now_value = now_line_split[j]) != NULL; j++)
            wmem_map_insert(map, header[j], g_strdup(g_strstrip(now_value)));
        g_strfreev(now_line_split);
    }
    g_strfreev(split_lines);
    g_free(content);

    return csv;
}

ENSURE_CSV_CACHED(index_mappings, "indexes.csv")

ENSURE_CSV_CACHED(protocol_mappings, "packets.csv")

char *get_index(protocol_storage *storage, uint32_t protocol_version, char *item) {
    ensure_cached_index_mappings(storage);
    wmem_map_t *version_index = wmem_map_lookup(storage->cached_index_mappings,
                                                (const void *) (uint64_t) protocol_version);
    return wmem_map_lookup(version_index, item);
}

char *build_indexed_file_name(protocol_storage *storage, char *root, char *item, uint32_t protocol_version) {
    char *index = get_index(storage, protocol_version, item);
    char *file_name = g_strdup_printf("%s.json", item);
    char *path;
    if (index == NULL)
        path = g_build_filename(pref_protocol_data_dir, storage->root, root, file_name, NULL);
    else
        path = g_build_filename(pref_protocol_data_dir, storage->root, "indexed_data", index, root, file_name, NULL);
    g_free(file_name);
    return path;
}

char *build_protocol_file_name(protocol_storage *storage, char *root, char *item, uint32_t protocol_version) {
    ensure_cached_protocol_mappings(storage);
    wmem_map_t *version_index = wmem_map_lookup(storage->cached_protocol_mappings,
                                                (const void *) (uint64_t) protocol_version);
    char *index = wmem_map_lookup(version_index, item);
    char *file_name = g_strdup_printf("%s.json", item);
    char *path;
    if (index == NULL || strcmp(index, "-1") == 0)
        path = g_build_filename(pref_protocol_data_dir, storage->root, root, file_name, NULL);
    else
        path = g_build_filename(pref_protocol_data_dir, storage->root, "indexed_data", index, root, file_name, NULL);
    g_free(file_name);
    return path;
}

gboolean clean_json(gpointer key _U_, gpointer value, gpointer user_data _U_) {
    cJSON_Delete(value);
    return true;
}

gboolean clean_protocol(gpointer key _U_, gpointer value, gpointer user_data _U_) {
    destroy_protocol(value);
    return true;
}

gboolean clean_nop(gpointer key _U_, gpointer value, gpointer user_data _U_) {
    return true;
}

void clear_storage(protocol_storage *storage) {
    CLEAR_CACHED_JSON(versions)
    CLEAR_CACHED_DATA(index_mappings, clean_nop)
    CLEAR_CACHED_DATA(protocol_mappings, clean_nop)
    CLEAR_CACHED_DATA(entity_sync_data, clean_json)
    CLEAR_CACHED_DATA(registry_data, clean_json)
    CLEAR_CACHED_DATA(protocol, clean_protocol)
    if (storage->initial_set != NULL) {
        destroy_protocol(storage->initial_set);
        storage->initial_set = NULL;
    }
}

char **get_mapped_readable_versions(protocol_storage *storage, uint32_t protocol_version) {
    ensure_cached_versions(storage);
    GPtrArray *array = g_ptr_array_new_with_free_func(g_free);
    for (int i = 0; i < cJSON_GetArraySize(storage->cached_versions); i++) {
        cJSON *item = cJSON_GetArrayItem(storage->cached_versions, i);
        cJSON *version = cJSON_GetObjectItem(item, "protocol_version");
        if (version == NULL || version->valueint != protocol_version)
            continue;
        cJSON *name = cJSON_GetObjectItem(item, "version");
        if (name == NULL)
            continue;
        g_ptr_array_add(array, g_strdup(name->valuestring));
    }
    g_ptr_array_add(array, NULL);
    return (char **) g_ptr_array_steal(array, NULL);
}

int32_t get_data_version(protocol_storage *storage, char *version) {
    ensure_cached_versions(storage);
    for (int i = 0; i < cJSON_GetArraySize(storage->cached_versions); i++) {
        cJSON *item = cJSON_GetArrayItem(storage->cached_versions, i);
        cJSON *name = cJSON_GetObjectItem(item, "version");
        if (name == NULL || g_strcmp0(name->valuestring, version) != 0)
            continue;
        cJSON *data_version = cJSON_GetObjectItem(item, "data_version");
        if (data_version == NULL)
            return -1;
        return data_version->valueint;
    }
    return -1;
}

cJSON *get_protocol_source(protocol_storage *storage, uint32_t protocol_version) {
    char *file = g_build_filename(
        pref_protocol_data_dir,
        storage->root,
        "indexed_data",
        get_index(storage, protocol_version, "protocol"),
        "protocol.json",
        NULL
    );
    char *content = NULL;
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

cJSON *get_packet_source(protocol_storage *storage, uint32_t protocol_version, char *packet) {
    char *path = build_protocol_file_name(storage, "packets", packet, protocol_version);

    char *content = NULL;
    if (!g_file_get_contents(path, &content, NULL, NULL)) {
        ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot read file %s", path);
        g_free(path);
        return NULL;
    }

    cJSON *json = cJSON_Parse(content);
    g_free(content);
    if (json == NULL) {
        const char *error = cJSON_GetErrorPtr();
        ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot parse file %s: %s", path, error);
        g_free(path);
        return NULL;
    }
    g_free(path);

    return json;
}

char *get_entity_sync_data_name(protocol_storage *storage, uint32_t protocol_version, char *entity_id, uint32_t index) {
    cJSON *cached = get_cached_entity_sync_data(storage, protocol_version);
    if (cached == NULL) {
        char *file = g_build_filename(
            pref_protocol_data_dir,
            storage->root,
            "indexed_data",
            get_index(storage, protocol_version, "entity_sync_data"),
            "entity_sync_data.json",
            NULL
        );
        char *content = NULL;
        if (!g_file_get_contents(file, &content, NULL, NULL)) {
            ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot read file %s", file);
            g_free(file);
            return NULL;
        }

        cached = cJSON_Parse(content);
        g_free(content);
        g_free(file);
        set_cached_entity_sync_data(storage, protocol_version, cached);
    }

    cJSON *data = cJSON_GetArrayItem(cJSON_GetObjectItem(cached, entity_id), (int) index);
    if (data == NULL)
        return NULL;
    return data->valuestring;
}

void ensure_cached_registry(protocol_storage *storage, uint32_t protocol_version, char *registry) {
    char *cache_key = g_strdup_printf("%s/%d", registry, protocol_version);
    cJSON *cached = get_cached_registry_data(storage, cache_key);
    if (cached == NULL) {
        char *file_name = g_strdup_printf("%s.json", registry);
        char *file = g_build_filename(
            pref_protocol_data_dir,
            storage->root,
            "indexed_data",
            get_index(storage, protocol_version, registry),
            "registries",
            file_name,
            NULL
        );
        g_free(file_name);
        char *content = NULL;
        if (!g_file_get_contents(file, &content, NULL, NULL)) {
            ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot read file %s", file);
            g_free(file);
            g_free(cache_key);
            return;
        }
        g_free(file);
        cached = cJSON_Parse(content);
        g_free(content);
        if (!cJSON_IsArray(cached)) {
            cJSON_free(cached);
            g_free(cache_key);
            return;
        }
        int count = cJSON_GetArraySize(cached);
        for (int i = 0; i < count; i++) {
            if (!cJSON_IsString(cJSON_GetArrayItem(cached, i))) {
                cJSON_free(cached);
                g_free(cache_key);
                return;
            }
        }
        set_cached_registry_data(storage, cache_key, cached);
    }
}

cJSON *get_registry(protocol_storage *storage, uint32_t protocol_version, char *registry) {
    ensure_cached_registry(storage, protocol_version, registry);
    char *cache_key = g_strdup_printf("%s/%d", registry, protocol_version);
    cJSON *data = get_cached_registry_data(storage, cache_key);
    g_free(cache_key);
    return data;
}

char *get_registry_data(protocol_storage *storage, uint32_t protocol_version, char *registry, uint32_t index) {
    cJSON *data = cJSON_GetArrayItem(get_registry(storage, protocol_version, registry), (int) index);
    if (data == NULL)
        return "<Unknown Registry Entry>";
    return data->valuestring;
}

protocol_dissector_set *get_initial_protocol(protocol_storage *storage) {
    if (storage->initial_set != NULL) return storage->initial_set;
    char *file = g_build_filename(pref_protocol_data_dir, "java_edition", "initial.json", NULL);

    char *content = NULL;
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

    storage->initial_set = create_protocol_with_json(json, storage->settings, ~0u);
    return storage->initial_set;
}

protocol_dissector_set *get_protocol_set(protocol_storage *storage, uint32_t protocol_version) {
    protocol_dissector_set *cached = get_cached_protocol(storage, protocol_version);
    if (cached != NULL) return cached;
    cached = create_protocol(protocol_version, storage->settings);
    set_cached_protocol(storage, protocol_version, cached);
    return cached;
}

// GLOBAL

cJSON *cached_settings = NULL;

void ensure_cached_settings() {
    if (cached_settings == NULL) {
        char *file = g_build_filename(pref_protocol_data_dir, "settings.json", NULL);
        char *content = NULL;
        if (g_file_get_contents(file, &content, NULL, NULL)) {
            cached_settings = cJSON_Parse(content);
            g_free(content);
            if (cached_settings == NULL)
                ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot parse settings: %s", cJSON_GetErrorPtr());
        } else {
            ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot read settings");
        }
        g_free(file);
    }
}

bool get_settings_flag(char *name) {
    ensure_cached_settings();
    cJSON *flag = cJSON_GetObjectItem(cached_settings, name);
    return flag != NULL && flag->type == cJSON_True;
}

bool is_compatible_protocol_data() {
    ensure_cached_settings();
    cJSON *version = cJSON_GetObjectItem(cached_settings, "version");
    return version != NULL && g_strcmp0(version->valuestring, PROTOCOL_DATA_VERSION) == 0;
}
