//
// Created by Nickid2018 on 2023/7/13.
//

#include "protocols.h"
#include "protocolVersions.h"
#include "protocolSchemas.h"

wmem_map_t *protocol_version_map_je = NULL;
wmem_map_t *data_version_map_je = NULL;
wmem_map_t *data_version_rev_map_je = NULL;
GArray *protocol_version_list_je = NULL;
wmem_map_t *protocol_raw_map_je = NULL;
wmem_map_t *protocol_schema_je = NULL;

gint compare_int(gconstpointer a, gconstpointer b) {
    return GPOINTER_TO_INT(a) - GPOINTER_TO_INT(b);
}

gint get_java_data_version_unchecked(gchar *java_version);

void check_map_je() {
    if (protocol_version_map_je == NULL) {
        protocol_version_map_je = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
        data_version_map_je = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
        data_version_rev_map_je = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
        cJSON *json = cJSON_Parse(PROTOCOL_VERSIONS_JE);
        int size = cJSON_GetArraySize(json);
        for (int i = 0; i < size; i++) {
            cJSON *item = cJSON_GetArrayItem(json, i);
            if (cJSON_GetObjectItem(item, "usesNetty")->valueint == 0)
                continue;
            guint version = (guint) cJSON_GetObjectItem(item, "version")->valueint;
            gchar *name = g_strdup(cJSON_GetObjectItem(item, "minecraftVersion")->valuestring);
            gint data_version = cJSON_GetObjectItem(item, "dataVersion")->valueint;
            gchar *map_values = wmem_map_lookup(protocol_version_map_je, GUINT_TO_POINTER(version));
            if (map_values != NULL) {
                gchar *now= g_strconcat(map_values, ", ", name, NULL);
                g_free(map_values);
                g_free(name);
                name = now;
            }
            wmem_map_insert(protocol_version_map_je, GUINT_TO_POINTER(version), name);
            wmem_map_insert(data_version_map_je, name, GINT_TO_POINTER(data_version));
            wmem_map_insert(data_version_rev_map_je, GINT_TO_POINTER(data_version), name);
        }
        cJSON_Delete(json);

        protocol_version_list_je = g_array_new(FALSE, FALSE, sizeof(guint));
        protocol_schema_je = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
        protocol_raw_map_je = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
        for (int i = 0; i < JE_PROTOCOL_SIZE; i++) {
            const char *name = JE_PROTOCOLS[i * 2];
            const char *raw = JE_PROTOCOLS[i * 2 + 1];
            gchar *g_name = g_strdup(name);
            gint data_version = get_java_data_version_unchecked(g_name);
            if (data_version == -1)
                continue;
            g_array_append_val(protocol_version_list_je, data_version);
            wmem_map_insert(protocol_raw_map_je, g_name, g_strdup(raw));
        }
        g_array_sort(protocol_version_list_je, compare_int);
    }
}

gchar *get_java_version_name(guint protocol_version) {
    check_map_je();
    gchar *data = wmem_map_lookup(protocol_version_map_je, GUINT_TO_POINTER(protocol_version));
    return data == NULL ? "Unknown" : data;
}

inline gint get_java_data_version_unchecked(gchar *java_version) {
    gint *data = wmem_map_lookup(data_version_map_je, java_version);
    return data == NULL ? -1 : GPOINTER_TO_INT(data);
}

gint get_java_data_version(gchar *java_version) {
    check_map_je();
    return get_java_data_version_unchecked(java_version);
}

gchar *get_java_version_name_by_data_version(guint data_version) {
    check_map_je();
    gchar *data = wmem_map_lookup(data_version_rev_map_je, GINT_TO_POINTER(data_version));
    return data == NULL ? "Unknown" : data;
}

gchar *find_java_protocol_name(guint data_version) {
    check_map_je();
    unsigned head = 0, tail = protocol_version_list_je->len - 1;
    while (head <= tail) {
        unsigned mid = (head + tail) / 2;
        guint mid_data = g_array_index(protocol_version_list_je, guint, mid);
        if (mid_data == data_version)
            return get_java_version_name_by_data_version(mid_data);
        else if (mid_data < data_version)
            head = mid + 1;
        else
            tail = mid - 1;
    }
    return get_java_version_name_by_data_version(g_array_index(protocol_version_list_je, guint, tail));
}

protocol_je_set get_protocol_je_set(gchar *java_version) {
    check_map_je();
    gchar *raw = wmem_map_lookup(protocol_raw_map_je, java_version);
    if (raw == NULL)
        return NULL;
    cJSON *json = cJSON_Parse(raw);
    cJSON *types = cJSON_GetObjectItem(json, "types");
    cJSON *login = cJSON_GetObjectItem(types, "login");
    cJSON *play = cJSON_GetObjectItem(types, "play");
    protocol_set login_set = create_protocol_set(types, login);
    protocol_set play_set = create_protocol_set(types, play);
    cJSON_Delete(json);
    protocol_je_set result = wmem_new(wmem_epan_scope(), struct _protocol_je_set);
    result->login = login_set;
    result->play = play_set;
    return result;
}