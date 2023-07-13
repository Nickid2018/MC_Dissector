//
// Created by Nickid2018 on 2023/7/13.
//

#include "protocols.h"
#include "../cJSON/cJSON.h"
#include "protocolVersions.h"

wmem_map_t *protocol_version_map_je = NULL;

gchar *get_java_version_name(guint protocol_version) {
    if (protocol_version_map_je == NULL) {
        protocol_version_map_je = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
        cJSON *json = cJSON_Parse(PROTOCOL_VERSIONS_JE);
        int size = cJSON_GetArraySize(json);
        for (int i = 0; i < size; i++) {
            cJSON *item = cJSON_GetArrayItem(json, i);
            guint version = (guint) cJSON_GetObjectItem(item, "version")->valueint;
            gchar *name = g_strdup(cJSON_GetObjectItem(item, "minecraftVersion")->valuestring);
            gchar *map_values = wmem_map_lookup(protocol_version_map_je, GUINT_TO_POINTER(version));
            if (map_values != NULL) {
                gchar *now= g_strconcat(map_values, ", ", name, NULL);
                g_free(map_values);
                g_free(name);
                name = now;
            }
            wmem_map_insert(protocol_version_map_je, GUINT_TO_POINTER(version), name);
        }
        cJSON_Delete(json);
    }
    gchar *data = wmem_map_lookup(protocol_version_map_je, GUINT_TO_POINTER(protocol_version));
    return data == NULL ? "Unknown" : data;
}