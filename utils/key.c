//
// Created by nickid2018 on 2026/10/21.
//

#include <wsutil/wslog.h>
#include <glib/gstrfuncs.h>
#include "key.h"
#include "mc_dissector.h"

gchar *match_secret_key(const gchar *challenge, const gchar *content) {
    char **split = g_strsplit(content, " ", 2);
    if (split[1] == NULL) return nullptr;
    char **split_key = g_strsplit(split[1], "\n", 2);
    if (strlen(split_key[0]) != 32) return nullptr;
    if (strcmp(split[0], challenge) == 0) return split_key[0];
    return nullptr;
}

const gchar *find_encryption_key(gchar *challenge_str) {
    if (!challenge_str) return nullptr;
    if (!pref_key_log_filepath_je) return pref_secret_key_je;
    char *content = nullptr;
    if (!g_file_get_contents(pref_key_log_filepath_je, &content, nullptr, nullptr)) {
        ws_log("MC-Dissector", LOG_LEVEL_WARNING, "Cannot read key file %s", pref_key_log_filepath_je);
        return pref_secret_key_je;
    }
    gchar *matched = match_secret_key(challenge_str, content);
    if (matched) return matched;
    while ((content = g_utf8_strchr(content, -1, '\n'))) {
        content++;
        if (content[0] == '\0') break;
        matched = match_secret_key(challenge_str, content);
        if (matched) return matched;
    }
    return pref_secret_key_je;
}

uint8_t *make_key(const gchar *encryption_key) {
    if (!encryption_key || strlen(encryption_key) != 32) return nullptr;
    uint8_t *secret_key = wmem_alloc(wmem_file_scope(), 16);
    bool failed = false;
    for (int i = 0; i < 16; i++) {
        gchar hex[3] = {encryption_key[i * 2], encryption_key[i * 2 + 1], '\0'};
        errno = 0;
        secret_key[i] = (uint8_t) strtol(hex, nullptr, 16);
        if (errno != 0) {
            failed = true;
            break;
        }
    }
    if (failed) {
        wmem_free(wmem_file_scope(), secret_key);
        return nullptr;
    }
    return secret_key;
}

char *bytes_to_hex(wmem_allocator_t *allocator, const uint8_t *bytes, const uint32_t len, const bool uppercase) {
    wmem_strbuf_t *buf = wmem_strbuf_new(allocator, "");
    for (uint32_t i = 0; i < len; i++) {
        wmem_strbuf_append_printf(buf, uppercase ? "%02X" : "%02x", bytes[i] & 0xFF);
    }
    return wmem_strbuf_finalize(buf);
}
