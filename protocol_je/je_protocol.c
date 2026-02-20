//
// Created by Nickid2018 on 2023/7/12.
//

#include <epan/proto.h>
#include <epan/conversation.h>
#include <errno.h>
#include "mc_dissector.h"
#include "je_dissect.h"
#include "je_protocol.h"
#include "protocol/storage/storage.h"
#include "utils/nbt.h"

extern int hf_invalid_data_je;
extern int hf_ignored_packet_je;
extern int hf_packet_id_je;
extern int hf_packet_name_je;
extern int hf_unknown_packet_je;
extern int hf_string_je;
extern int hf_generated_je;
extern int hf_uint8_je;
extern int hf_uint16_je;
extern int hf_int32_je;

extern protocol_dissector_settings *settings_je;
extern protocol_storage *storage_je;

char *JE_STATE_NAME[] = {
    "Handshake", "Play", "Status", "Login", "Transfer", "Configuration", "Legacy Query",
    "Invalid", "Not Compatible", "Protocol Not Found", "Secret Key Not Found"
};

uint32_t je_state_to_protocol_set_state(je_state state, bool is_client) {
    uint32_t base_state = 0;
    switch (state) {
        case PLAY:
            base_state = PLAY_SERVER;
            break;
        case STATUS:
            base_state = STATUS_SERVER;
            break;
        case LOGIN:
        case TRANSFER:
            base_state = LOGIN_SERVER;
            break;
        case CONFIGURATION:
            base_state = CONFIGURATION_SERVER;
            break;
        default:
            base_state = HANDSHAKE_SERVER;
    }
    return is_client ? 8 + base_state : base_state;
}

je_state protocol_set_state_to_je_state(uint32_t base_state) {
    switch (base_state) {
        case PLAY_SERVER:
            return PLAY;
        case STATUS_SERVER:
            return STATUS;
        case CONFIGURATION_SERVER:
            return CONFIGURATION;
        case LOGIN_SERVER:
            return LOGIN;
        default:
            return HANDSHAKE;
    }
}

void handle_with_set(
    proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, protocol_dissector_set *set, je_state state, bool is_client
) {
    uint32_t now_state = je_state_to_protocol_set_state(state, is_client);
    int32_t packet_id;
    int32_t len = read_var_int(tvb, 0, &packet_id);
    if (is_invalid(len)) {
        proto_tree_add_string(tree, hf_packet_name_je, tvb, 0, 0, "Invalid Packet ID");
        return;
    }

    proto_tree_add_uint(tree, hf_packet_id_je, tvb, 0, len, packet_id);
    uint32_t count = (uint64_t) wmem_map_lookup(set->count_by_state, (void *) (uint64_t) now_state);
    if (packet_id >= count) {
        proto_tree_add_string(tree, hf_unknown_packet_je, tvb, 0, 1, "Unknown Packet ID");
        return;
    }

    char **key = wmem_map_lookup(set->registry_keys, (void *) (uint64_t) now_state);
    char **name = wmem_map_lookup(set->readable_names, (void *) (uint64_t) now_state);
    protocol_dissector **d = wmem_map_lookup(set->dissectors_by_state, (void *) (uint64_t) now_state);
    proto_tree_add_string_format_value(
        tree, hf_packet_name_je, tvb, 0, len, key[packet_id],
        "%s (%s)", name[packet_id], key[packet_id]
    );

    bool ignore = false;
    if (strlen(pref_ignore_packets_je) != 0) {
        char *search_name = wmem_strdup_printf(pinfo->pool, "%s:%s", is_client ? "c" : "s", key[packet_id]);
        GList *list = prefs_get_string_list(pref_ignore_packets_je);
        ignore = g_list_find_custom(list, search_name, (GCompareFunc) g_strcmp0) != NULL;
        wmem_free(pinfo->pool, search_name);
    }

    uint32_t length = tvb_reported_length(tvb);
    if (ignore)
        proto_tree_add_string(tree, hf_ignored_packet_je, tvb, len, (int32_t) length - len, "Ignored by user");
    else {
        wmem_map_t *packet_save = wmem_map_new(pinfo->pool, g_str_hash, g_str_equal);
        int32_t sub_len = d[packet_id]->dissect_protocol(
            tree, pinfo, tvb, len, pinfo->pool, d[packet_id], "Packet Data", packet_save, NULL
        );
        if (sub_len + len != length && sub_len != DISSECT_ERROR)
            proto_tree_add_string_format_value(
                tree, hf_invalid_data_je, tvb, len, (int32_t) length - len,
                "length mismatch", "Packet length mismatch, expected %d, got %d", length - len,
                sub_len
            );
    }
}

void handle_initial(
    proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, mc_protocol_context *ctx, je_state state, bool is_client
) {
    protocol_dissector_set *initial_set = get_initial_protocol(storage_je);
    if (initial_set == NULL) {
        proto_tree_add_string(tree, hf_invalid_data_je, tvb, 0, 1, "Can't find initial protocol set");
        ctx->client_state = ctx->server_state = PROTOCOL_NOT_FOUND;
        return;
    }
    handle_with_set(tree, pinfo, tvb, initial_set, state, is_client);
}

void handle_protocol(
    proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, mc_protocol_context *ctx, je_state state, bool is_client
) {
    if (ctx->dissector_set == NULL) {
        proto_tree_add_string(tree, hf_invalid_data_je, tvb, 0, 1, "Can't find protocol set for this version");
        ctx->client_state = ctx->server_state = PROTOCOL_NOT_FOUND;
        return;
    }
    if (!ctx->dissector_set->valid) {
        proto_tree_add_string(tree, hf_invalid_data_je, tvb, 0, 1, "Protocol dissector is freed");
        ctx->client_state = ctx->server_state = INVALID;
        return;
    }

    handle_with_set(tree, pinfo, tvb, ctx->dissector_set, state, is_client);
}

int try_switch_initial(tvbuff_t *tvb, packet_info *pinfo, mc_protocol_context *ctx, bool is_client) {
    protocol_dissector_set *initial_set = get_initial_protocol(storage_je);
    if (initial_set == NULL) return INVALID_DATA;
    int32_t packet_id;
    int32_t len = read_var_int(tvb, 0, &packet_id);
    if (is_invalid(len)) return INVALID_DATA;
    uint32_t now_state = je_state_to_protocol_set_state(is_client ? ctx->client_state : ctx->server_state, is_client);
    wmem_map_t *special_mark = wmem_map_lookup(initial_set->special_mark, (void *) (uint64_t) now_state);
    if (wmem_map_contains(special_mark, (void *) (uint64_t) packet_id)) {
        char *mark = wmem_map_lookup(special_mark, (void *) (uint64_t) packet_id);
        if (strcmp(mark, "intention") == 0) {
            protocol_dissector **d = wmem_map_lookup(initial_set->dissectors_by_state, (void *) (uint64_t) now_state);
            wmem_allocator_t *temp_alloc = wmem_allocator_new(WMEM_ALLOCATOR_SIMPLE);
            wmem_map_t *packet_save = wmem_map_new(temp_alloc, g_str_hash, g_str_equal);
            int32_t sub_len = d[packet_id]->dissect_protocol(
                NULL, pinfo, tvb, len, temp_alloc, d[packet_id], "Packet Data", packet_save, NULL
            );
            if (sub_len + len != tvb_reported_length(tvb) && sub_len != DISSECT_ERROR) {
                wmem_destroy_allocator(temp_alloc);
                return INVALID_DATA;
            }
            char *protocol_version_str = wmem_map_lookup(packet_save, "protocol_version");
            char *intention_str = wmem_map_lookup(packet_save, "intention");
            if (intention_str == NULL || protocol_version_str == NULL) {
                wmem_destroy_allocator(temp_alloc);
                ctx->client_state = ctx->server_state = PROTOCOL_NOT_FOUND;
                return INVALID_DATA;
            }
            char *end;
            uint32_t protocol_version = strtoll(protocol_version_str, &end, 10);
            ctx->protocol_version = protocol_version;
            wmem_map_insert(ctx->global_data, "protocol_version", (void *) (uint64_t) protocol_version);
            int next_state = -1;
            if (strcmp(intention_str, "Status") == 0) next_state = STATUS;
            if (strcmp(intention_str, "Login") == 0) next_state = LOGIN;
            if (strcmp(intention_str, "Transfer") == 0) next_state = TRANSFER;
            wmem_destroy_allocator(temp_alloc);
            if (next_state == -1) {
                ctx->client_state = ctx->server_state = PROTOCOL_NOT_FOUND;
                return INVALID_DATA;
            }
            ctx->client_state = ctx->server_state = next_state;
            char **java_versions = get_mapped_readable_versions(storage_je, protocol_version);
            if (java_versions == NULL || java_versions[0] == NULL) {
                ctx->client_state = ctx->server_state = PROTOCOL_NOT_FOUND;
                return INVALID_DATA;
            }
            ctx->data_version = get_data_version(storage_je, java_versions[0]);
            g_strfreev(java_versions);
            wmem_map_insert(ctx->global_data, "data_version", (void *) (uint64_t) ctx->data_version);
            if (ctx->data_version >= 3567)
                wmem_map_insert(ctx->global_data, "nbt_any_type", (void *) 1);
            if (next_state == STATUS)
                return 0;
            ctx->dissector_set = get_protocol_set(storage_je, protocol_version);
            if (ctx->dissector_set == NULL)
                ctx->client_state = ctx->server_state = PROTOCOL_NOT_FOUND;
        }
    }
    return 0;
}

gchar *match_secret_key(gchar *challenge, gchar *content) {
    char **split = g_strsplit(content, " ", 2);
    if (split[1] == NULL) return NULL;
    char **split_key = g_strsplit(split[1], "\n", 2);
    if (strlen(split_key[0]) != 32) return NULL;
    if (strcmp(split[0], challenge) == 0) return split_key[0];
    return NULL;
}

gchar *find_encryption_key(gchar *challenge_str) {
    if (!challenge_str) return NULL;
    if (!pref_key_log_filepath_je) return pref_secret_key_je;
    char *content = NULL;
    if (!g_file_get_contents(pref_key_log_filepath_je, &content, NULL, NULL)) {
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

int try_switch_state(
    tvbuff_t *tvb, packet_info *pinfo, mc_protocol_context *ctx, mc_frame_data *frame_data, bool is_client
) {
    if (ctx->dissector_set == NULL) return INVALID_DATA;
    uint32_t now_state = je_state_to_protocol_set_state(is_client ? ctx->client_state : ctx->server_state, is_client);
    int32_t packet_id;
    int32_t len = read_var_int(tvb, 0, &packet_id);
    if (is_invalid(len)) return INVALID_DATA;
    wmem_map_t *state_to_next = wmem_map_lookup(ctx->dissector_set->state_to_next, (void *) (uint64_t) now_state);
    wmem_map_t *state_side = wmem_map_lookup(ctx->dissector_set->state_to_next_side, (void *) (uint64_t) now_state);
    wmem_map_t *special_mark = wmem_map_lookup(ctx->dissector_set->special_mark, (void *) (uint64_t) now_state);
    if (wmem_map_contains(state_to_next, (void *) (uint64_t) packet_id)) {
        uint32_t state = protocol_set_state_to_je_state(
            (uint64_t) wmem_map_lookup(state_to_next, (void *) (uint64_t) packet_id)
        );
        uint32_t side = (uint64_t) wmem_map_lookup(state_side, (void *) (uint64_t) packet_id);
        if ((side & 1) != 0) ctx->client_state = state;
        if ((side & 2) != 0) ctx->server_state = state;
    }
    if (wmem_map_contains(special_mark, (void *) (uint64_t) packet_id)) {
        char *mark = wmem_map_lookup(special_mark, (void *) (uint64_t) packet_id);

        if (strcmp(mark, "encrypt_request") == 0) {
            int32_t str_len;
            len += read_var_int(tvb, len, &str_len);
            len += str_len;
            len += read_buffer(tvb, len, NULL, NULL);
            uint8_t *challenge;
            read_buffer(tvb, len, &challenge, pinfo->pool);
            gchar *challenge_str = wmem_strdup_printf(
                wmem_file_scope(), "%02x%02x%02x%02x",
                challenge[0], challenge[1], challenge[2], challenge[3]
            );
            wmem_map_insert(ctx->global_data, "#key_challenge", challenge_str);
        }

        if (strcmp(mark, "encrypt") == 0) {
            ctx->encrypted = true;
            gchar *encryption_key = find_encryption_key(wmem_map_lookup(ctx->global_data, "#key_challenge"));
            if (encryption_key == NULL || strlen(encryption_key) != 32) {
                ctx->server_state = ctx->client_state = SECRET_KEY_NOT_FOUND;
            } else {
                uint8_t *secret_key = wmem_alloc(wmem_file_scope(), 16);
                bool failed = false;
                for (int i = 0; i < 16; i++) {
                    gchar hex[3] = {encryption_key[i * 2], encryption_key[i * 2 + 1], '\0'};
                    errno = 0;
                    secret_key[i] = (uint8_t) strtol(hex, NULL, 16);
                    if (errno != 0) {
                        failed = true;
                        break;
                    }
                }
                if (failed) {
                    ctx->server_state = ctx->client_state = SECRET_KEY_NOT_FOUND;
                } else {
                    ctx->secret_key = secret_key;
                }
            }
        }

        if (strcmp(mark, "compress") == 0) {
            int32_t threshold;
            len = read_var_int(tvb, len, &threshold);
            if (is_invalid(len)) return INVALID_DATA;
            ctx->compression_threshold = threshold;
            frame_data->first_compression_packet = true;
            frame_data->compression_threshold = threshold;
        }

        if (strcmp(mark, "registry") == 0) {
            wmem_map_t *writable_registry = wmem_map_lookup(ctx->global_data, "#writable_registry");
            if (writable_registry == NULL) {
                writable_registry = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
                wmem_map_insert(ctx->global_data, "#writable_registry", writable_registry);
            }
            wmem_map_t *writable_registry_size = wmem_map_lookup(ctx->global_data, "#writable_registry_size");
            if (writable_registry_size == NULL) {
                writable_registry_size = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
                wmem_map_insert(ctx->global_data, "#writable_registry_size", writable_registry_size);
            }
            char *registry_name;
            int32_t offset = len;
            len = read_string(tvb, offset, &registry_name, wmem_file_scope());
            if (is_invalid(len)) return INVALID_DATA;

            char **splits = g_strsplit(registry_name, ":", 10);
            char *last_split = "";
            for (int i = 0; splits[i] != NULL; i++) {
                last_split = splits[i];
            }
            char **second_splits = g_strsplit(last_split, "/", 10);
            char *real_name = "";
            for (int i = 0; second_splits[i] != NULL; i++) {
                real_name = second_splits[i];
            }
            wmem_free(wmem_file_scope(), registry_name);
            registry_name = wmem_strdup(wmem_file_scope(), real_name);
            g_strfreev(splits);
            g_strfreev(second_splits);

            offset += len;
            int32_t count;
            len = read_var_int(tvb, offset, &count);
            if (is_invalid(len)) return INVALID_DATA;
            offset += len;
            char **data = wmem_alloc(wmem_file_scope(), sizeof(char *) * count);
            bool is_new_nbt = wmem_map_lookup(ctx->global_data, "nbt_any_type");
            for (int i = 0; i < count; i++) {
                char *name;
                len = read_string(tvb, offset, &name, wmem_file_scope());
                if (is_invalid(len)) {
                    wmem_free(wmem_file_scope(), data);
                    return INVALID_DATA;
                }
                data[i] = name + 10;
                if (tvb_get_uint8(tvb, offset + len) == 0) {
                    len += 1;
                } else {
                    if (is_new_nbt) {
                        uint8_t present = tvb_get_uint8(tvb, offset + len + 1);
                        len += present ? count_je_nbt_length_with_type(tvb, offset + len + 2, present) + 2 : 2;
                    } else
                        len += count_je_nbt_length(tvb, offset + len + 1) + 1;
                }
                offset += len;
            }
            wmem_map_insert(writable_registry, registry_name, data);
            wmem_map_insert(writable_registry_size, registry_name, (void *) (uint64_t) count);
        }
    }
    return 0;
}

void handle_legacy_query(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, mc_protocol_context *ctx) {
    bool is_server = addresses_equal(&pinfo->dst, &ctx->server_address) && pinfo->destport == ctx->server_port;
    if (is_server) {
        col_set_str(pinfo->cinfo, COL_INFO, "[C => S] Legacy Query");
        bool is_version1;
        if (!pinfo->fd->visited) {
            is_version1 = tvb_reported_length_remaining(tvb, 1) > 0;
            wmem_map_insert(ctx->global_data, "legacy_query", (void *) is_version1);
        } else {
            is_version1 = wmem_map_lookup(ctx->global_data, "legacy_query");
        }
        if (tree) {
            proto_item *ti = proto_tree_add_item(tree, proto_mcje, tvb, 0, (int32_t) tvb_reported_length(tvb), FALSE);
            proto_item_append_text(ti, ", Client State: Legacy Query, Server State: Legacy Query");
            tree = proto_item_add_subtree(ti, ett_mc_je);
            proto_item *gen;
            if (is_version1) {
                if (tvb_get_uint8(tvb, 1) != 0x01) {
                    proto_tree_add_string(tree, hf_invalid_data_je, tvb, 1, 1, "Invalid Version 1 header");
                    return;
                }
                if (tvb_reported_length_remaining(tvb, 2) > 0) {
                    gen = proto_tree_add_string(tree, hf_generated_je, tvb, 1, 1, "Version 1, 1.6");
                    bool valid = tvb_get_uint8(tvb, 2) == 0xFA;
                    int32_t offset = 3;
                    int32_t len;
                    if (valid) {
                        uint8_t *str = read_legacy_string(tvb, offset, &len);
                        if (str != NULL) {
                            if (strcmp((char *) str, "MC|PingHost") != 0) valid = false;
                            else offset += len;
                        } else valid = false;
                    }
                    if (valid) {
                        int32_t len_should = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
                        if (len_should != tvb_reported_length_remaining(tvb, offset + 2)) valid = false;
                        else {
                            proto_item *payload = proto_tree_add_uint(tree, hf_uint16_je, tvb, offset, 2, len_should);
                            proto_item_prepend_text(payload, "Payload Length ");
                            offset += 2;
                        }
                    }
                    if (valid) {
                        uint8_t protocol = tvb_get_uint8(tvb, offset);
                        if (protocol < 73) valid = false;
                        else {
                            proto_item *payload = proto_tree_add_uint(tree, hf_uint8_je, tvb, offset, 1, protocol);
                            proto_item_prepend_text(payload, "Protocol Version ");
                            offset++;
                        }
                    }
                    if (valid) {
                        uint8_t *str = read_legacy_string(tvb, offset, &len);
                        if (str != NULL) {
                            proto_item *payload =
                                proto_tree_add_string(tree, hf_string_je, tvb, offset, len, (char *) str);
                            proto_item_prepend_text(payload, "Host Name ");
                            offset += len;
                        } else valid = false;
                    }
                    if (valid) {
                        int32_t port = tvb_get_int32(tvb, offset, ENC_BIG_ENDIAN);
                        if (port <= 65535) {
                            proto_item *payload = proto_tree_add_int(tree, hf_int32_je, tvb, offset, 4, port);
                            proto_item_prepend_text(payload, "Port ");
                            offset += 4;
                        } else valid = false;
                    }
                    if (valid) {
                        valid = tvb_reported_length_remaining(tvb, offset) == 0;
                    }
                    if (!valid) {
                        proto_tree_add_string(
                            tree, hf_invalid_data_je, tvb,
                            offset, tvb_reported_length_remaining(tvb, offset), "Invalid query"
                        );
                    }
                } else {
                    gen = proto_tree_add_string(tree, hf_generated_je, tvb, 1, 1, "Version 1, 1.4-1.5.x");
                }
            } else {
                gen = proto_tree_add_string(tree, hf_generated_je, tvb, 0, 1, "Version 0, <1.3.x");
            }
            proto_item_set_generated(gen);
            proto_item_prepend_text(gen, "Legacy Query Request Version ");
        }
    } else {
        col_set_str(pinfo->cinfo, COL_INFO, "[S => C] Legacy Query Response");
        if (tree) {
            proto_item *ti = proto_tree_add_item(tree, proto_mcje, tvb, 0, (int32_t) tvb_reported_length(tvb), FALSE);
            proto_item_append_text(ti, ", Client State: Legacy Query, Server State: Legacy Query");
            tree = proto_item_add_subtree(ti, ett_mc_je);
            bool is_version1 = wmem_map_lookup(ctx->global_data, "legacy_query");
            proto_item *gen = proto_tree_add_string(
                tree, hf_generated_je, tvb, 1, 1, is_version1 ? "Version 1" : "Version 0"
            );
            proto_item_set_generated(gen);
            proto_item_prepend_text(gen, "Legacy Query Response Version ");
            if (tvb_get_uint8(tvb, 0) != 0xFF) {
                proto_tree_add_string(tree, hf_invalid_data_je, tvb, 0, 1, "Invalid header");
                return;
            }
            int32_t len;
            uint8_t *str = read_legacy_string(tvb, 1, &len);
            if (str != NULL) {
                if (is_version1) {
                    int32_t start = 7;
                    int32_t offset = 7;
                    while (offset < len / 2 - 2) {
                        if (tvb_get_uint16(tvb, offset * 2 + 3, ENC_BIG_ENDIAN) == 0) break;
                        offset++;
                    }
                    proto_item *payload = proto_tree_add_string(
                        tree, hf_string_je, tvb, start * 2 + 3, (offset - start) * 2,
                        (char *) tvb_get_string_enc(pinfo->pool, tvb, start * 2 + 3, (offset - start) * 2, ENC_UTF_16)
                    );
                    proto_item_prepend_text(payload, "Server Version ");
                    start = ++offset;
                    while (offset < len / 2 - 2) {
                        if (tvb_get_uint16(tvb, offset * 2 + 3, ENC_BIG_ENDIAN) == 0) break;
                        offset++;
                    }
                    payload = proto_tree_add_string(
                        tree, hf_string_je, tvb, 3 + start * 2, (offset - start) * 2,
                        (char *) tvb_get_string_enc(pinfo->pool, tvb, start * 2 + 3, (offset - start) * 2, ENC_UTF_16)
                    );
                    proto_item_prepend_text(payload, "Motd ");
                    start = ++offset;
                    while (offset < len / 2 - 2) {
                        if (tvb_get_uint16(tvb, offset * 2 + 3, ENC_BIG_ENDIAN) == 0) break;
                        offset++;
                    }
                    payload = proto_tree_add_string(
                        tree, hf_string_je, tvb, 3 + start * 2, (offset - start) * 2,
                        (char *) tvb_get_string_enc(pinfo->pool, tvb, start * 2 + 3, (offset - start) * 2, ENC_UTF_16)
                    );
                    proto_item_prepend_text(payload, "Player Count ");
                    start = ++offset;
                    payload = proto_tree_add_string(
                        tree, hf_string_je, tvb, 3 + start * 2, len - start * 2 - 2,
                        (char *) tvb_get_string_enc(pinfo->pool, tvb, start * 2 + 3, len - start * 2 - 2, ENC_UTF_16)
                    );
                    proto_item_prepend_text(payload, "Max Players ");
                } else {
                    char **strv = g_strsplit((char *) str, "\u00a7", 100);
                    uint32_t array = g_strv_length(strv);
                    int64_t offset0 = 0, offset1;
                    if (array > 3) {
                        for (int32_t i = 0; i < array - 2; i++) offset0 += g_utf8_strlen(strv[i], 400) + 1;
                        offset1 = offset0 + g_utf8_strlen(strv[array - 2], 400) + 1;
                    } else {
                        offset0 = g_utf8_strlen(strv[0], 400) + 1;
                        offset1 = offset0 + g_utf8_strlen(strv[1], 400) + 1;
                    }
                    proto_item *payload = proto_tree_add_string(
                        tree, hf_string_je, tvb, 3, (int32_t) (offset0 - 1) * 2,
                        (char *) tvb_get_string_enc(pinfo->pool, tvb, 3, (int32_t) (offset0 - 1) * 2, ENC_UTF_16)
                    );
                    proto_item_prepend_text(payload, "Motd ");
                    payload = proto_tree_add_string(
                        tree, hf_string_je, tvb, (int32_t) offset0 * 2 + 3, (int32_t) (offset1 - offset0 - 1) * 2,
                        (char *) tvb_get_string_enc(
                            pinfo->pool, tvb, (int32_t) offset0 * 2 + 3, (int32_t) (offset1 - offset0 - 1) * 2,
                            ENC_UTF_16
                        )
                    );
                    proto_item_prepend_text(payload, "Player Count ");
                    payload = proto_tree_add_string(
                        tree, hf_string_je, tvb, (int32_t) offset1 * 2 + 3, (int32_t) (len - offset1 * 2 - 2),
                        (char *) tvb_get_string_enc(
                            pinfo->pool, tvb, (int32_t) offset1 * 2 + 3, (int32_t) (len - offset1 * 2 - 2), ENC_UTF_16
                        )
                    );
                    proto_item_prepend_text(payload, "Max Players ");
                }
            } else {
                proto_tree_add_string(
                    tree, hf_invalid_data_je, tvb,
                    1, (int32_t) tvb_reported_length(tvb) - 1, "Invalid response"
                );
            }
        }
    }
}
