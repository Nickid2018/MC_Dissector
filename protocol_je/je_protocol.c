//
// Created by Nickid2018 on 2023/7/12.
//

#include <epan/proto.h>
#include <epan/conversation.h>
#include "mc_dissector.h"
#include "je_dissect.h"
#include "je_protocol.h"
#include "utils/nbt.h"

extern int hf_invalid_data;
extern int hf_ignored_packet_je;
extern int hf_packet_id_je;
extern int hf_packet_name_je;
extern int hf_unknown_packet_je;
extern int hf_protocol_version_je;
extern int hf_server_address_je;
extern int hf_next_state_je;
extern int hf_ping_time_je;
extern int hf_server_status_je;
extern int hf_legacy_slp_payload;

int handle_server_handshake_switch(tvbuff_t *tvb, mc_protocol_context *ctx) {
    gint packet_id;
    gint read;
    gint p = read_var_int(tvb, 0, &packet_id);
    if (is_invalid(p))
        return INVALID_DATA;
    if (packet_id == PACKET_ID_HANDSHAKE) {
        gint protocol_version;
        read = read_var_int(tvb, p, &protocol_version);
        if (is_invalid(read))
            return INVALID_DATA;
        p += read;
        gint str_len;
        read = read_var_int(tvb, p, &str_len);
        if (is_invalid(read))
            return INVALID_DATA;
        p += read + str_len + 2;
        gint next_state;
        read = read_var_int(tvb, p, &next_state);
        if (is_invalid(read))
            return INVALID_DATA;
        if (next_state < 1 || next_state > 3)
            return INVALID_DATA;

        ctx->client_state = ctx->server_state = next_state + 1;

        ctx->protocol_version = protocol_version;
        wmem_map_insert(ctx->global_data, "protocol_version", GUINT_TO_POINTER(protocol_version));

        gchar **java_versions = get_mapped_java_versions(protocol_version);
        if (java_versions[0] == NULL) {
            ctx->client_state = ctx->server_state = PROTOCOL_NOT_FOUND;
            return INVALID_DATA;
        }
        ctx->data_version = get_data_version(java_versions[0]);
        wmem_map_insert(ctx->global_data, "data_version", GUINT_TO_POINTER(ctx->data_version));
        if (ctx->data_version >= 3567)
            wmem_map_insert(ctx->global_data, "nbt_any_type", (void *) 1);

        ctx->dissector_set = create_protocol(protocol_version);
        if (ctx->dissector_set == NULL)
            ctx->client_state = ctx->server_state = PROTOCOL_NOT_FOUND;
        return 0;
    } else if (packet_id == PACKET_ID_LEGACY_SERVER_LIST_PING)
        return 0;
    return INVALID_DATA;
}

void handle_server_handshake(proto_tree *packet_tree, packet_info *pinfo, tvbuff_t *tvb) {
    gint packet_id;
    gint p;
    gint read = p = read_var_int(tvb, 0, &packet_id);
    if (is_invalid(read)) {
        proto_tree_add_string(packet_tree, hf_packet_name_je, tvb, 0, 0, "Invalid Packet ID");
        return;
    }
    proto_tree_add_uint(packet_tree, hf_packet_id_je, tvb, 0, read, packet_id);
    if (packet_id == PACKET_ID_HANDSHAKE) {
        proto_tree_add_string_format_value(
                packet_tree, hf_packet_name_je, tvb, 0, read,
                "set_protocol", "Server Handshake"
        );

        gint protocol_version;
        read = read_var_int(tvb, p, &protocol_version);
        if (is_invalid(read)) {
            proto_tree_add_string(packet_tree, hf_protocol_version_je, tvb, p, -1, "Invalid Protocol Version");
            return;
        }
        gchar **java_versions = get_mapped_java_versions(protocol_version);
        if (java_versions == NULL || java_versions[0] == NULL) {
            proto_tree_add_string(packet_tree, hf_protocol_version_je, tvb, p, read, "Unknown Protocol Version");
        } else {
            gchar *java_version = g_strjoinv(",", java_versions);
            g_strfreev(java_versions);
            proto_tree_add_string_format_value(
                    packet_tree, hf_protocol_version_je, tvb, p, read, "",
                    "%d (%s)", protocol_version, java_version
            );
        }
        p += read;

        guint8 *server_address;
        read = read_buffer(tvb, p, &server_address, pinfo->pool);
        if (is_invalid(read)) {
            proto_tree_add_string(packet_tree, hf_server_address_je, tvb, p, -1, "Invalid Server Address");
            return;
        }
        guint16 server_port = tvb_get_uint16(tvb, p + read, ENC_BIG_ENDIAN);
        read += 2;
        proto_tree_add_string_format_value(
                packet_tree, hf_server_address_je, tvb, p, read, "",
                "%s:%d", server_address, server_port
        );
        p += read;

        gint next_state;
        read = read_var_int(tvb, p, &next_state);
        if (is_invalid(read)) {
            proto_tree_add_string(packet_tree, hf_next_state_je, tvb, p, -1, "Invalid Next State");
            return;
        }
        proto_tree_add_string(packet_tree, hf_next_state_je, tvb, p, read, STATE_NAME[next_state + 1]);
    } else if (packet_id == PACKET_ID_LEGACY_SERVER_LIST_PING) {
        proto_tree_add_string_format_value(
                packet_tree, hf_packet_name_je, tvb, 0, read,
                "legacy_server_list_ping", "Legacy Server List Ping"
        );
        guint8 payload = tvb_get_uint8(tvb, p);
        proto_tree_add_uint(packet_tree, hf_legacy_slp_payload, tvb, p, 1, payload);
    } else
        proto_tree_add_string(packet_tree, hf_packet_name_je, tvb, 0, 1, "Unknown Packet ID");
}

void handle_server_slp(proto_tree *packet_tree, tvbuff_t *tvb) {
    gint packet_id;
    gint p;
    gint read = p = read_var_int(tvb, 0, &packet_id);
    if (is_invalid(read)) {
        proto_tree_add_string(packet_tree, hf_packet_name_je, tvb, 0, 0, "Invalid Packet ID");
        return;
    }

    proto_tree_add_uint(packet_tree, hf_packet_id_je, tvb, 0, read, packet_id);
    if (packet_id == PACKET_ID_SERVER_PING_START)
        proto_tree_add_string(packet_tree, hf_packet_name_je, tvb, 0, read, "Server Ping Start");
    else if (packet_id == PACKET_ID_SERVER_PING) {
        proto_tree_add_string(packet_tree, hf_packet_name_je, tvb, 0, read, "Server Ping");
        proto_tree_add_int64(packet_tree, hf_ping_time_je, tvb, p, 8, tvb_get_int64(tvb, p, ENC_BIG_ENDIAN));
    } else
        proto_tree_add_string(packet_tree, hf_packet_name_je, tvb, 0, read, "Unknown Packet ID");
}

void handle_client_slp(proto_tree *packet_tree, packet_info *pinfo, tvbuff_t *tvb) {
    gint packet_id;
    gint p;
    gint read = p = read_var_int(tvb, 0, &packet_id);
    if (is_invalid(read)) {
        proto_tree_add_string(packet_tree, hf_packet_name_je, tvb, 0, 0, "Invalid Packet ID");
        return;
    }

    proto_tree_add_uint(packet_tree, hf_packet_id_je, tvb, 0, read, packet_id);
    if (packet_id == PACKET_ID_CLIENT_SERVER_INFO) {
        proto_tree_add_string(packet_tree, hf_packet_name_je, tvb, 0, read, "Client Server Info");
        guint8 *server_info;
        read = read_buffer(tvb, p, &server_info, pinfo->pool);
        if (is_invalid(read)) {
            proto_tree_add_string(packet_tree, hf_invalid_data, tvb, p, -1, "Invalid Server Info");
            return;
        }
        proto_tree_add_string(packet_tree, hf_server_status_je, tvb, p, read, *(char **) &server_info);
    } else if (packet_id == PACKET_ID_CLIENT_PING) {
        proto_tree_add_string(packet_tree, hf_packet_name_je, tvb, 0, read, "Client Ping");
        proto_tree_add_int64(packet_tree, hf_ping_time_je, tvb, p, 8, tvb_get_int64(tvb, p, ENC_BIG_ENDIAN));
    } else
        proto_tree_add_string(packet_tree, hf_packet_name_je, tvb, 0, read, "Unknown Packet ID");
}

void handle_protocol(
        proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, mc_protocol_context *ctx, je_state state, bool is_client
) {
    if (ctx->dissector_set == NULL) {
        proto_tree_add_string(tree, hf_invalid_data, tvb, 0, 1, "Can't find protocol set for this version");
        ctx->client_state = ctx->server_state = PROTOCOL_NOT_FOUND;
        return;
    }

    uint32_t now_state = is_client ? state : state + 16;
    int32_t packet_id;
    int32_t len = read_var_int(tvb, 0, &packet_id);
    if (is_invalid(len)) {
        proto_tree_add_string(tree, hf_packet_name_je, tvb, 0, 0, "Invalid Packet ID");
        return;
    }

    uint32_t count = (uint64_t) wmem_map_lookup(ctx->dissector_set->count_by_state, (void *) (uint64_t) now_state);
    if (packet_id >= count) {
        proto_tree_add_string(tree, hf_unknown_packet_je, tvb, 0, 1, "Unknown Packet ID");
        return;
    }

    gchar **key = wmem_map_lookup(ctx->dissector_set->registry_keys, (void *) (uint64_t) now_state);
    gchar **name = wmem_map_lookup(ctx->dissector_set->readable_names, (void *) (uint64_t) now_state);
    protocol_dissector **d = wmem_map_lookup(ctx->dissector_set->dissectors_by_state, (void *) (uint64_t) now_state);
    proto_tree_add_string_format_value(
            tree, hf_packet_name_je, tvb, 0, len, key[packet_id],
            "%s (%s)", name[packet_id], key[packet_id]
    );

    bool ignore = false;
    if (strlen(pref_ignore_packets_je) != 0) {
        gchar *search_name = g_strdup_printf("%s:%s", is_client ? "c" : "s", key[packet_id]);
        GList *list = prefs_get_string_list(pref_ignore_packets_je);
        ignore = g_list_find_custom(list, search_name, (GCompareFunc) g_strcmp0) != NULL;
    }

    uint32_t length = tvb_reported_length(tvb);
    if (ignore)
        proto_tree_add_string(tree, hf_ignored_packet_je, tvb, len, (int32_t) length - len, "Ignored by user");
    else {
        wmem_map_t *packet_save = wmem_map_new(pinfo->pool, g_str_hash, g_str_equal);
        int32_t sub_len = d[packet_id]->dissect_protocol(
                tree, pinfo, tvb, len, d[packet_id], "Packet Data", packet_save, NULL
        );
        if (sub_len + len != length && sub_len != DISSECT_ERROR)
            proto_tree_add_string_format_value(
                    tree, hf_invalid_data, tvb, len, (int32_t) length - len,
                    "length mismatch", "Packet length mismatch, expected %d, got %d", length - len,
                    sub_len
            );
    }
}

int try_switch_state(tvbuff_t *tvb, mc_protocol_context *ctx, bool is_client) {
    if (ctx->dissector_set == NULL) return INVALID_DATA;
    uint32_t now_state = is_client ? ctx->client_state : ctx->server_state + 16;
    int32_t packet_id;
    int32_t len = read_var_int(tvb, 0, &packet_id);
    if (is_invalid(len)) return INVALID_DATA;
    wmem_map_t *state_to_next = wmem_map_lookup(ctx->dissector_set->state_to_next, (void *) (uint64_t) now_state);
    wmem_map_t *state_side = wmem_map_lookup(ctx->dissector_set->state_to_next_side, (void *) (uint64_t) now_state);
    wmem_map_t *special_mark = wmem_map_lookup(ctx->dissector_set->special_mark, (void *) (uint64_t) now_state);
    if (wmem_map_contains(state_to_next, (void *) (uint64_t) packet_id)) {
        uint32_t state = (uint64_t) wmem_map_lookup(state_to_next, (void *) (uint64_t) packet_id);
        uint32_t side = (uint64_t) wmem_map_lookup(state_side, (void *) (uint64_t) packet_id);
        if ((side & 1) != 0) ctx->client_state = state;
        if ((side & 2) != 0) ctx->server_state = state;
    }
    if (wmem_map_contains(special_mark, (void *) (uint64_t) packet_id)) {
        gchar *mark = wmem_map_lookup(special_mark, (void *) (uint64_t) packet_id);

        if (strcmp(mark, "encrypt") == 0) ctx->encrypted = true;
        if (strcmp(mark, "compress") == 0) {
            int32_t threshold;
            len = read_var_int(tvb, len, &threshold);
            if (is_invalid(len)) return INVALID_DATA;
            ctx->compression_threshold = threshold;
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
            gchar *registry_name;
            int32_t offset = len;
            len = read_buffer(tvb, offset, (uint8_t **) &registry_name, wmem_file_scope());
            if (is_invalid(len)) return INVALID_DATA;
            registry_name = g_utf8_substring(registry_name, 10, g_utf8_strlen(registry_name, 200));
            offset += len;
            int32_t count;
            len = read_var_int(tvb, offset, &count);
            if (is_invalid(len)) return INVALID_DATA;
            offset += len;
            gchar **data = wmem_alloc(wmem_file_scope(), sizeof(gchar *) * count);
            bool is_new_nbt = wmem_map_lookup(ctx->global_data, "nbt_any_type");
            for (int i = 0; i < count; i++) {
                gchar *name;
                len = read_buffer(tvb, offset, (uint8_t **) &name, wmem_file_scope());
                if (is_invalid(len)) {
                    wmem_free(wmem_file_scope(), data);
                    return INVALID_DATA;
                }
                data[i] = g_utf8_substring(name, 10, g_utf8_strlen(name, 200));
                if (tvb_get_uint8(tvb, offset + len) == 0) {
                    len += 1;
                } else {
                    if (is_new_nbt) {
                        bool present = tvb_get_uint8(tvb, offset + len + 1);
                        len += present ? count_nbt_length_with_type(tvb, offset + len + 2, present) + 2 : 2;
                    } else
                        len += count_nbt_length(tvb, offset + len + 1) + 1;
                }
                offset += len;
            }
            wmem_map_insert(writable_registry, registry_name, data);
            wmem_map_insert(writable_registry_size, registry_name, (void *) (uint64_t) count);
        }
    }
    return 0;
}