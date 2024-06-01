//
// Created by Nickid2018 on 2023/7/12.
//

#include <epan/proto.h>
#include <epan/conversation.h>
#include "mc_dissector.h"
#include "je_dissect.h"
#include "je_protocol.h"
#include "strings_je.h"

int handle_server_handshake_switch(const guint8 *data, guint length, mcje_protocol_context *ctx) {
    guint packet_id;
    guint read;
    guint p = read_var_int(data, length, &packet_id);
    if (is_invalid(p))
        return INVALID_DATA;
    if (packet_id == PACKET_ID_HANDSHAKE) {
        guint protocol_version;
        read = read_var_int(data + p, length - p, &protocol_version);
        if (is_invalid(read))
            return INVALID_DATA;
        p += read;
        guint str_len;
        read = read_var_int(data + p, length - p, &str_len);
        if (is_invalid(read))
            return INVALID_DATA;
        p += read + str_len + 2;
        guint next_state;
        read = read_var_int(data + p, length - p, &next_state);
        if (is_invalid(read))
            return INVALID_DATA;
        if (next_state < 1 || next_state > 3)
            return INVALID_DATA;
        gchar *unchecked_java_version = get_java_version_name_unchecked(protocol_version);
        ctx->data_version = get_java_data_version(unchecked_java_version);
        if (ctx->data_version == -1)
            return INVALID_DATA;
        guint nearest_data_version = find_nearest_java_protocol(ctx->data_version);
        gchar *nearest_java_version = get_java_version_name_by_data_version(nearest_data_version);
        ctx->client_state = ctx->server_state = next_state + 1;
        ctx->protocol_set = get_protocol_je_set(nearest_java_version);
        ctx->protocol_version = protocol_version;
#ifdef MC_DISSECTOR_FUNCTION_FEATURE
        wmem_map_insert(((extra_data *) ctx->extra)->data, "protocol_version", GUINT_TO_POINTER(protocol_version));
        wmem_map_insert(((extra_data *) ctx->extra)->data, "data_version", GUINT_TO_POINTER(ctx->data_version));
#endif // MC_DISSECTOR_FUNCTION_FEATURE
        return 0;
    } else if (packet_id == PACKET_ID_LEGACY_SERVER_LIST_PING)
        return 0;
    return INVALID_DATA;
}

void handle_server_handshake(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const guint8 *data,
                             guint length, mcje_protocol_context *ctx) {
    guint packet_id;
    guint p;
    gint read = p = read_var_int(data, length, &packet_id);
    if (is_invalid(read)) {
        proto_tree_add_string(packet_tree, hf_packet_name_je, tvb, 0, 0, "Invalid Packet ID");
        return;
    }
    proto_tree_add_uint(packet_tree, hf_packet_id_je, tvb, 0, read, packet_id);
    if (packet_id == PACKET_ID_HANDSHAKE) {
        proto_tree_add_string_format_value(packet_tree, hf_packet_name_je, tvb, 0, read,
                                           "set_protocol", "Server Handshake");

        guint protocol_version;
        read = read_var_int(data + p, length - p, &protocol_version);
        if (is_invalid(read)) {
            proto_tree_add_string(packet_tree, hf_protocol_version_je, tvb, p, -1, "Invalid Protocol Version");
            return;
        }
        proto_tree_add_string_format_value(packet_tree, hf_protocol_version_je, tvb, p, read, "",
                                           "%d (%s)", protocol_version, get_java_version_name(protocol_version));
        p += read;

        guint8 *server_address;
        read = read_buffer(data + p, &server_address);
        if (is_invalid(read)) {
            proto_tree_add_string(packet_tree, hf_server_address_je, tvb, p, -1, "Invalid Server Address");
            return;
        }
        guint16 server_port;
        read += read_ushort(data + p + read, &server_port);
        proto_tree_add_string_format_value(packet_tree, hf_server_address_je, tvb, p, read, "",
                                           "%s:%d", server_address, server_port);
        p += read;

        guint next_state;
        read = read_var_int(data + p, length - p, &next_state);
        if (is_invalid(read)) {
            proto_tree_add_string(packet_tree, hf_next_state_je, tvb, p, -1, "Invalid Next State");
            return;
        }
        proto_tree_add_string(packet_tree, hf_next_state_je, tvb, p, read, STATE_NAME[next_state + 1]);
    } else if (packet_id == PACKET_ID_LEGACY_SERVER_LIST_PING) {
        proto_tree_add_string_format_value(packet_tree, hf_packet_name_je, tvb, 0, read,
                                           "legacy_server_list_ping", "Legacy Server List Ping");
        guint8 payload = data[p];
        proto_tree_add_uint(packet_tree, hf_legacy_slp_payload, tvb, p, 1, payload);
    } else
        proto_tree_add_string(packet_tree, hf_packet_name_je, tvb, 0, 1, "Unknown Packet ID");
}

void handle_server_slp(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const guint8 *data,
                       guint length, mcje_protocol_context *ctx) {
    guint packet_id;
    guint p;
    gint read = p = read_var_int(data, length, &packet_id);
    if (is_invalid(read)) {
        proto_tree_add_string(packet_tree, hf_packet_name_je, tvb, 0, 0, "Invalid Packet ID");
        return;
    }

    proto_tree_add_uint(packet_tree, hf_packet_id_je, tvb, 0, read, packet_id);
    if (packet_id == PACKET_ID_SERVER_PING_START)
        proto_tree_add_string(packet_tree, hf_packet_name_je, tvb, 0, read, "Server Ping Start");
    else if (packet_id == PACKET_ID_SERVER_PING) {
        proto_tree_add_string(packet_tree, hf_packet_name_je, tvb, 0, read, "Server Ping");
        guint64 payload;
        read = read_ulong(data + p, &payload);
        if (is_invalid(read)) {
            proto_tree_add_string(packet_tree, hf_invalid_data_je, tvb, p, -1, "Invalid time field");
            return;
        }
        proto_tree_add_int64(packet_tree, hf_ping_time_je, tvb, p, read, *(gint64 *) &payload);
    } else
        proto_tree_add_string(packet_tree, hf_packet_name_je, tvb, 0, read, "Unknown Packet ID");
}

void handle_client_slp(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const guint8 *data,
                       guint length, mcje_protocol_context *ctx) {
    guint packet_id;
    guint p;
    gint read = p = read_var_int(data, length, &packet_id);
    if (is_invalid(read)) {
        proto_tree_add_string(packet_tree, hf_packet_name_je, tvb, 0, 0, "Invalid Packet ID");
        return;
    }

    proto_tree_add_uint(packet_tree, hf_packet_id_je, tvb, 0, read, packet_id);
    if (packet_id == PACKET_ID_CLIENT_SERVER_INFO) {
        proto_tree_add_string(packet_tree, hf_packet_name_je, tvb, 0, read, "Client Server Info");
        guint8 *server_info;
        read = read_buffer(data + p, &server_info);
        if (is_invalid(read)) {
            proto_tree_add_string(packet_tree, hf_invalid_data_je, tvb, p, -1, "Invalid Server Info");
            return;
        }
        proto_tree_add_string(packet_tree, hf_server_status_je, tvb, p, read, server_info);
    } else if (packet_id == PACKET_ID_CLIENT_PING) {
        proto_tree_add_string(packet_tree, hf_packet_name_je, tvb, 0, read, "Client Ping");
        guint64 payload;
        read = read_ulong(data + p, &payload);
        if (is_invalid(read)) {
            proto_tree_add_string(packet_tree, hf_invalid_data_je, tvb, p, -1, "Invalid time field");
            return;
        }
        proto_tree_add_int64(packet_tree, hf_ping_time_je, tvb, p, read, *(gint64 *) &payload);
    } else
        proto_tree_add_string(packet_tree, hf_packet_name_je, tvb, 0, read, "Unknown Packet ID");
}

int handle_client_login_switch(const guint8 *data, guint length, mcje_protocol_context *ctx) {
    if (ctx->protocol_set == NULL) {
        ctx->client_state = ctx->server_state = INVALID;
        return -1;
    }
    guint packet_id;
    guint read;
    guint p = read_var_int(data, length, &packet_id);
    if (is_invalid(p))
        return INVALID_DATA;
    if (packet_id == PACKET_ID_CLIENT_SUCCESS) {
        if (ctx->data_version >= 3567)
            ctx->client_state = CONFIGURATION;
        else
            ctx->client_state = ctx->server_state = PLAY;
    }
    if (packet_id == PACKET_ID_CLIENT_COMPRESS) {
        guint threshold;
        read = read_var_int(data + p, length - p, &threshold);
        if (is_invalid(read))
            return INVALID_DATA;
        ctx->compression_threshold = threshold;
    }
    return 0;
}

int handle_server_login_switch(const guint8 *data, guint length, mcje_protocol_context *ctx, packet_info *pinfo) {
    if (ctx->protocol_set == NULL) {
        ctx->client_state = ctx->server_state = INVALID;
        return -1;
    }
    guint packet_id;
    guint p = read_var_int(data, length, &packet_id);
    if (is_invalid(p))
        return INVALID_DATA;
    if (packet_id == get_packet_id(ctx->protocol_set->login, "login_acknowledgement", false))
        ctx->server_state = CONFIGURATION;
    if (packet_id == PACKET_ID_SERVER_ENCRYPTION_BEGIN) {
        gchar *secret_key_str = pref_secret_key;
        if (strlen(secret_key_str) != 32) {
            ctx->client_state = ctx->server_state = INVALID;
            return INVALID_DATA;
        }
        guint8 secret_key[16];
        for (int i = 0; i < 16; i++) {
            gchar hex[3] = {secret_key_str[i * 2], secret_key_str[i * 2 + 1], '\0'};
            secret_key[i] = (guint8) strtol(hex, NULL, 16);
        }
        mcje_decryption_context *decryption_context = wmem_new(wmem_file_scope(), mcje_decryption_context);
        decryption_context->client_last_decrypt_available = 0;
        decryption_context->server_last_decrypt_available = 0;
        decryption_context->client_decrypt_length = 0;
        decryption_context->server_decrypt_length = 0;
        decryption_context->client_required_length = 0;
        decryption_context->server_required_length = 0;
        decryption_context->client_decrypt = wmem_alloc(wmem_file_scope(), 0);
        decryption_context->server_decrypt = wmem_alloc(wmem_file_scope(), 0);
        gcry_cipher_open(&decryption_context->server_cipher, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CFB8, 0);
        gcry_cipher_setkey(decryption_context->server_cipher, secret_key, sizeof(secret_key));
        gcry_cipher_setiv(decryption_context->server_cipher, secret_key, sizeof(secret_key));
        gcry_cipher_open(&decryption_context->client_cipher, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CFB8, 0);
        gcry_cipher_setkey(decryption_context->client_cipher, secret_key, sizeof(secret_key));
        gcry_cipher_setiv(decryption_context->client_cipher, secret_key, sizeof(secret_key));
        ctx->decryption_context = decryption_context;
    }
    return 0;
}

void handle(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const guint8 *data,
            guint length, mcje_protocol_context *ctx, protocol_set protocol_set, bool is_client) {
    guint packet_id;
    guint p;
    gint read = p = read_var_int(data, length, &packet_id);
    if (is_invalid(read)) {
        proto_tree_add_string(packet_tree, hf_packet_name_je, tvb, 0, 0, "Invalid Packet ID");
        return;
    }
    if (protocol_set == NULL) {
        proto_tree_add_string(packet_tree, hf_invalid_data_je, tvb, 0, 1, "Can't find protocol set");
        return;
    }
    protocol_entry protocol = get_protocol_entry(protocol_set, packet_id, is_client);
    proto_tree_add_uint(packet_tree, hf_packet_id_je, tvb, 0, read, packet_id);
    if (protocol == NULL) {
        proto_tree_add_string(packet_tree, hf_unknown_packet_je, tvb, 0, 1, "Unknown Packet ID");
        return;
    }
    gchar *packet_name = get_packet_name(protocol);
    if (packet_id == 1) // Temp fix for debugging
        return;
    gchar *better_name = wmem_map_lookup(is_client ? protocol_name_map_client_je : protocol_name_map_server_je,
                                         packet_name);
    if (better_name == NULL)
        proto_tree_add_string(packet_tree, hf_packet_name_je, tvb, 0, read, packet_name);
    else
        proto_tree_add_string_format_value(packet_tree, hf_packet_name_je, tvb, 0, read, packet_name,
                                           "%s (%s)", better_name, packet_name);

    bool ignore = false;
    if (strlen(pref_ignore_packets_je) != 0) {
        gchar *search_name = g_strdup_printf("%s:%s", is_client ? "c" : "s", packet_name);
        GList *list = prefs_get_string_list(pref_ignore_packets_je);
        ignore = g_list_find_custom(list, search_name, (GCompareFunc) g_strcmp0) != NULL;
    }
    if (ignore)
        proto_tree_add_string(packet_tree, hf_ignored_packet_je, tvb, p, length - p, "Ignored by user");
    else if (!make_tree(protocol, packet_tree, tvb, ctx->extra, data, length))
        proto_tree_add_string(packet_tree, hf_ignored_packet_je, tvb, p, length - p,
                              "Protocol hasn't been implemented yet");
}

void handle_login(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const guint8 *data,
                  guint length, mcje_protocol_context *ctx, bool is_client) {
    if (ctx->protocol_set == NULL) {
        proto_tree_add_string(packet_tree, hf_invalid_data_je, tvb, 0, 1, "Can't find protocol set for this version");
        ctx->client_state = ctx->server_state = INVALID;
        return;
    }
    handle(packet_tree, tvb, pinfo, data, length, ctx, ctx->protocol_set->login, is_client);
}

int handle_client_play_switch(const guint8 *data, guint length, mcje_protocol_context *ctx) {
    if (ctx->protocol_set == NULL) {
        ctx->client_state = ctx->server_state = INVALID;
        return -1;
    }
    guint packet_id;
    guint p = read_var_int(data, length, &packet_id);
    if (is_invalid(p))
        return INVALID_DATA;
    if (packet_id == get_packet_id(ctx->protocol_set->play, "start_configuration", true))
        ctx->client_state = CONFIGURATION;
    return 0;
}

int handle_server_play_switch(const guint8 *data, guint length, mcje_protocol_context *ctx) {
    if (ctx->protocol_set == NULL) {
        ctx->client_state = ctx->server_state = INVALID;
        return -1;
    }
    guint packet_id;
    guint p = read_var_int(data, length, &packet_id);
    if (is_invalid(p))
        return INVALID_DATA;
    if (packet_id == get_packet_id(ctx->protocol_set->play, "configuration_acknowledgement", false))
        ctx->server_state = CONFIGURATION;
    return 0;
}

void handle_play(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const guint8 *data,
                 guint length, mcje_protocol_context *ctx, bool is_client) {
    if (ctx->protocol_set == NULL) {
        proto_tree_add_string(packet_tree, hf_invalid_data_je, tvb, 0, 1, "Can't find protocol set for this version");
        ctx->client_state = ctx->server_state = INVALID;
        return;
    }
    handle(packet_tree, tvb, pinfo, data, length, ctx, ctx->protocol_set->play, is_client);
}

int handle_client_configuration_switch(const guint8 *data, guint length, mcje_protocol_context *ctx) {
    if (ctx->protocol_set == NULL) {
        ctx->client_state = ctx->server_state = INVALID;
        return -1;
    }
    guint packet_id;
    guint p = read_var_int(data, length, &packet_id);
    if (is_invalid(p))
        return INVALID_DATA;
    if (packet_id == get_packet_id(ctx->protocol_set->configuration, "finish_configuration", true))
        ctx->client_state = PLAY;
    return 0;
}

int handle_server_configuration_switch(const guint8 *data, guint length, mcje_protocol_context *ctx) {
    if (ctx->protocol_set == NULL) {
        ctx->client_state = ctx->server_state = INVALID;
        return -1;
    }
    guint packet_id;
    guint p = read_var_int(data, length, &packet_id);
    if (is_invalid(p))
        return INVALID_DATA;
    if (packet_id == get_packet_id(ctx->protocol_set->configuration, "finish_configuration", false))
        ctx->server_state = PLAY;
    return 0;
}

void handle_configuration(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const guint8 *data,
                          guint length, mcje_protocol_context *ctx, bool is_client) {
    if (ctx->protocol_set == NULL) {
        proto_tree_add_string(packet_tree, hf_invalid_data_je, tvb, 0, 1, "Can't find protocol set for this version");
        ctx->client_state = ctx->server_state = INVALID;
        return;
    }
    handle(packet_tree, tvb, pinfo, data, length, ctx, ctx->protocol_set->configuration, is_client);
}