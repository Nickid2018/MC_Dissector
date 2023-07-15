//
// Created by Nickid2018 on 2023/7/12.
//

#include <epan/proto.h>
#include <stdlib.h>
#include "je_dissect.h"
#include "je_protocol.h"

int handle_server_handshake_switch(const guint8 *data, guint length, mcje_protocol_context *ctx) {
    guint packet_id;
    guint read;
    guint p = read_var_int(data, length, &packet_id);
    if (is_invalid(p))
        return INVALID_DATA;
    if (packet_id != PACKET_ID_HANDSHAKE)
        return INVALID_DATA;
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
    if (next_state != 1 && next_state != 2)
        return INVALID_DATA;
    gchar *unchecked_java_version = get_java_version_name_unchecked(protocol_version);
    gint data_version = get_java_data_version(unchecked_java_version);
    if (data_version == -1)
        return INVALID_DATA;
    guint nearest_data_version = find_nearest_java_protocol(data_version);
    gchar *nearest_java_version = get_java_version_name_by_data_version(nearest_data_version);
    ctx->state = next_state + 1;
    ctx->protocol_set = get_protocol_je_set(nearest_java_version);
    ctx->protocol_version = protocol_version;
    return 0;
}

void handle_server_handshake(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const guint8 *data,
                             guint length, mcje_protocol_context *ctx) {
    guint packet_id;
    guint p;
    gint read = p = read_var_int(data, length, &packet_id);
    if (is_invalid(read)) {
        proto_tree_add_string(packet_tree, hf_packet_id_je, tvb, 0, 0, "Invalid Packet ID");
        return;
    }
    if (packet_id != 0x00) {
        proto_tree_add_string_format_value(packet_tree, hf_packet_id_je, tvb, 0, 1, "",
                                           "Unknown Packet ID (%d)", packet_id);
        return;
    }
    proto_tree_add_string(packet_tree, hf_packet_id_je, tvb, 0, 1, "0x00 Server Handshake");

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
}

void handle_server_slp(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const guint8 *data,
                       guint length, mcje_protocol_context *ctx) {
    guint packet_id;
    guint p;
    gint read = p = read_var_int(data, length, &packet_id);
    if (is_invalid(read)) {
        proto_tree_add_string(packet_tree, hf_packet_id_je, tvb, 0, 0, "Invalid Packet ID");
        return;
    }

    if (packet_id == PACKET_ID_SERVER_PING_START)
        proto_tree_add_string(packet_tree, hf_packet_id_je, tvb, 0, 1, "0x00 Server Ping Start");
    else if (packet_id == PACKET_ID_SERVER_PING) {
        proto_tree_add_string(packet_tree, hf_packet_id_je, tvb, 0, 1, "0x01 Server Ping");
        guint64 payload;
        read = read_ulong(data + p, &payload);
        if (is_invalid(read)) {
            proto_tree_add_string(packet_tree, hf_invalid_data_je, tvb, p, -1, "Invalid time field");
            return;
        }
        proto_tree_add_uint64(packet_tree, hf_ping_time_je, tvb, p, read, payload);
    } else
        proto_tree_add_string_format_value(packet_tree, hf_packet_id_je, tvb, 0, 1, "",
                                           "Unknown Packet ID (%d)", packet_id);
}

void handle_client_slp(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const guint8 *data,
                       guint length, mcje_protocol_context *ctx) {
    guint packet_id;
    guint p;
    gint read = p = read_var_int(data, length, &packet_id);
    if (is_invalid(read)) {
        proto_tree_add_string(packet_tree, hf_packet_id_je, tvb, 0, 0, "Invalid Packet ID");
        return;
    }

    if (packet_id == PACKET_ID_CLIENT_SERVER_INFO) {
        proto_tree_add_string(packet_tree, hf_packet_id_je, tvb, 0, 1, "0x00 Client Server Info");
        guint8 *server_info;
        read = read_buffer(data + p, &server_info);
        if (is_invalid(read)) {
            proto_tree_add_string(packet_tree, hf_invalid_data_je, tvb, p, -1, "Invalid Server Info");
            return;
        }
        proto_tree_add_string(packet_tree, hf_server_status_je, tvb, p, read, server_info);
    } else if (packet_id == PACKET_ID_CLIENT_PING) {
        proto_tree_add_string(packet_tree, hf_packet_id_je, tvb, 0, 1, "0x01 Client Ping");
        guint64 payload;
        read = read_ulong(data + p, &payload);
        if (is_invalid(read)) {
            proto_tree_add_string(packet_tree, hf_invalid_data_je, tvb, p, -1, "Invalid time field");
            return;
        }
        proto_tree_add_uint64(packet_tree, hf_ping_time_je, tvb, p, read, payload);
    } else
        proto_tree_add_string_format_value(packet_tree, hf_packet_id_je, tvb, 0, 1, "",
                                           "Unknown Packet ID (%d)", packet_id);
}

int handle_client_login_switch(const guint8 *data, guint length, mcje_protocol_context *ctx) {
    guint packet_id;
    guint read;
    guint p = read_var_int(data, length, &packet_id);
    if (is_invalid(p))
        return INVALID_DATA;
    if (packet_id == PACKET_ID_CLIENT_SUCCESS)
        ctx->state = PLAY;
    if (packet_id == PACKET_ID_CLIENT_COMPRESS) {
        guint threshold;
        read = read_var_int(data + p, length - p, &threshold);
        if (is_invalid(read))
            return INVALID_DATA;
        ctx->compression_threshold = threshold;
    }
    return 0;
}

void handle(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const guint8 *data,
            guint length, mcje_protocol_context *ctx, protocol_set protocol_set, bool is_client) {
    guint packet_id;
    guint p;
    gint read = p = read_var_int(data, length, &packet_id);
    if (is_invalid(read)) {
        proto_tree_add_string(packet_tree, hf_packet_id_je, tvb, 0, 0, "Invalid Packet ID");
        return;
    }
    if (protocol_set == NULL) {
        proto_tree_add_string(packet_tree, hf_packet_id_je, tvb, 0, 1, "Can't find protocol set");
        return;
    }
    protocol_entry protocol = get_protocol_entry(protocol_set, packet_id, is_client);
    if (protocol == NULL) {
        proto_tree_add_string_format_value(packet_tree, hf_packet_id_je, tvb, 0, 1, "",
                                           "Unknown Packet ID (%d)", packet_id);
        return;
    }
    gchar *packet_name = get_packet_name(protocol);
    proto_tree_add_string_format_value(packet_tree, hf_packet_id_je, tvb, 0, 1, "",
                                       "0x%02x %s", packet_id, packet_name);
}

void handle_login(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const guint8 *data,
                         guint length, mcje_protocol_context *ctx, bool is_client) {
    if (ctx->protocol_set == NULL) {
        proto_tree_add_string(packet_tree, hf_packet_id_je, tvb, 0, 1, "Can't find protocol set");
        return;
    }
    handle(packet_tree, tvb, pinfo, data, length, ctx, ctx->protocol_set->login, is_client);
}

void handle_play(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const guint8 *data,
                  guint length, mcje_protocol_context *ctx, bool is_client) {
    if (ctx->protocol_set == NULL) {
        proto_tree_add_string(packet_tree, hf_packet_id_je, tvb, 0, 1, "Can't find protocol set");
        return;
    }
    handle(packet_tree, tvb, pinfo, data, length, ctx, ctx->protocol_set->play, is_client);
}