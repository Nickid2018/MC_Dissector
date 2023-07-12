//
// Created by Nickid2018 on 2023/7/12.
//

#include "je_protocol.h"
#include "protocol_data.h"
#include "mc_dissector.h"
#include <epan/proto.h>

int handle_server_handshake_switch(const guint8 *data, guint length, mc_protocol_context *ctx) {
    guint packet_id;
    guint read;
    guint p = read_var_int(data, length, &packet_id);
    if (is_invalid(p))
        return INVALID_DATA;
    if (packet_id != PACKET_ID_HANDSHAKE)
        return INVALID_DATA;
    read = read_var_int(data + p, length - p, &ctx->protocol_version);
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
    ctx->state = next_state + 1;
    return 0;
}

void handle_server_handshake(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const guint8 *data,
                             guint length, mc_protocol_context *ctx) {
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
    ctx->protocol_version = protocol_version;
    proto_tree_add_string_format_value(packet_tree, hf_protocol_version_je, tvb, p, read, "",
                        "%d ()", protocol_version);
    p += read;
    guint8 *server_address;
    read = read_string(data + p, &server_address);
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
                       guint length, mc_protocol_context *ctx) {
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
                       guint length, mc_protocol_context *ctx) {
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
        read = read_string(data + p, &server_info);
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