//
// Created by Nickid2018 on 2023/7/12.
//

#include "je_protocol.h"
#include "protocol_data.h"
#include "mc_dissector.h"
#include <epan/proto.h>

void handle_server_handshake(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const guint8 *data, guint length, mc_protocol_context *ctx) {
    guint packet_id;
    guint p;
    gint read = p = read_var_int(data, length, &packet_id);
    if (is_invalid(read)) {
        proto_tree_add_string(packet_tree, hf_packet_id_je, tvb, 0, 0, "Invalid Packet ID");
        return;
    }
    if (packet_id != 0x00) {
        proto_item_set_text(proto_tree_add_item(packet_tree, hf_packet_id_je, tvb, 0, 1, FALSE),
                            "Unknown Packet ID (%d)", packet_id);
        return;
    }
    proto_tree_add_string(packet_tree, hf_packet_id_je, tvb, 0, 1, "0x00 Server Handshake");
    guint protocol_version;
    read = read_var_int(data + p, length - p, &protocol_version);
    ctx->protocol_version = protocol_version;
    proto_item_set_text(proto_tree_add_item(packet_tree, hf_protocol_version_je, tvb, p, read, FALSE),
                        "%d ()", protocol_version);
    p += read;
    guint8 *server_address;
    read = read_string(data + p, &server_address);
    if (is_invalid(read)) {
        proto_tree_add_string(packet_tree, hf_server_address_je, tvb, p, 0,"Invalid Server Address");
        return;
    }
    guint16 server_port;
    read += read_ushort(data + p + read, &server_port);
    proto_item_set_text(proto_tree_add_item(packet_tree, hf_server_address_je, tvb, p, read, FALSE),
                        "%s:%d", server_address, server_port);
    p += read;
    guint next_state;
    read = read_var_int(data + p, length - p, &next_state);
    if (is_invalid(read)) {
        proto_tree_add_string(packet_tree, hf_next_state_je, tvb, p, 0, "Invalid Next State");
        return;
    }
    ctx->state = next_state + 1;
    proto_tree_add_string(packet_tree, hf_next_state_je, tvb, p, read, STATE_NAME[next_state]);
}