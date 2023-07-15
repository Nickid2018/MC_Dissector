//
// Created by Nickid2018 on 2023/7/13.
//

#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/proto_data.h>
#include "../mc_dissector.h"
#include "je_dissect.h"
#include "je_protocol.h"

int hf_invalid_data_je = -1;
int hf_packet_length_je = -1;
int hf_packet_data_length_je = -1;
int hf_packet_id_je = -1;
int hf_packet_name_je = -1;
int hf_protocol_version_je = -1;
int hf_server_address_je = -1;
int hf_next_state_je = -1;
int hf_ping_time_je = -1;
int hf_server_status_je = -1;

int hf_unknown_int_je = -1;
int hf_unknown_uint_je = -1;
int hf_unknown_int64_je = -1;
int hf_unknown_uint64_je = -1;
int hf_unknown_float_je = -1;
int hf_unknown_double_je = -1;
int hf_unknown_bytes_je = -1;
int hf_unknown_string_je = -1;
int hf_unknown_boolean_je = -1;
int hf_unknown_uuid_je = -1;
// --------------------
#define ADD_HF(name, hf_index) wmem_map_insert(name_hf_map_je, g_strdup(name), GINT_TO_POINTER(hf_index))
int hf_threshold = -1;
int hf_position_xzy = -1;
int hf_x_26 = -1;
int hf_z_26 = -1;
int hf_y_12 = -1;
// --------------------

dissector_handle_t mcje_boot_handle, mcje_handle, ignore_je_handle;

int ett_mcje = -1, ett_je_proto = -1;
int ett_sub_je = -1;
wmem_map_t *name_hf_map_je = NULL;
wmem_map_t *unknown_hf_map_je = NULL;
wmem_map_t *bitmask_hf_map_je = NULL;

void proto_reg_handoff_mcje() {
    mcje_boot_handle = create_dissector_handle(dissect_je_boot, proto_mcje);
    mcje_handle = create_dissector_handle(dissect_je_conv, proto_mcje);
    ignore_je_handle = create_dissector_handle(dissect_je_ignore, proto_mcje);
    dissector_add_uint("tcp.port", MCJE_PORT, mcje_boot_handle);
}

void proto_register_mcje() {
    proto_mcje = proto_register_protocol(MCJE_NAME, MCJE_SHORT_NAME, MCJE_FILTER);

    static gint *ett_je[] = {&ett_mcje, &ett_je_proto, &ett_sub_je};
    static hf_register_info hf_je[] = {
            DEFINE_HF(hf_invalid_data_je, "Invalid Data", "mcje.invalid_data", STRING, NONE)
            DEFINE_HF(hf_packet_length_je, "Packet Length", "mcje.packet_length", UINT32, DEC)
            DEFINE_HF(hf_packet_data_length_je, "Packet Data Length", "mcje.packet_data_length", UINT32, DEC)
            DEFINE_HF(hf_packet_id_je, "Packet ID", "mcje.packet_id", UINT8, HEX)
            DEFINE_HF(hf_packet_name_je, "Packet Name", "mcje.packet_name", STRING, NONE)
            DEFINE_HF(hf_protocol_version_je, "Protocol Version", "mcje.protocol_version", STRING, NONE)
            DEFINE_HF(hf_server_address_je, "Server Address", "mcje.server_address", STRING, NONE)
            DEFINE_HF(hf_next_state_je, "Next State", "mcje.next_state", STRING, NONE)
            DEFINE_HF(hf_ping_time_je, "Ping Time", "mcje.ping_time", UINT64, DEC)
            DEFINE_HF(hf_server_status_je, "Server Status", "mcje.server_status", STRING, NONE)
            DEFINE_HF(hf_unknown_int_je, "Unresolved Integer", "mcje.unknown_int", INT32, DEC)
            DEFINE_HF(hf_unknown_uint_je, "Unresolved Unsigned Integer", "mcje.unknown_uint", UINT32, DEC)
            DEFINE_HF(hf_unknown_int64_je, "Unresolved Long Integer", "mcje.unknown_int64", INT64, DEC)
            DEFINE_HF(hf_unknown_uint64_je, "Unresolved Unsigned Long Integer", "mcje.unknown_uint64", UINT64, DEC)
            DEFINE_HF(hf_unknown_float_je, "Unresolved Float", "mcje.unknown_float", FLOAT, DEC)
            DEFINE_HF(hf_unknown_double_je, "Unresolved Double", "mcje.unknown_double", DOUBLE, DEC)
            DEFINE_HF(hf_unknown_bytes_je, "Unresolved Bytes", "mcje.unknown_bytes", BYTES, NONE)
            DEFINE_HF(hf_unknown_string_je, "Unresolved String", "mcje.unknown_string", STRING, NONE)
            DEFINE_HF(hf_unknown_boolean_je, "Unresolved Boolean", "mcje.unknown_boolean", BOOLEAN, NONE)
            DEFINE_HF(hf_unknown_uuid_je, "Unresolved UUID", "mcje.unknown_uuid", GUID, NONE)
            DEFINE_HF(hf_threshold, "Threshold", "mcje.threshold", UINT32, DEC)
            DEFINE_HF(hf_position_xzy, "Position", "mcje.position_xzy", INT64, DEC)

            DEFINE_HF_BITMASK(hf_x_26, "X", "mcje.x26", INT64, DEC, 0xFFFFFFC000000000)
            DEFINE_HF_BITMASK(hf_z_26, "Z", "mcje.z26", INT64, DEC, 0x0000003FFFFFF000)
            DEFINE_HF_BITMASK(hf_y_12, "Y", "mcje.y12", INT64, DEC, 0x0000000000000FFF)
    };
    proto_register_field_array(proto_mcje, hf_je, array_length(hf_je));
    proto_register_subtree_array(ett_je, array_length(ett_je));

    unknown_hf_map_je = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    wmem_map_insert(unknown_hf_map_je, g_strdup("int"), GINT_TO_POINTER(hf_unknown_int_je));
    wmem_map_insert(unknown_hf_map_je, g_strdup("uint"), GINT_TO_POINTER(hf_unknown_uint_je));
    wmem_map_insert(unknown_hf_map_je, g_strdup("int64"), GINT_TO_POINTER(hf_unknown_int64_je));
    wmem_map_insert(unknown_hf_map_je, g_strdup("uint64"), GINT_TO_POINTER(hf_unknown_uint64_je));
    wmem_map_insert(unknown_hf_map_je, g_strdup("float"), GINT_TO_POINTER(hf_unknown_float_je));
    wmem_map_insert(unknown_hf_map_je, g_strdup("double"), GINT_TO_POINTER(hf_unknown_double_je));
    wmem_map_insert(unknown_hf_map_je, g_strdup("bytes"), GINT_TO_POINTER(hf_unknown_bytes_je));
    wmem_map_insert(unknown_hf_map_je, g_strdup("string"), GINT_TO_POINTER(hf_unknown_string_je));
    wmem_map_insert(unknown_hf_map_je, g_strdup("boolean"), GINT_TO_POINTER(hf_unknown_boolean_je));
    wmem_map_insert(unknown_hf_map_je, g_strdup("uuid"), GINT_TO_POINTER(hf_unknown_uuid_je));

    name_hf_map_je = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    ADD_HF("threshold", hf_threshold);
    ADD_HF("[26]x[26]z[12]y", hf_position_xzy);

    bitmask_hf_map_je = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    static int * positionXZY[] = {&hf_x_26, &hf_z_26, &hf_y_12, NULL};
    wmem_map_insert(bitmask_hf_map_je, g_strdup("[26]x[26]z[12]y"), positionXZY);
    init_je();
}

guint get_packet_length_je(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data _U_) {
    guint len;
    guint packet_length = tvb_reported_length(tvb);
    if (packet_length == 0)
        return 0;

    const guint8 *dt = tvb_get_ptr(tvb, offset, packet_length - offset);
    int ret = read_var_int(dt, packet_length - offset, &len);
    if (is_invalid(ret)) {
        col_append_str(pinfo->cinfo, COL_INFO, "[Invalid] Failed to parse payload length");
        conversation_t *conv = find_or_create_conversation(pinfo);
        mcje_protocol_context *ctx = conversation_get_proto_data(conv, proto_mcje);
        ctx->state = INVALID;
        conversation_set_dissector(conv, ignore_je_handle);
        return 0;
    } else
        return len + ret;
}

void sub_dissect_je(guint length, tvbuff_t *tvb, packet_info *pinfo,
                    proto_tree *tree, mcje_protocol_context *ctx,
                    bool is_client, bool visited) {
    const guint8 *data = tvb_get_ptr(tvb, pinfo->desegment_offset, length);
    if (is_client) {
        switch (ctx->state) {
            case HANDSHAKE:
                if (!visited && is_invalid(handle_server_handshake_switch(data, length, ctx)))
                    return;
                if (tree)
                    handle_server_handshake(tree, tvb, pinfo, data, length, ctx);
                return;
            case PING:
                if (tree)
                    handle_server_slp(tree, tvb, pinfo, data, length, ctx);
                return;
            case LOGIN:
                if (tree)
                    handle_login(tree, tvb, pinfo, data, length, ctx, false);
                return;
            case PLAY:
                if (tree)
                    handle_play(tree, tvb, pinfo, data, length, ctx, false);
                return;
            default:
                col_add_str(pinfo->cinfo, COL_INFO, "[Invalid State]");
                return;
        }
    } else {
        switch (ctx->state) {
            case PING:
                if (tree)
                    handle_client_slp(tree, tvb, pinfo, data, length, ctx);
                return;
            case LOGIN:
                if (!visited && is_invalid(handle_client_login_switch(data, length, ctx)))
                    return;
                if (tree)
                    handle_login(tree, tvb, pinfo, data, length, ctx, true);
                return;
            case PLAY:
                if (tree)
                    handle_play(tree, tvb, pinfo, data, length, ctx, true);
                return;
            default:
                col_add_str(pinfo->cinfo, COL_INFO, "[Invalid State]");
                return;
        }
    }
}

int dissect_je_core(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, MCJE_SHORT_NAME);

    mcje_protocol_context *ctx;
    if (pinfo->fd->visited) {
        ctx = p_get_proto_data(wmem_file_scope(), pinfo, proto_mcje, pinfo->fd->subnum);
    } else {
        conversation_t *conv;
        conv = find_or_create_conversation(pinfo);
        ctx = conversation_get_proto_data(conv, proto_mcje);
        mcje_protocol_context *save;
        save = wmem_alloc(wmem_file_scope(), sizeof(mcje_protocol_context));
        *save = *ctx;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_mcje, pinfo->fd->subnum, save);
    }

    bool is_client = pinfo->destport == ctx->server_port;
    if (is_client)
        col_set_str(pinfo->cinfo, COL_INFO, "[C => S]");
    else
        col_set_str(pinfo->cinfo, COL_INFO, "[S => C]");

    guint read_pointer = 0;
    guint packet_length = tvb_reported_length(tvb);
    const guint8 *dt = tvb_get_ptr(tvb, 0, packet_length);
    guint packet_length_vari;
    guint packet_length_length = read_var_int(dt, packet_length, &packet_length_vari);
    read_pointer += packet_length_length;
    col_append_fstr(pinfo->cinfo, COL_INFO, " (%d bytes)", packet_length_vari);

    proto_tree *mcje_tree;
    if (tree) {
        proto_item *ti = proto_tree_add_item(tree, proto_mcje, tvb, 0, -1, FALSE);
        mcje_tree = proto_item_add_subtree(ti, ett_mcje);
        proto_tree_add_uint(mcje_tree, hf_packet_length_je, tvb, 0, packet_length_length, packet_length_vari);
        proto_item_append_text(ti, ", State: %s", STATE_NAME[ctx->state]);
    }

    tvbuff_t *new_tvb;
    if (ctx->compression_threshold < 0) {
        new_tvb = tvb_new_subset_remaining(tvb, packet_length_length);
        if (tree) {
            proto_item *packet_item = proto_tree_add_item(mcje_tree, proto_mcje, new_tvb, 0, -1, FALSE);
            proto_item_set_text(packet_item, "Minecraft JE Packet");
            proto_tree *sub_mcpc_tree = proto_item_add_subtree(packet_item, ett_je_proto);
            sub_dissect_je(packet_length_vari, new_tvb, pinfo, sub_mcpc_tree, ctx, is_client, pinfo->fd->visited);
        } else
            sub_dissect_je(packet_length_vari, new_tvb, pinfo, NULL, ctx, is_client, pinfo->fd->visited);
    } else {
        guint uncompressed_length;
        int var_len = read_var_int(dt + packet_length_length, packet_length - read_pointer, &uncompressed_length);
        if (is_invalid(var_len)) {
            proto_tree_add_string(mcje_tree, hf_invalid_data_je, tvb,
                                  read_pointer, var_len, "Invalid Compression VarInt");
            return 0;
        }

        read_pointer += var_len;

        if ((int32_t) uncompressed_length > 0) {
            if (tree) {
                proto_tree_add_uint(mcje_tree, hf_packet_data_length_je, tvb,
                                    read_pointer - var_len, var_len, uncompressed_length);
                if (uncompressed_length < ctx->compression_threshold)
                    proto_tree_add_string_format_value(mcje_tree, hf_invalid_data_je, tvb, read_pointer - var_len,
                                                       var_len, "",
                                                       "Badly compressed packet - size of %d is below server threshold of %d",
                                                       uncompressed_length, ctx->compression_threshold);
            }
            new_tvb = tvb_uncompress(tvb, read_pointer, packet_length - read_pointer);
            if (new_tvb == NULL)
                return 0;
            add_new_data_source(pinfo, new_tvb, "Uncompressed packet");
        } else
            new_tvb = tvb_new_subset_remaining(tvb, read_pointer);

        if (tree) {
            proto_item *packet_item = proto_tree_add_item(mcje_tree, proto_mcje, new_tvb, 0, -1, FALSE);
            proto_item_set_text(packet_item, "Minecraft JE Packet");
            proto_tree *sub_mcpc_tree = proto_item_add_subtree(packet_item, ett_je_proto);
            sub_dissect_je(tvb_captured_length(new_tvb), new_tvb, pinfo, sub_mcpc_tree, ctx, is_client,
                           pinfo->fd->visited);
        } else
            sub_dissect_je(tvb_captured_length(new_tvb), new_tvb, pinfo, NULL, ctx, is_client,
                           pinfo->fd->visited);
    }

    return tvb_captured_length(tvb);
}

int dissect_je_boot(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
    conversation_t *conv = find_or_create_conversation(pinfo);
    mcje_protocol_context *ctx = conversation_get_proto_data(conv, proto_mcje);
    if (!ctx) {
        ctx = wmem_alloc(wmem_file_scope(), sizeof(mcje_protocol_context));
        ctx->server_port = pinfo->destport;
        ctx->state = HANDSHAKE;
        ctx->compression_threshold = -1;
        conversation_add_proto_data(conv, proto_mcje, ctx);
        conversation_set_dissector(conv, mcje_handle);
    }
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 0,
                     get_packet_length_je, dissect_je_core, data);
    return tvb_captured_length(tvb);
}

int dissect_je_conv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 0,
                     get_packet_length_je, dissect_je_core, data);
    return tvb_captured_length(tvb);
}

int dissect_je_ignore(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
    pinfo->fd->subnum = 0;

    mcje_protocol_context *ctx;
    conversation_t *conv = find_or_create_conversation(pinfo);
    if (!(ctx = p_get_proto_data(wmem_file_scope(), pinfo, proto_mcje, pinfo->fd->subnum)))
        ctx = conversation_get_proto_data(conv, proto_mcje);

    if (ctx->state == INVALID) {
        col_add_str(pinfo->cinfo, COL_INFO, "[Invalid] Data may be corrupted or meet a capturing failure.");
    } else
        tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 0,
                         get_packet_length_je, dissect_je_core, data);

    return tvb_captured_length(tvb);
}