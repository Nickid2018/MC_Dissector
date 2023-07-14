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
int hf_protocol_version_je = -1;
int hf_server_address_je = -1;
int hf_next_state_je = -1;
int hf_ping_time_je = -1;
int hf_server_status_je = -1;

dissector_handle_t mcje_boot_handle, mcje_handle, ignore_je_handle;

int ett_mcje = -1, ett_je_proto = -1;

void proto_reg_handoff_mcje() {
    mcje_boot_handle = create_dissector_handle(dissect_je_boot, proto_mcje);
    mcje_handle = create_dissector_handle(dissect_je_conv, proto_mcje);
    ignore_je_handle = create_dissector_handle(dissect_je_ignore, proto_mcje);
    dissector_add_uint("tcp.port", MCJE_PORT, mcje_boot_handle);
}

void proto_register_mcje() {
    proto_mcje = proto_register_protocol(MCJE_NAME, MCJE_SHORT_NAME, MCJE_FILTER);
    static gint *ett_je[] = {&ett_mcje, &ett_je_proto};
    static hf_register_info hf_je[] = {
            {&hf_invalid_data_je,
                    {
                            "Invalid Data",
                            "mcje.invalid_data",
                            FT_STRING, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {&hf_packet_length_je,
                    {
                            "Packet Length",
                            "mcje.packet_length",
                            FT_UINT32, BASE_DEC,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {&hf_packet_data_length_je,
                    {
                            "Packet Data Length",
                            "mcje.packet_data_length",
                            FT_UINT32, BASE_DEC,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {&hf_packet_id_je,
                    {
                            "Packet ID",
                            "mcje.packet_id",
                            FT_STRING, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {&hf_protocol_version_je,
                    {
                            "Protocol Version",
                            "mcje.protocol_version",
                            FT_STRING, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {&hf_server_address_je,
                    {
                            "Server Address",
                            "mcje.server_address",
                            FT_STRING, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {&hf_next_state_je,
                    {
                            "Next State",
                            "mcje.next_state",
                            FT_STRING, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {&hf_ping_time_je,
                    {
                            "Ping Time",
                            "mcje.ping_time",
                            FT_UINT64, BASE_DEC,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            {&hf_server_status_je,
                    {
                            "Server Status",
                            "mcje.server_status",
                            FT_STRING, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
    };
    proto_register_field_array(proto_mcje, hf_je, array_length(hf_je));
    proto_register_subtree_array(ett_je, array_length(ett_je));
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
        if (is_invalid(var_len))
            return 0;

        proto_tree_add_uint(mcje_tree, hf_packet_data_length_je, tvb, read_pointer, var_len, uncompressed_length);
        read_pointer += var_len;

        if ((int32_t) uncompressed_length > 0) {
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
    init_je();
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