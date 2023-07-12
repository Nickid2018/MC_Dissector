//
// Created by Nickid2018 on 2023/7/12.
//
#include <config.h>

#define WS_BUILD_DLL

#include "mc_dissector.h"
#include "protocol_data.h"
#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/dissectors/packet-tcp.h>

WS_DLL_PUBLIC_DEF const gchar plugin_version[] = "0.0.0";
WS_DLL_PUBLIC_DEF const int plugin_want_major = VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register();

int proto_mcje = -1;
int proto_mcbe = -1;

int hf_packet_length_je = -1;
int hf_packet_id_je = -1;

int ett_mcje = -1;

static dissector_handle_t mcje_boot_handle, mcbe_boot_handle, mcje_handle, mcbe_handle, ignore_je_handle, ignore_be_handle;

// ------------------- Protocol Registration -------------------

void proto_register_mcje() {
    proto_mcje = proto_register_protocol(MCJE_NAME, MCJE_SHORT_NAME, MCJE_FILTER);
    static gint *ett_je[] = {&ett_mcje};
    static hf_register_info hf_je[] = {
            {&hf_packet_length_je,
             {"Packet Length",
              "mcje.packet_length",
              FT_UINT32, BASE_DEC,
              NULL, 0x0,
              NULL, HFILL
             }
            },
            {&hf_packet_id_je,
             {"Packet ID",
              "mcje.packet_id",
              FT_UINT32, BASE_HEX,
              NULL, 0x0,
              NULL, HFILL
             }
            }
    };
    proto_register_field_array(proto_mcje, hf_je, array_length(hf_je));
    proto_register_subtree_array(ett_je, array_length(ett_je));
}

void proto_register_mcbe() {
    proto_mcbe = proto_register_protocol(MCBE_NAME, MCBE_SHORT_NAME, MCBE_FILTER);
}

guint get_packet_length_je(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data _U_) {
    int ret;
    uint32_t len;
    guint packet_length;

    packet_length = tvb_reported_length(tvb);
    if (packet_length == 0)
        return 0;

    const guint8 *dt = tvb_get_ptr(tvb, offset, packet_length - offset);
    ret = read_var_int(dt, packet_length - offset, &len);
    if (is_invalid(ret)) {
        col_add_str(pinfo->cinfo, COL_INFO, "[INVALID] Failed to parse payload length");
        conversation_t *conv = find_or_create_conversation(pinfo);
        mc_protocol_context *ctx = conversation_get_proto_data(conv, proto_mcje);
        ctx->state = INVALID;
        conversation_set_dissector(conv, ignore_je_handle);
        return 0;
    } else
        return len + ret;
}

// ------------------- JE Dissector Registration -------------------

int dissect_mcje_core(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, MCJE_SHORT_NAME);

    conversation_t *conv = find_or_create_conversation(pinfo);
    mc_protocol_context *ctx = conversation_get_proto_data(conv, proto_mcje);
    if (!ctx) {
        ctx = wmem_alloc(wmem_file_scope(), sizeof(mc_protocol_context));
        ctx->server_port = pinfo->destport;
        ctx->state = HANDSHAKE;
        ctx->compression_threshold = -1;
        conversation_add_proto_data(conv, proto_mcje, ctx);
        conversation_set_dissector(conv, mcje_handle);
    }

    if (pinfo->destport == ctx->server_port)
        col_set_str(pinfo->cinfo, COL_INFO, "[C => S]");
    else
        col_set_str(pinfo->cinfo, COL_INFO, "[S => C]");

    guint read_pointer = 0;
    guint packet_length = tvb_reported_length(tvb);
    guint8 *dt = tvb_get_ptr(tvb, 0, packet_length);
    guint packet_length_vari;
    read_pointer += read_var_int(dt, packet_length, &packet_length_vari);
    col_append_fstr(pinfo->cinfo, COL_INFO, "(%d bytes)", packet_length_vari);

    if (tree) {
        proto_item *ti;

        ti = proto_tree_add_item(tree, proto_mcje, tvb, 0, -1, FALSE);
        proto_tree *mcje_tree = proto_item_add_subtree(ti, ett_mcje);
        proto_tree_add_uint(mcje_tree, hf_packet_length_je, tvb, 0, read_pointer, packet_length_vari);
        proto_item_append_text(ti, ", state: %d", ctx->state);
    }
}

int dissect_mcje_boot(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
    conversation_t *conv = find_or_create_conversation(pinfo);
    mc_protocol_context *ctx = conversation_get_proto_data(conv, proto_mcje);
    if (!ctx) {
        ctx = wmem_alloc(wmem_file_scope(), sizeof(mc_protocol_context));
        ctx->server_port = pinfo->destport;
        ctx->state = HANDSHAKE;
        ctx->compression_threshold = -1;
        conversation_add_proto_data(conv, proto_mcje, ctx);
        conversation_set_dissector(conv, mcje_handle);
    }
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 0,
                     get_packet_length_je, dissect_mcje_core, data);
    return tvb_captured_length(tvb);
}

int dissect_je_conv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 0,
                     get_packet_length_je, dissect_mcje_core, data);
    return tvb_captured_length(tvb);
}

int dissect_ignore_je(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
    pinfo->fd->subnum = 0;
    conversation_t *conv = find_or_create_conversation(pinfo);
    mc_protocol_context *ctx = conversation_get_proto_data(conv, proto_mcje);

    if (ctx->state == INVALID)
        col_add_str(pinfo->cinfo, COL_INFO, "[INVALID] before");
    else
        tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 0,
                         get_packet_length_je, dissect_mcje_core, data);

    return tvb_captured_length(tvb);
}

// ------------------- BE Dissector Registration -------------------

int dissect_mcbe_boot(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
    return tvb_captured_length(tvb);
}

int dissect_be_conv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
    return tvb_captured_length(tvb);
}

int dissect_ignore_be(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
    return tvb_captured_length(tvb);
}

// ------------------- Handoff Registration -------------------

void proto_reg_handoff_mcje() {
    mcje_boot_handle = create_dissector_handle(dissect_mcje_boot, proto_mcje);
    mcje_handle = create_dissector_handle(dissect_je_conv, proto_mcje);
    ignore_je_handle = create_dissector_handle(dissect_ignore_je, proto_mcje);
    dissector_add_uint("tcp.port", MCJE_PORT, mcje_boot_handle);
}

void proto_reg_handoff_mcbe() {
    mcbe_boot_handle = create_dissector_handle(dissect_mcbe_boot, proto_mcbe);
    mcbe_handle = create_dissector_handle(dissect_be_conv, proto_mcbe);
    ignore_be_handle = create_dissector_handle(dissect_ignore_be, proto_mcbe);
    dissector_add_uint("udp.port", MCBE_PORT, mcbe_boot_handle);
}

// ------------------- Plugin Registration -------------------

void plugin_register() {
    if (proto_mcje == -1) {
        static proto_plugin plugMCJE;
        plugMCJE.register_protoinfo = proto_register_mcje;
        plugMCJE.register_handoff = proto_reg_handoff_mcje;
        proto_register_plugin(&plugMCJE);
    }
    if (proto_mcbe == -1) {
        static proto_plugin plugMCBE;
        plugMCBE.register_protoinfo = proto_register_mcbe;
        plugMCBE.register_handoff = proto_reg_handoff_mcbe;
        proto_register_plugin(&plugMCBE);
    }
}