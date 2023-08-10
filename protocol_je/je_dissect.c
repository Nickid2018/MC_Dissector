//
// Created by Nickid2018 on 2023/7/13.
//

#include <epan/conversation.h>
#include <epan/exceptions.h>
#include <epan/proto_data.h>
#include <epan/dissectors/packet-tcp.h>
#include "mc_dissector.h"
#include "je_dissect.h"
#include "je_protocol.h"
#include "je_protocol_constants.h"

dissector_handle_t mcje_handle;
dissector_handle_t ignore_je_handle;

void proto_reg_handoff_mcje() {
    mcje_handle = create_dissector_handle(dissect_je_conv, proto_mcje);
    ignore_je_handle = create_dissector_handle(dissect_je_ignore, proto_mcje);
    dissector_add_uint_with_preference("tcp.port", MCJE_PORT, mcje_handle);
}

void sub_dissect_je(guint length, tvbuff_t *tvb, packet_info *pinfo,
                    proto_tree *tree, mcje_protocol_context *ctx,
                    bool is_server, bool visited) {
    const guint8 *data = tvb_get_ptr(tvb, pinfo->desegment_offset, length);
    if (is_server) {
        switch (ctx->server_state) {
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
                if (!visited && is_invalid(handle_server_login_switch(data, length, ctx, pinfo)))
                    return;
                if (tree)
                    handle_login(tree, tvb, pinfo, data, length, ctx, false);
                return;
            case PLAY:
                if (!visited && is_invalid(handle_server_play_switch(data, length, ctx)))
                    return;
                if (tree)
                    handle_play(tree, tvb, pinfo, data, length, ctx, false);
                return;
            case CONFIGURATION:
                if (!visited && is_invalid(handle_server_configuration_switch(data, length, ctx)))
                    return;
                if (tree)
                    handle_configuration(tree, tvb, pinfo, data, length, ctx, false);
                return;
            default:
                col_add_str(pinfo->cinfo, COL_INFO, "[Invalid State]");
                return;
        }
    } else {
        switch (ctx->client_state) {
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
                if (!visited && is_invalid(handle_client_play_switch(data, length, ctx)))
                    return;
                if (tree)
                    handle_play(tree, tvb, pinfo, data, length, ctx, true);
                return;
            case CONFIGURATION:
                if (!visited && is_invalid(handle_client_configuration_switch(data, length, ctx)))
                    return;
                if (tree)
                    handle_configuration(tree, tvb, pinfo, data, length, ctx, true);
                return;
            default:
                col_add_str(pinfo->cinfo, COL_INFO, "[Invalid State]");
                return;
        }
    }
}

mcje_protocol_context *get_context(packet_info *pinfo) {
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
    pinfo->fd->subnum++;
    return ctx;
}

int dissect_je_core(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, MCJE_SHORT_NAME);
    guint *read_counter = data;

    mcje_protocol_context *ctx = get_context(pinfo);
    if (ctx == NULL)
        return tvb_captured_length(tvb);

    bool is_server = addresses_equal(&pinfo->dst, &ctx->server_address) && pinfo->destport == ctx->server_port;
    guint read_pointer = 0;
    guint packet_length = tvb_reported_length(tvb);
    const guint8 *dt = tvb_get_ptr(tvb, 0, packet_length);
    guint packet_length_vari;
    guint packet_length_length = read_var_int(dt, packet_length, &packet_length_vari);
    read_pointer += packet_length_length;
    col_append_fstr(pinfo->cinfo, COL_INFO, " (%d bytes)", packet_length_vari);
    *read_counter += packet_length_vari + packet_length_length;

    proto_tree *mcje_tree;
    if (tree) {
        proto_item *ti = proto_tree_add_item(tree, proto_mcje, tvb, 0, -1, FALSE);
        mcje_tree = proto_item_add_subtree(ti, ett_mcje);
        proto_tree_add_uint(mcje_tree, hf_packet_length_je, tvb, 0, packet_length_length, packet_length_vari);
        proto_item_append_text(ti, ", Client State: %s, Server State: %s", STATE_NAME[ctx->client_state],
                               STATE_NAME[ctx->server_state]);
    }

    tvbuff_t *new_tvb;
    if (ctx->compression_threshold < 0) {
        new_tvb = tvb_new_subset_remaining(tvb, read_pointer);
        if (tree) {
            proto_item *packet_item = proto_tree_add_item(mcje_tree, proto_mcje, new_tvb, 0, -1, FALSE);
            proto_item_set_text(packet_item, "Minecraft JE Packet");
            proto_tree *sub_mcpc_tree = proto_item_add_subtree(packet_item, ett_je_proto);
            sub_dissect_je(packet_length_vari, new_tvb, pinfo, sub_mcpc_tree, ctx, is_server, pinfo->fd->visited);
        } else
            sub_dissect_je(packet_length_vari, new_tvb, pinfo, NULL, ctx, is_server, pinfo->fd->visited);
    } else {
        guint uncompressed_length;
        int var_len = read_var_int(dt + read_pointer, packet_length - read_pointer, &uncompressed_length);
        if (is_invalid(var_len)) {
            proto_tree_add_string(mcje_tree, hf_invalid_data_je, tvb,
                                  read_pointer, var_len, "Invalid Compression VarInt");
            ctx->client_state = INVALID;
            ctx->server_state = INVALID;
            return tvb_captured_length(tvb);
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
                return tvb_captured_length(tvb);
            add_new_data_source(pinfo, new_tvb, "Uncompressed packet");
        } else {
            if (tree)
                proto_tree_add_uint(mcje_tree, hf_packet_data_length_je, tvb,
                                    read_pointer - 1, 1, packet_length_vari - 1);
            new_tvb = tvb_new_subset_remaining(tvb, read_pointer);
        }

        if (tree) {
            proto_item *packet_item = proto_tree_add_item(mcje_tree, proto_mcje, new_tvb, 0, -1, FALSE);
            proto_item_set_text(packet_item, "Minecraft JE Packet");
            proto_tree *sub_mcpc_tree = proto_item_add_subtree(packet_item, ett_je_proto);
            sub_dissect_je(tvb_captured_length(new_tvb), new_tvb, pinfo, sub_mcpc_tree, ctx, is_server,
                           pinfo->fd->visited);
        } else
            sub_dissect_je(tvb_captured_length(new_tvb), new_tvb, pinfo, NULL, ctx, is_server,
                           pinfo->fd->visited);
    }

    return tvb_captured_length(tvb);
}

guint get_packet_length(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data _U_) {
    guint len;
    guint packet_length = tvb_reported_length(tvb);
    if (packet_length == 0)
        return 0;

    const guint8 *dt = tvb_get_ptr(tvb, offset, packet_length - offset);
    int ret = read_var_int(dt, packet_length - offset, &len);
    if (is_invalid(ret)) {
        col_set_str(pinfo->cinfo, COL_INFO, "[Invalid] Failed to parse payload length");
        conversation_t *conv = find_or_create_conversation(pinfo);
        mcje_protocol_context *ctx = conversation_get_proto_data(conv, proto_mcje);
        ctx->client_state = INVALID;
        ctx->server_state = INVALID;
        conversation_set_dissector(conv, ignore_je_handle);
        return 0;
    } else
        return len + ret;
}

int dissect_je_conv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
    pinfo->fd->subnum = 0;

    conversation_t *conv = find_or_create_conversation(pinfo);
    mcje_protocol_context *ctx = conversation_get_proto_data(conv, proto_mcje);
    if (!ctx) {
        ctx = wmem_alloc(wmem_file_scope(), sizeof(mcje_protocol_context));
        ctx->client_state = HANDSHAKE;
        ctx->server_state = HANDSHAKE;
        ctx->compression_threshold = -1;
        ctx->server_port = pinfo->destport;
        copy_address(&ctx->server_address, &pinfo->dst);
        conversation_add_proto_data(conv, proto_mcje, ctx);
    }

    guint length = tvb_captured_length_remaining(tvb, 0);
    bool is_visited = pinfo->fd->visited;
    bool is_server = addresses_equal(&pinfo->dst, &ctx->server_address) && pinfo->destport == ctx->server_port;
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_str(pinfo->cinfo, COL_INFO, is_server ? "[C => S]" : "[S => C]");

    mcje_decryption_context *decryption_ctx = p_get_proto_data(wmem_file_scope(), pinfo, proto_mcje, 0xFFFFFFFF);
    if (decryption_ctx != NULL) {
        if (!is_visited) {
            gcry_cipher_hd_t cipher = is_server ? decryption_ctx->server_cipher : decryption_ctx->client_cipher;
            guint last_decrypt_available = is_server ? decryption_ctx->server_last_decrypt_available
                                                     : decryption_ctx->client_last_decrypt_available;
            guint to_decrypt = length - last_decrypt_available;
            guint8 *write_to = is_server ? decryption_ctx->server_decrypt : decryption_ctx->client_decrypt;
            guint *old_length = is_server ? &decryption_ctx->server_decrypt_length
                                          : &decryption_ctx->client_decrypt_length;
            if (to_decrypt > 0) {
                memmove(write_to, write_to + *old_length - last_decrypt_available, last_decrypt_available);
                wmem_realloc(wmem_file_scope(), write_to, length);
                gcry_error_t err = gcry_cipher_decrypt(cipher, write_to + last_decrypt_available, to_decrypt,
                                                       tvb_get_ptr(tvb, last_decrypt_available, to_decrypt),
                                                       to_decrypt);
                if (err != 0) {
                    col_append_str(pinfo->cinfo, COL_INFO, "<Decryption Error>");
                    ctx->server_state = INVALID;
                    ctx->client_state = INVALID;
                    return tvb_captured_length(tvb);
                }
                *old_length = length;
            }
        }
        guint8 *decrypt = is_server ? decryption_ctx->server_decrypt : decryption_ctx->client_decrypt;
        guint decrypt_length = is_server ? decryption_ctx->server_decrypt_length
                                         : decryption_ctx->client_decrypt_length;
        if (decrypt != NULL) {
            col_append_str(pinfo->cinfo, COL_INFO, "(Encrypted) ");
            tvb = tvb_new_child_real_data(tvb, decrypt, decrypt_length, decrypt_length);
            add_new_data_source(pinfo, tvb, "Decrypted Data");
        }
    }

    guint read_len = 0;
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 1, get_packet_length,
                     dissect_je_core, &read_len);
    if (decryption_ctx != NULL) {
        guint *last_decrypt_available = is_server ? &decryption_ctx->server_last_decrypt_available
                                                  : &decryption_ctx->client_last_decrypt_available;
        *last_decrypt_available = length - read_len;
    }

    return tvb_captured_length(tvb);
}

int dissect_je_ignore(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
    pinfo->fd->subnum = 0;

    mcje_protocol_context *ctx;
    conversation_t *conv = find_or_create_conversation(pinfo);
    if (!(ctx = p_get_proto_data(wmem_file_scope(), pinfo, proto_mcje, pinfo->fd->subnum)))
        ctx = conversation_get_proto_data(conv, proto_mcje);

    if (ctx->client_state == INVALID || ctx->server_state == INVALID) {
        col_add_str(pinfo->cinfo, COL_PROTOCOL, MCJE_SHORT_NAME);
        col_add_str(pinfo->cinfo, COL_INFO, "[Invalid] Data may be corrupted or meet a capturing failure.");
    }

    return tvb_captured_length(tvb);
}