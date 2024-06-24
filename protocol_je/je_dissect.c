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

extern int hf_packet_length_je;
extern int hf_packet_data_length_je;

dissector_handle_t mcje_handle;

void proto_reg_handoff_mcje() {
    mcje_handle = create_dissector_handle(dissect_je_conv, proto_mcje);
    dissector_add_uint_range_with_preference("tcp.port", MCJE_PORT, mcje_handle);
}

void sub_dissect_je(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, mcje_protocol_context *ctx, bool is_server, bool visited) {
    if (is_server) {
        switch (ctx->server_state) {
            case HANDSHAKE:
                if (!visited && is_invalid(handle_server_handshake_switch(tvb, ctx)))
                    return;
                if (tree)
                    handle_server_handshake(tree, pinfo, tvb);
                return;
            case PING:
                if (tree)
                    handle_server_slp(tree, tvb);
                return;
            case LOGIN:
            case TRANSFER:
                if (!visited && is_invalid(handle_server_login_switch(tvb, ctx)))
                    return;
                if (tree)
                    handle_login(tree, pinfo, tvb, ctx, false);
                return;
            case PLAY:
                if (!visited && is_invalid(handle_server_play_switch(tvb, ctx)))
                    return;
                if (tree)
                    handle_play(tree, pinfo, tvb, ctx, false);
                return;
            case CONFIGURATION:
                if (!visited && is_invalid(handle_server_configuration_switch(tvb, ctx)))
                    return;
                if (tree)
                    handle_configuration(tree, pinfo, tvb, ctx, false);
                return;
            default:
                col_add_str(pinfo->cinfo, COL_INFO, "[Invalid State]");
                return;
        }
    } else {
        switch (ctx->client_state) {
            case PING:
                if (tree)
                    handle_client_slp(tree, pinfo, tvb);
                return;
            case LOGIN:
            case TRANSFER:
                if (!visited && is_invalid(handle_client_login_switch(tvb, ctx)))
                    return;
                if (tree)
                    handle_login(tree, pinfo, tvb, ctx, true);
                return;
            case PLAY:
                if (!visited && is_invalid(handle_client_play_switch(tvb, ctx)))
                    return;
                if (tree)
                    handle_play(tree, pinfo, tvb, ctx, true);
                return;
            case CONFIGURATION:
                if (!visited && is_invalid(handle_client_configuration_switch(tvb, ctx)))
                    return;
                if (tree)
                    handle_configuration(tree, pinfo, tvb, ctx, true);
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
        ((extra_data *) ctx->extra)->visited = true;
    } else {
        conversation_t *conv;
        conv = find_or_create_conversation(pinfo);
        ctx = conversation_get_proto_data(conv, proto_mcje);
        mcje_protocol_context *save;
        save = wmem_alloc(wmem_file_scope(), sizeof(mcje_protocol_context));
        *save = *ctx;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_mcje, pinfo->fd->subnum, save);
        ((extra_data *) ctx->extra)->visited = false;
    }
    pinfo->fd->subnum++;
    return ctx;
}

void mark_invalid(packet_info *pinfo) {
    conversation_t *conv = find_or_create_conversation(pinfo);
    mcje_protocol_context *ctx = conversation_get_proto_data(conv, proto_mcje);
    ctx->client_state = INVALID;
    ctx->server_state = INVALID;
}

int dissect_je_core(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    mcje_protocol_context *ctx = get_context(pinfo);
    gint captured_length = (gint) tvb_captured_length(tvb);

    if (ctx->client_state == INVALID || ctx->server_state == INVALID) {
        col_set_str(pinfo->cinfo, COL_INFO, "[Invalid] Data may be corrupted or meet a capturing failure.");
        return captured_length;
    }

    bool is_server = addresses_equal(&pinfo->dst, &ctx->server_address) && pinfo->destport == ctx->server_port;
    gint read_pointer = 0;
    gint packet_length = (gint) tvb_reported_length(tvb);
    gint packet_length_vari;
    gint packet_length_length = read_var_int(tvb, 0, &packet_length_vari);
    read_pointer += packet_length_length;
    col_append_fstr(pinfo->cinfo, COL_INFO, " (%d bytes)", packet_length_vari);

    proto_tree *mcje_tree;
    if (tree) {
        proto_item *ti = proto_tree_add_item(tree, proto_mcje, tvb, 0, -1, FALSE);
        mcje_tree = proto_item_add_subtree(ti, ett_mcje);
        proto_tree_add_uint(mcje_tree, hf_packet_length_je, tvb, 0, packet_length_length, packet_length_vari);
        proto_item_append_text(
                ti, ", Client State: %s, Server State: %s", STATE_NAME[ctx->client_state],
                STATE_NAME[ctx->server_state]
        );
    }

    tvbuff_t *new_tvb;
    if (ctx->compression_threshold < 0) {
        new_tvb = tvb_new_subset_length(tvb, read_pointer, packet_length_vari);
        if (tree) {
            proto_item *packet_item = proto_tree_add_item(mcje_tree, proto_mcje, new_tvb, 0, -1, FALSE);
            proto_item_set_text(packet_item, "Minecraft JE Packet");
            proto_tree *sub_mcpc_tree = proto_item_add_subtree(packet_item, ett_je_proto);
            sub_dissect_je(new_tvb, pinfo, sub_mcpc_tree, ctx, is_server, pinfo->fd->visited);
        } else
            sub_dissect_je(new_tvb, pinfo, NULL, ctx, is_server, pinfo->fd->visited);
    } else {
        gint uncompressed_length;
        int var_len = read_var_int(tvb, read_pointer, &uncompressed_length);
        if (is_invalid(var_len)) {
            col_set_str(pinfo->cinfo, COL_INFO, "[Invalid] Invalid Compression VarInt");
            mark_invalid(pinfo);
            return captured_length;
        }

        read_pointer += var_len;

        if ((int32_t) uncompressed_length > 0) {
            if (tree) {
                proto_tree_add_uint(
                        mcje_tree, hf_packet_data_length_je, tvb,
                        read_pointer - var_len, var_len, uncompressed_length
                );
                if (uncompressed_length < ctx->compression_threshold) {
                    col_set_str(pinfo->cinfo, COL_INFO, "[Invalid] Badly compressed packet");
                    col_append_fstr(
                            pinfo->cinfo, COL_INFO, " - size of %d is below server threshold of %d",
                            uncompressed_length, ctx->compression_threshold
                    );
                    mark_invalid(pinfo);
                    return captured_length;
                }
            }
            new_tvb = tvb_uncompress(tvb, read_pointer, packet_length - read_pointer);
            if (new_tvb == NULL)
                return captured_length;
            add_new_data_source(pinfo, new_tvb, "Uncompressed packet");
        } else {
            if (tree)
                proto_tree_add_uint(
                        mcje_tree, hf_packet_data_length_je, tvb,
                        read_pointer - 1, 1, packet_length_vari - 1
                );
            new_tvb = tvb_new_subset_remaining(tvb, read_pointer);
        }

        if (tree) {
            proto_item *packet_item = proto_tree_add_item(mcje_tree, proto_mcje, new_tvb, 0, -1, FALSE);
            proto_item_set_text(packet_item, "Minecraft JE Packet");
            proto_tree *sub_mcpc_tree = proto_item_add_subtree(packet_item, ett_je_proto);
            sub_dissect_je(new_tvb, pinfo, sub_mcpc_tree, ctx, is_server, pinfo->fd->visited);
        } else
            sub_dissect_je(new_tvb, pinfo, NULL, ctx, is_server, pinfo->fd->visited);
    }

    return captured_length;
}

guint get_packet_length(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data) {
    gint len;
    gint packet_length = (gint) tvb_reported_length(tvb);
    if (packet_length == 0)
        return 0;

    reassemble_offset *reassemble_data = data;
    gint remaining = packet_length - offset;
    int ret = read_var_int_with_limit(tvb, offset, remaining > 3 ? 3 : remaining, &len);
    if (is_invalid(ret)) {
        if (remaining < 3) {
            reassemble_data->record_latest = 0;
            return 0;
        }
        col_set_str(pinfo->cinfo, COL_INFO, "[Invalid] Failed to parse payload length");
        mark_invalid(pinfo);
        return 0;
    } else {
        reassemble_data->record_latest = len + ret;
        reassemble_data->record_total += len + ret;
        return len + ret;
    }
}

// 0xFFFFFFFF: Decrypted Data for first
// 0xFFFFFFFE: Decrypted Data for second (if contains)
// 0xFFFFFFFD: Sub Number for second
int dissect_je_conv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
    pinfo->fd->subnum = 0;
    if (pinfo->curr_layer_num == 7)
        pinfo->fd->subnum = GPOINTER_TO_UINT(p_get_proto_data(wmem_file_scope(), pinfo, proto_mcje, 0xFFFFFFFD));

    conversation_t *conv = find_or_create_conversation(pinfo);
    mcje_protocol_context *ctx = conversation_get_proto_data(conv, proto_mcje);
    if (!ctx) {
        ctx = wmem_alloc(wmem_file_scope(), sizeof(mcje_protocol_context));
        ctx->client_state = HANDSHAKE;
        ctx->server_state = HANDSHAKE;
        ctx->compression_threshold = -1;
        ctx->server_port = pinfo->destport;
        copy_address(&ctx->server_address, &pinfo->dst);
        ctx->extra = wmem_alloc(wmem_file_scope(), sizeof(extra_data));
        ((extra_data *) ctx->extra)->data = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
        ctx->decryption_context = NULL;
        conversation_add_proto_data(conv, proto_mcje, ctx);
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, MCJE_SHORT_NAME);

    gint length = tvb_reported_length_remaining(tvb, 0);
    bool is_visited = pinfo->fd->visited;
    bool is_server = addresses_equal(&pinfo->dst, &ctx->server_address) && pinfo->destport == ctx->server_port;
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_str(pinfo->cinfo, COL_INFO, is_server ? "[C => S] " : "[S => C] ");

    mcje_decryption_context *decryption_ctx = ctx->decryption_context;
    bool is_encrypted = decryption_ctx != NULL;
    if (is_encrypted) {
        guint8 *decrypt;
        if (!is_visited) {
            gcry_cipher_hd_t cipher = is_server ? decryption_ctx->server_cipher : decryption_ctx->client_cipher;
            gint last_decrypt_available = is_server ? decryption_ctx->server_last_decrypt_available
                                                    : decryption_ctx->client_last_decrypt_available;
            gint to_decrypt = length - last_decrypt_available;
            guint8 **write_to = is_server ? &decryption_ctx->server_decrypt : &decryption_ctx->client_decrypt;
            gint *old_length = is_server ? &decryption_ctx->server_decrypt_length
                                         : &decryption_ctx->client_decrypt_length;
            guint8 *old = *write_to;
            *write_to = decrypt = wmem_alloc(wmem_file_scope(), length);
            memcpy(*write_to, old + *old_length - last_decrypt_available, last_decrypt_available);
            gcry_error_t err = gcry_cipher_decrypt(
                    cipher, *write_to + last_decrypt_available, to_decrypt,
                    tvb_memdup(pinfo->pool, tvb, last_decrypt_available, to_decrypt),
                    to_decrypt
            );
            if (err != 0) {
                col_append_str(pinfo->cinfo, COL_INFO, "[Invalid] Decryption Error: Decryption failed");
                mark_invalid(pinfo);
                return (gint) tvb_captured_length(tvb);
            }
            p_add_proto_data(
                    wmem_file_scope(), pinfo, proto_mcje,
                    pinfo->curr_layer_num == 6 ? 0xFFFFFFFF : 0xFFFFFFFE, *write_to
            );
            *old_length = length;
        } else {
            if (pinfo->curr_layer_num == 6)
                decrypt = p_get_proto_data(wmem_file_scope(), pinfo, proto_mcje, 0xFFFFFFFF);
            else
                decrypt = p_get_proto_data(wmem_file_scope(), pinfo, proto_mcje, 0xFFFFFFFE);
        }
        if (decrypt != NULL) {
            col_append_str(pinfo->cinfo, COL_INFO, "(Encrypted) ");
            tvb = tvb_new_child_real_data(tvb, decrypt, length, length);
            add_new_data_source(pinfo, tvb, "Decrypted Data");
        }
    }

    reassemble_offset *reassemble_data = wmem_new(pinfo->pool, reassemble_offset);
    reassemble_data->record_total = 0;
    reassemble_data->record_latest = 0;
    tcp_dissect_pdus(
            tvb, pinfo, tree, TRUE, 0, get_packet_length,
            dissect_je_core, reassemble_data
    );
    if (!is_visited && pinfo->curr_layer_num == 6)
        p_add_proto_data(wmem_file_scope(), pinfo, proto_mcje, 0xFFFFFFFD, GUINT_TO_POINTER(pinfo->fd->subnum));
    if (!is_visited && is_encrypted) {
        gint *last_decrypt_available = is_server ? &decryption_ctx->server_last_decrypt_available
                                                 : &decryption_ctx->client_last_decrypt_available;
        gint *required_length = is_server ? &decryption_ctx->server_required_length
                                          : &decryption_ctx->client_required_length;
        gint read = reassemble_data->record_total;
        if (read > length) {
            read -= reassemble_data->record_latest;
            *required_length = reassemble_data->record_latest;
        } else
            *required_length = 0;
        *last_decrypt_available = length - read;
    }
    wmem_free(pinfo->pool, reassemble_data);

    return (gint) tvb_captured_length(tvb);
}