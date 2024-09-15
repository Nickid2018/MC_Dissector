//
// Created by Nickid2018 on 2023/7/13.
//

#include <epan/conversation.h>
#include <epan/proto_data.h>
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

void sub_dissect_je(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, mc_frame_data *frame_data,
                    mc_protocol_context *ctx, bool is_server,
                    bool visited) {
    if (is_server) {
        switch (frame_data->server_state) {
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
        switch (frame_data->client_state) {
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

void mark_invalid(packet_info *pinfo) {
    conversation_t *conv = find_or_create_conversation(pinfo);
    mc_protocol_context *ctx = conversation_get_proto_data(conv, proto_mcje);
    ctx->client_state = INVALID;
    ctx->server_state = INVALID;
}

void dissect_je_core(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, gint packet_len_len, gint len) {
    conversation_t *conv = find_or_create_conversation(pinfo);
    mc_protocol_context *ctx = conversation_get_proto_data(conv, proto_mcje);
    mc_frame_data *frame_data = p_get_proto_data(wmem_file_scope(), pinfo, proto_mcje, 0);

    proto_tree *mcje_tree;
    if (tree) {
        proto_item *ti = proto_tree_add_item(tree, proto_mcje, tvb, 0, -1, FALSE);
        mcje_tree = proto_item_add_subtree(ti, ett_mc);
        proto_tree_add_uint(mcje_tree, hf_packet_length_je, tvb, offset - packet_len_len, packet_len_len, len);
        proto_item_append_text(
                ti, ", Client State: %s, Server State: %s",
                STATE_NAME[frame_data->client_state], STATE_NAME[frame_data->server_state]
        );
    }

    tvbuff_t *new_tvb;
    if (frame_data->compression_threshold > 0) {
        gint uncompressed_length;
        int var_len = read_var_int(tvb, offset, &uncompressed_length);
        if (is_invalid(var_len)) {
            col_set_str(pinfo->cinfo, COL_INFO, "[Invalid] Invalid Compression VarInt");
            mark_invalid(pinfo);
            return;
        }

        offset += var_len;
        if (uncompressed_length > 0) {
            if (uncompressed_length < frame_data->compression_threshold) {
                col_set_str(pinfo->cinfo, COL_INFO, "[Invalid] Badly compressed packet");
                col_append_fstr(
                        pinfo->cinfo, COL_INFO, " - size of %d is below server threshold of %d",
                        uncompressed_length, frame_data->compression_threshold
                );
                mark_invalid(pinfo);
                return;
            }

            new_tvb = tvb_uncompress_zlib(tvb, offset, len - var_len);
            if (new_tvb == NULL)
                return;

            add_new_data_source(pinfo, new_tvb, "Uncompressed packet");
        } else {
            new_tvb = tvb_new_subset_length(tvb, offset, len - var_len);
        }
    } else {
        new_tvb = tvb_new_subset_length(tvb, offset, len);
    }

    bool is_server = addresses_equal(&pinfo->dst, &ctx->server_address) && pinfo->destport == ctx->server_port;
    if (tree) {
        proto_item *packet_item = proto_tree_add_item(mcje_tree, proto_mcje, new_tvb, 0, -1, FALSE);
        proto_item_set_text(packet_item, "Minecraft JE Packet");
        proto_tree *sub_mcje_tree = proto_item_add_subtree(packet_item, ett_proto);
        sub_dissect_je(new_tvb, pinfo, sub_mcje_tree, frame_data, ctx, is_server, pinfo->fd->visited);
    } else {
        sub_dissect_je(new_tvb, pinfo, NULL, frame_data, ctx, is_server, pinfo->fd->visited);
    }
}

int dissect_je_conv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
    conversation_t *conv = find_or_create_conversation(pinfo);
    mc_protocol_context *ctx = conversation_get_proto_data(conv, proto_mcje);
    if (!ctx) {
        ctx = wmem_alloc(wmem_file_scope(), sizeof(mc_protocol_context));
        ctx->client_state = is_compatible_protocol_data() ? HANDSHAKE : NOT_COMPATIBLE;
        ctx->server_state = is_compatible_protocol_data() ? HANDSHAKE : NOT_COMPATIBLE;
        ctx->compression_threshold = -1;
        ctx->server_port = pinfo->destport;
        ctx->server_cipher = NULL;
        ctx->client_cipher = NULL;
        ctx->server_last_segment_remaining = 0;
        ctx->client_last_segment_remaining = 0;
        ctx->server_last_remains = NULL;
        ctx->client_last_remains = NULL;
        copy_address(&ctx->server_address, &pinfo->dst);
        ctx->global_data = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
        conversation_add_proto_data(conv, proto_mcje, ctx);
    }

    mc_frame_data *frame_data = p_get_proto_data(wmem_file_scope(), pinfo, proto_mcje, 0);
    if (!frame_data) {
        frame_data = wmem_alloc(wmem_file_scope(), sizeof(mc_frame_data));
        frame_data->client_state = ctx->client_state;
        frame_data->server_state = ctx->server_state;
        frame_data->encrypted = ctx->encrypted;
        frame_data->decrypted_data_head = NULL;
        frame_data->decrypted_data_tail = NULL;
        frame_data->compression_threshold = ctx->compression_threshold;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_mcje, 0, frame_data);
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, MCJE_SHORT_NAME);

    if (frame_data->client_state == NOT_COMPATIBLE || frame_data->server_state == NOT_COMPATIBLE) {
        col_set_str(pinfo->cinfo, COL_INFO, "[Invalid] Protocol data is not compatible with the current plugin version");
        return (gint) tvb_captured_length(tvb);
    }
    if (frame_data->client_state == INVALID || frame_data->server_state == INVALID) {
        col_set_str(pinfo->cinfo, COL_INFO, "[Invalid] Data may be corrupted or meet a capturing failure");
        return (gint) tvb_captured_length(tvb);
    }
    if (frame_data->client_state == PROTOCOL_NOT_FOUND || frame_data->server_state == PROTOCOL_NOT_FOUND) {
        col_set_str(pinfo->cinfo, COL_INFO, "[Invalid] Protocol data is not found or invalid");
        return (gint) tvb_captured_length(tvb);
    }

    bool is_server = addresses_equal(&pinfo->dst, &ctx->server_address) && pinfo->destport == ctx->server_port;

    col_set_str(pinfo->cinfo, COL_INFO, is_server ? "[C => S] " : "[S => C] ");
    if (frame_data->encrypted)
        col_append_str(pinfo->cinfo, COL_INFO, "(Encrypted) ");

    tvbuff_t *use_tvb = tvb;
    if (frame_data->encrypted) {
        guint length = tvb_reported_length_remaining(tvb, 0);
        gint length_remaining = is_server ? ctx->server_last_segment_remaining : ctx->client_last_segment_remaining;
        gcry_cipher_hd_t *cipher = is_server ? &ctx->server_cipher : &ctx->client_cipher;
        guint8 **decrypt_data = pinfo->curr_proto_layer_num == 1 ? &frame_data->decrypted_data_head : &frame_data->decrypted_data_tail;

        if (*cipher == NULL) {
            gchar *secret_key_str = pref_secret_key;
            if (strlen(secret_key_str) != 32) {
                col_set_str(pinfo->cinfo, COL_INFO, "[Invalid] Decryption Error: Secret key is not set");
                mark_invalid(pinfo);
                return (gint) tvb_captured_length(tvb);
            }
            guint8 secret_key[16];
            for (int i = 0; i < 16; i++) {
                gchar hex[3] = {secret_key_str[i * 2], secret_key_str[i * 2 + 1], '\0'};
                secret_key[i] = (guint8) strtol(hex, NULL, 16);
            }
            gcry_cipher_open(cipher, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CFB8, 0);
            gcry_cipher_setkey(*cipher, secret_key, sizeof(secret_key));
            gcry_cipher_setiv(*cipher, secret_key, sizeof(secret_key));
        }

        if (!*decrypt_data) {
            guint8 *decrypt = wmem_alloc(pinfo->pool, length - length_remaining);
            gcry_error_t err = gcry_cipher_decrypt(
                    *cipher, decrypt,
                    length - length_remaining,
                    tvb_memdup(pinfo->pool, tvb, length_remaining, length - length_remaining),
                    length - length_remaining
            );
            if (err) {
                col_set_str(pinfo->cinfo, COL_INFO, "[Invalid] Decryption Error: Decryption failed with code ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%d", err);
                mark_invalid(pinfo);
                return (gint) tvb_captured_length(tvb);
            }

            guint8 *merged = wmem_alloc(wmem_file_scope(), length);
            memcpy(merged, is_server ? ctx->server_last_remains : ctx->client_last_remains, length_remaining);
            memcpy(merged + length_remaining, decrypt, length - length_remaining);

            *decrypt_data = merged;
        }

        use_tvb = tvb_new_real_data(*decrypt_data, length, (gint) length);
        add_new_data_source(pinfo, use_tvb, "Decrypted packet");
    }

    gint offset = 0;
    gint packet_count = 0;
    while (offset < tvb_reported_length(use_tvb)) {
        gint available = tvb_reported_length_remaining(use_tvb, offset);
        gint len = 0;
        gint packet_len_len = read_var_int_with_limit(use_tvb, offset, available, &len);

        if (packet_len_len == INVALID_DATA) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "[%d packet(s)]", packet_count);
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            if (!pinfo->fd->visited) {
                if (is_server) {
                    ctx->server_last_segment_remaining = available;
                    ctx->server_last_remains = tvb_memdup(wmem_file_scope(), use_tvb, offset, available);
                } else {
                    ctx->client_last_segment_remaining = available;
                    ctx->client_last_remains = tvb_memdup(wmem_file_scope(), use_tvb, offset, available);
                }
            }
            return offset + available;
        }

        if (len + packet_len_len > available) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "[%d packet(s)]", packet_count);
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = len + packet_len_len - available;
            if (!pinfo->fd->visited) {
                if (is_server) {
                    ctx->server_last_segment_remaining = available;
                    ctx->server_last_remains = tvb_memdup(wmem_file_scope(), use_tvb, offset, available);
                } else {
                    ctx->client_last_segment_remaining = available;
                    ctx->client_last_remains = tvb_memdup(wmem_file_scope(), use_tvb, offset, available);
                }
            }
            return offset + available;
        }

        offset += packet_len_len;
        dissect_je_core(use_tvb, pinfo, tree, offset, packet_len_len, len);
        offset += len;
        packet_count++;
    }

    if (!pinfo->fd->visited) {
        if (is_server) {
            ctx->server_last_segment_remaining = 0;
            ctx->server_last_remains = NULL;
        } else {
            ctx->client_last_segment_remaining = 0;
            ctx->client_last_remains = NULL;
        }
    }
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%d packet(s)]", packet_count);
    return (gint) tvb_captured_length(tvb);
}