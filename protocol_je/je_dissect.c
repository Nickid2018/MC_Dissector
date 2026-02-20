//
// Created by Nickid2018 on 2023/7/13.
//

#include <epan/conversation.h>
#include <epan/proto_data.h>
#include <epan/exceptions.h>
#include "mc_dissector.h"
#include "je_dissect.h"
#include "je_protocol.h"
#include "protocol/storage/storage.h"

extern int hf_packet_length_je;
extern int hf_packet_data_length_je;
extern int hf_invalid_data_je;

dissector_handle_t mcje_handle;

void proto_reg_handoff_mcje() {
    mcje_handle = create_dissector_handle(dissect_je_conv, proto_mcje);
    dissector_add_uint_range_with_preference("tcp.port", MCJE_PORT, mcje_handle);
    dissector_add_for_decode_as(MCJE_NAME, mcje_handle);
}

void sub_dissect_je(
    tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, mc_frame_data *frame_data,
    mc_protocol_context *ctx, bool is_server, bool visited
) {
    je_state state = is_server ? frame_data->server_state : frame_data->client_state;
    switch (state) {
        case HANDSHAKE:
        case STATUS:
            if (!visited && is_invalid(try_switch_initial(tvb, pinfo, ctx, !is_server)))
                return;
            if (tree)
                handle_initial(tree, pinfo, tvb, ctx, state, !is_server);
            return;
        case LOGIN:
        case TRANSFER:
        case PLAY:
        case CONFIGURATION:
            if (!visited && is_invalid(try_switch_state(tvb, pinfo, ctx, frame_data, !is_server)))
                return;
            if (tree) {
                TRY {
                        handle_protocol(tree, pinfo, tvb, ctx, state, !is_server);
                    }
                    CATCH_BOUNDS_ERRORS {
                        proto_tree_add_string_format_value(
                            tree, hf_invalid_data_je, tvb, 0, -1, "DISSECT_ERROR",
                            "Packet dissecting error: Bound Error (%s)", GET_MESSAGE
                        );
                    }
                    CATCH_BOUNDS_AND_DISSECTOR_ERRORS {
                        proto_tree_add_string_format_value(
                            tree, hf_invalid_data_je, tvb, 0, -1, "DISSECT_ERROR",
                            "Packet dissecting error: Dissector Error (%s)", GET_MESSAGE
                        );
                    }
                    CATCH_ALL {
                        proto_tree_add_string_format_value(
                            tree, hf_invalid_data_je, tvb, 0, -1, "DISSECT_ERROR",
                            "Packet dissecting error: Other Error (%s)", GET_MESSAGE
                        );
                    }
                ENDTRY;
            }
            return;
        default:
            col_add_str(pinfo->cinfo, COL_INFO, "[Invalid State]");
    }
}

void mark_session_invalid_je(packet_info *pinfo) {
    conversation_t *conv = find_or_create_conversation(pinfo);
    mc_protocol_context *ctx = conversation_get_proto_data(conv, proto_mcje);
    ctx->client_state = ctx->server_state = INVALID;
}

void dissect_je_core(
    tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int32_t offset,
    int32_t packet_len_len, int32_t len, int32_t packet_count
) {
    conversation_t *conv = find_or_create_conversation(pinfo);
    mc_protocol_context *ctx = conversation_get_proto_data(conv, proto_mcje);
    mc_frame_data *frame_data = p_get_proto_data(wmem_file_scope(), pinfo, proto_mcje, 0);

    proto_tree *mcje_tree;
    if (tree) {
        proto_item *ti = proto_tree_add_item(tree, proto_mcje, tvb, 0, -1, FALSE);
        mcje_tree = proto_item_add_subtree(ti, ett_mc_je);
        proto_tree_add_uint(mcje_tree, hf_packet_length_je, tvb, offset - packet_len_len, packet_len_len, len);
        proto_item_append_text(
            ti, ", Client State: %s, Server State: %s",
            JE_STATE_NAME[frame_data->client_state], JE_STATE_NAME[frame_data->server_state]
        );
    }

    tvbuff_t *new_tvb;
    if (frame_data->compression_threshold > 0 && !(packet_count == 0 && frame_data->first_compression_packet)) {
        int32_t uncompressed_length;
        int var_len = read_var_int(tvb, offset, &uncompressed_length);
        if (is_invalid(var_len)) {
            col_set_str(pinfo->cinfo, COL_INFO, "[Invalid] Invalid Compression VarInt");
            mark_session_invalid_je(pinfo);
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
                mark_session_invalid_je(pinfo);
                return;
            }

            new_tvb = tvb_child_uncompress_zlib(tvb, tvb, offset, len - var_len);
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
        proto_tree *sub_mcje_tree = proto_item_add_subtree(packet_item, ett_proto_je);
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
        ctx->secret_key = NULL;
        ctx->server_cipher = NULL;
        ctx->client_cipher = NULL;
        ctx->server_last_segment_remaining = 0;
        ctx->client_last_segment_remaining = 0;
        ctx->server_last_remains = NULL;
        ctx->client_last_remains = NULL;
        ctx->encrypted = false;
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
        frame_data->first_compression_packet = false;
        frame_data->compression_threshold = ctx->compression_threshold;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_mcje, 0, frame_data);
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, MCJE_SHORT_NAME);

    if (frame_data->client_state == NOT_COMPATIBLE || frame_data->server_state == NOT_COMPATIBLE) {
        col_set_str(
            pinfo->cinfo, COL_INFO, "[Invalid] Protocol data is not compatible with the current plugin version"
        );
        return (int32_t) tvb_captured_length(tvb);
    }
    if (frame_data->client_state == INVALID || frame_data->server_state == INVALID) {
        col_set_str(pinfo->cinfo, COL_INFO, "[Invalid] Data may be corrupted or meet a capturing failure");
        return (int32_t) tvb_captured_length(tvb);
    }
    if (frame_data->client_state == PROTOCOL_NOT_FOUND || frame_data->server_state == PROTOCOL_NOT_FOUND) {
        col_set_str(pinfo->cinfo, COL_INFO, "[Invalid] Protocol data is not found or invalid");
        return (int32_t) tvb_captured_length(tvb);
    }
    if (frame_data->client_state == SECRET_KEY_NOT_FOUND || frame_data->server_state == SECRET_KEY_NOT_FOUND) {
        col_set_str(pinfo->cinfo, COL_INFO, "[Decryption Failed] Missing or invalid secret key");
        return (int32_t) tvb_captured_length(tvb);
    }

    bool is_server = addresses_equal(&pinfo->dst, &ctx->server_address) && pinfo->destport == ctx->server_port;

    col_set_str(pinfo->cinfo, COL_INFO, is_server ? "[C => S] " : "[S => C] ");
    if (frame_data->encrypted)
        col_append_str(pinfo->cinfo, COL_INFO, "(Encrypted) ");

    tvbuff_t *use_tvb = tvb;
    if (frame_data->encrypted) {
        uint32_t length = tvb_reported_length_remaining(tvb, 0);
        int32_t length_remaining = is_server
                                       ? ctx->server_last_segment_remaining
                                       : ctx->client_last_segment_remaining;
        gcry_cipher_hd_t *cipher = is_server ? &ctx->server_cipher : &ctx->client_cipher;
        uint8_t **decrypt_data =
            pinfo->curr_proto_layer_num == 1
                ? &frame_data->decrypted_data_head
                : &frame_data->decrypted_data_tail;

        if (*cipher == NULL) {
            gcry_cipher_open(cipher, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CFB8, 0);
            gcry_cipher_setkey(*cipher, ctx->secret_key, 16);
            gcry_cipher_setiv(*cipher, ctx->secret_key, 16);
        }

        if (!*decrypt_data) {
            uint8_t *decrypt = wmem_alloc(pinfo->pool, length - length_remaining);
            gcry_error_t err = gcry_cipher_decrypt(
                *cipher, decrypt,
                length - length_remaining,
                tvb_memdup(pinfo->pool, tvb, length_remaining, length - length_remaining),
                length - length_remaining
            );
            if (err) {
                col_set_str(pinfo->cinfo, COL_INFO, "[Decryption Failed] Decryption failed with code ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%d", err);
                mark_session_invalid_je(pinfo);
                return (int32_t) tvb_captured_length(tvb);
            }

            uint8_t *merged = wmem_alloc(wmem_file_scope(), length);
            memcpy(merged, is_server ? ctx->server_last_remains : ctx->client_last_remains, length_remaining);
            memcpy(merged + length_remaining, decrypt, length - length_remaining);

            *decrypt_data = merged;
        }

        use_tvb = tvb_new_child_real_data(tvb, *decrypt_data, length, (int32_t) length);
        add_new_data_source(pinfo, use_tvb, "Decrypted packet");
    }

    if (!pinfo->fd->visited && ctx->client_state == HANDSHAKE && tvb_get_uint8(tvb, 0) == 0xFE) {
        ctx->client_state = ctx->server_state = LEGACY_QUERY;
        frame_data->client_state = frame_data->server_state = LEGACY_QUERY;
    }

    if (frame_data->client_state == LEGACY_QUERY) {
        if (!pinfo->fd->visited && is_server && wmem_map_lookup(ctx->global_data, "meet_first") == NULL) {
            pinfo->desegment_offset = 0;
            pinfo->desegment_len = DESEGMENT_UNTIL_FIN;
            wmem_map_insert(ctx->global_data, "meet_first", GINT_TO_POINTER(1));
            return (int32_t) tvb_captured_length(tvb);
        }
        handle_legacy_query(tvb, pinfo, tree, ctx);
        return (int32_t) tvb_captured_length(tvb);
    }

    int32_t offset = 0;
    int32_t packet_count = 0;
    while (offset < tvb_reported_length(use_tvb)) {
        int32_t available = tvb_reported_length_remaining(use_tvb, offset);
        int32_t len = 0;
        int32_t packet_len_len = read_var_int_with_limit(use_tvb, offset, available, &len);

        if (packet_len_len == INVALID_DATA) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "[%d packet(s)]", packet_count);
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            if (!pinfo->fd->visited) {
                if (is_server) {
                    ctx->server_last_segment_remaining = available;
                    if (ctx->server_last_remains) wmem_free(wmem_file_scope(), ctx->server_last_remains);
                    ctx->server_last_remains = tvb_memdup(wmem_file_scope(), use_tvb, offset, available);
                } else {
                    ctx->client_last_segment_remaining = available;
                    if (ctx->client_last_remains) wmem_free(wmem_file_scope(), ctx->client_last_remains);
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
                    if (ctx->server_last_remains) wmem_free(wmem_file_scope(), ctx->server_last_remains);
                    ctx->server_last_remains = tvb_memdup(wmem_file_scope(), use_tvb, offset, available);
                } else {
                    ctx->client_last_segment_remaining = available;
                    if (ctx->client_last_remains) wmem_free(wmem_file_scope(), ctx->client_last_remains);
                    ctx->client_last_remains = tvb_memdup(wmem_file_scope(), use_tvb, offset, available);
                }
            }
            return offset + available;
        }

        offset += packet_len_len;
        dissect_je_core(use_tvb, pinfo, tree, offset, packet_len_len, len, packet_count);
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
    return (int32_t) tvb_captured_length(tvb);
}
