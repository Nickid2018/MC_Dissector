//
// Created by Nickid2018 on 2023/7/13.
//

#include <epan/conversation.h>
#include <epan/dissectors/packet-raknet.h>
#include <epan/exceptions.h>
#include <epan/proto_data.h>

#include "be_dissect.h"
#include "be_protocol.h"
#include "mc_dissector.h"
#include "protocol/protocol_data.h"
#include "protocol/storage/storage.h"
#include "utils/endian.h"

dissector_handle_t mcbe_handle;

extern int ett_mc_be;
extern int hf_invalid_data_be;
extern int hf_packet_id_be;
extern int hf_packet_length_be;

void proto_reg_handoff_mcbe() {
    mcbe_handle = create_dissector_handle(dissect_be_conv, proto_mcbe);
    heur_dtbl_entry_t *mcpe_handler = find_heur_dissector_by_unique_short_name("mcpe_raknet");
    heur_dissector_delete("raknet", mcpe_handler->dissector, proto_get_id(mcpe_handler->protocol));
    heur_dissector_add("raknet", dissect_be_core_heuristic, MCBE_NAME, MCBE_FILTER, proto_mcbe, true);
}

void mark_session_invalid_be(packet_info *pinfo) {
    conversation_t *conv = find_or_create_conversation(pinfo);
    mc_protocol_context *ctx = conversation_get_proto_data(conv, proto_mcbe);
    ctx->client_state = ctx->server_state = INVALID;
}

char *bytes_to_hex(wmem_allocator_t *allocator, const uint8_t *bytes, const uint32_t len) {
    wmem_strbuf_t *buf = wmem_strbuf_new(allocator, "");
    for (uint32_t i = 0; i < len; i++){
        wmem_strbuf_append_printf(buf, "%02X", bytes[i] & 0xFF);
    }
    return wmem_strbuf_finalize(buf);
}

int32_t dissect_be_core(
    tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, mc_protocol_context *ctx, mc_frame_data *frame_data
) {
    bool is_server = addresses_equal(&pinfo->dst, &ctx->server_address) && pinfo->destport == ctx->server_port;
    be_state state = is_server ? frame_data->server_state : frame_data->client_state;

    int32_t offset = 0;
    int32_t packets = 0;
    while (offset < tvb_reported_length(tvb)) {
        int32_t len = read_packet_len(tvb, offset);
        if (is_invalid(len)) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "[%d packet(s), malformed]", packets);
            return tvb_reported_length(tvb);
        }
        if (!pinfo->fd->visited && is_invalid(try_change_state(tvb, offset, pinfo, ctx, frame_data, !is_server))) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "[%d packet(s), state error]", packets);
            return tvb_reported_length(tvb);
        }
        if (tree) {
            proto_item *ti = proto_tree_add_item(tree, proto_mcbe, tvb, offset, len, FALSE);
            proto_tree *sub_tree = proto_item_add_subtree(ti, ett_mc_be);
            TRY {
                    handle_packet(sub_tree, pinfo, tvb, offset, ctx, state, !is_server);
                }
                CATCH_BOUNDS_ERRORS {
                    proto_tree_add_string_format_value(
                        tree, hf_invalid_data_be, tvb, 0, -1, "DISSECT_ERROR",
                        "Packet dissecting error: Bound Error (%s)", GET_MESSAGE
                    );
                }
                CATCH_BOUNDS_AND_DISSECTOR_ERRORS {
                    proto_tree_add_string_format_value(
                        tree, hf_invalid_data_be, tvb, 0, -1, "DISSECT_ERROR",
                        "Packet dissecting error: Dissector Error (%s)", GET_MESSAGE
                    );
                }
                CATCH_ALL {
                    proto_tree_add_string_format_value(
                        tree, hf_invalid_data_be, tvb, 0, -1, "DISSECT_ERROR",
                        "Packet dissecting error: Other Error (%s)", GET_MESSAGE
                    );
                }
            ENDTRY;
            proto_item_append_text(
                ti, ", Client State: %s, Server State: %s",
                BE_STATE_NAME[frame_data->client_state], BE_STATE_NAME[frame_data->server_state]
            );
        }
        offset += len;
        packets++;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, "[%d packet(s)]", packets);
    return offset;
}

int32_t dissect_be_uncompress(
    tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, mc_protocol_context *ctx, mc_frame_data *frame_data
) {
    int32_t report_len = tvb_reported_length(tvb);
    tvbuff_t *new_tvb = NULL;
    switch (tvb_get_uint8(tvb, 0)) {
        case ZLIB:
            new_tvb = tvb_child_uncompress_zlib(tvb, tvb, 1, report_len - 1);
            break;
        case SNAPPY:
            new_tvb = tvb_child_uncompress_snappy(tvb, tvb, 1, report_len - 1);
            break;
        case 255:
            new_tvb = tvb_new_subset_length(tvb, 1, report_len - 1);
            return dissect_be_core(new_tvb, pinfo, tree, ctx, frame_data) + 1;
        default:
            col_set_str(pinfo->cinfo, COL_INFO, "[Invalid] Invalid Compression Algorithm");
            // mark_session_invalid_be(pinfo);
            return report_len;
    }
    if (new_tvb == NULL) {
        col_set_str(pinfo->cinfo, COL_INFO, "[Invalid] Uncompression failed");
        return report_len;
    }

    add_new_data_source(pinfo, new_tvb, "Uncompressed packet");
    dissect_be_core(new_tvb, pinfo, tree, ctx, frame_data);
    return report_len;
}

int dissect_be_conv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    if (tree) tree = proto_tree_get_root(tree);

    int32_t report_len = tvb_reported_length(tvb);
    if (tvb_get_uint8(tvb, 0) != MSG_GAME) {
        return report_len;
    }
    tvb = tvb_new_subset_length(tvb, 1, report_len - 1);

    conversation_t *conv = find_or_create_conversation(pinfo);
    mc_protocol_context *ctx = conversation_get_proto_data(conv, proto_mcbe);
    mcbe_context *protocol_ctx = ctx->protocol_data;

    mc_frame_data *frame_data = p_get_proto_data(wmem_file_scope(), pinfo, proto_mcbe, 0);
    if (!frame_data) {
        frame_data = wmem_alloc(wmem_file_scope(), sizeof(mc_frame_data));
        frame_data->client_state = ctx->client_state;
        frame_data->server_state = ctx->server_state;
        frame_data->encrypted = ctx->encrypted;
        frame_data->protocol_data = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_mcbe, 0, frame_data);
    }

    mcbe_frame_data *protocol_frame = wmem_map_lookup(frame_data->protocol_data, GUINT_TO_POINTER(pinfo->curr_proto_layer_num));
    if (!protocol_frame) {
        protocol_frame = wmem_alloc(wmem_file_scope(), sizeof(mcbe_frame_data));
        protocol_frame->decrypted_data = NULL;
        protocol_frame->compression_threshold = protocol_ctx->compression_threshold;
        protocol_frame->compression_algorithm = protocol_ctx->compression_algorithm;
        protocol_frame->expect_checksum = NULL;
        wmem_map_insert(frame_data->protocol_data, GUINT_TO_POINTER(pinfo->curr_proto_layer_num), protocol_frame);
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, MCBE_SHORT_NAME);
    if (frame_data->client_state == NOT_COMPATIBLE || frame_data->server_state == NOT_COMPATIBLE) {
        col_set_str(
            pinfo->cinfo, COL_INFO, "[Invalid] Protocol data is not compatible with the current plugin version"
        );
        return report_len;
    }
    if (frame_data->client_state == INVALID || frame_data->server_state == INVALID) {
        col_set_str(pinfo->cinfo, COL_INFO, "[Invalid] Data may be corrupted or meet a capturing failure");
        return report_len;
    }
    if (frame_data->client_state == PROTOCOL_NOT_FOUND || frame_data->server_state == PROTOCOL_NOT_FOUND) {
        col_set_str(pinfo->cinfo, COL_INFO, "[Invalid] Protocol data is not found or invalid");
        return report_len;
    }
    if (frame_data->client_state == SECRET_KEY_NOT_FOUND || frame_data->server_state == SECRET_KEY_NOT_FOUND) {
        col_set_str(pinfo->cinfo, COL_INFO, "[Decryption Failed] Missing or invalid secret key");
        return report_len;
    }

    bool is_server = addresses_equal(&pinfo->dst, &ctx->server_address) && pinfo->destport == ctx->server_port;
    col_set_str(pinfo->cinfo, COL_INFO, is_server ? "[C => S] " : "[S => C] ");

    if (frame_data->encrypted) {
        col_append_str(pinfo->cinfo, COL_INFO, "(Encrypted) ");
        uint32_t length = tvb_reported_length_remaining(tvb, 0);

        gcry_cipher_hd_t *cipher = is_server ? &ctx->server_cipher : &ctx->client_cipher;

        if (*cipher == NULL) {
            if (ctx->protocol_version <= 431) {
                gcry_cipher_open(cipher, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB8, 0);
                gcry_cipher_setkey(*cipher, ctx->secret_key, 32);
                gcry_cipher_setiv(*cipher, ctx->secret_key, 16);
            } else {
                gcry_cipher_open(cipher, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, 0);
                gcry_cipher_setkey(*cipher, ctx->secret_key, 32);
                gcry_cipher_setiv(*cipher, ctx->secret_key, 12);
            }
        }

        if (!protocol_frame->decrypted_data) {
            int64_t *counter = is_server ? &protocol_ctx->server_counter : &protocol_ctx->client_counter;
            protocol_frame->decrypted_data = wmem_alloc(wmem_file_scope(), length);
            gcry_error_t err = gcry_cipher_decrypt(
                *cipher, protocol_frame->decrypted_data,
                length,
                tvb_memdup(pinfo->pool, tvb, 0, length),
                length
            );
            if (err) {
                col_set_str(pinfo->cinfo, COL_INFO, "[Decryption Failed] Decryption failed with code ");
                col_append_fstr(pinfo->cinfo, COL_INFO, "%d", err);
                mark_session_invalid_be(pinfo);
                return (int32_t) length + 1;
            }

            uint8_t *checksum_buffer = wmem_alloc(pinfo->pool, length + 32);
            uint64_t le_counter = htole64(*counter);
            memcpy(checksum_buffer, &le_counter, 8);
            memcpy(checksum_buffer + 8, protocol_frame->decrypted_data, length - 8);
            memcpy(checksum_buffer + length, ctx->secret_key, 32);
            uint8_t *hash_buffer = wmem_alloc(pinfo->pool, 32);
            gcry_md_hash_buffer(GCRY_MD_SHA256, hash_buffer, checksum_buffer, length + 32);
            char *got = bytes_to_hex(pinfo->pool, protocol_frame->decrypted_data + length - 8, 8);
            char *expect = bytes_to_hex(pinfo->pool, hash_buffer, 8);
            if (strcmp(got, expect) != 0) {
                protocol_frame->expect_checksum = wmem_strdup(wmem_file_scope(), expect);
            }

            *counter = *counter + 1;
        }

        tvb = tvb_new_child_real_data(tvb, protocol_frame->decrypted_data, length, (int32_t) length);
        add_new_data_source(pinfo, tvb, "Decrypted packet");

        if (protocol_frame->expect_checksum && tree) {
            proto_item *ti = proto_tree_add_item(tree, proto_mcbe, tvb, length - 8, 8, FALSE);
            proto_tree *sub_tree = proto_item_add_subtree(ti, ett_mc_be);
            proto_tree_add_string_format_value(
                sub_tree, hf_invalid_data_be, tvb, length - 8, 8, "invalid_hash",
                "Packet Hash mismatch: expect %s, got %s",
                protocol_frame->expect_checksum,
                bytes_to_hex(pinfo->pool, protocol_frame->decrypted_data + length - 8, 8)
            );
        }

        tvb = tvb_new_subset_length(tvb, 0, length - 8);
    }

    if (protocol_frame->compression_threshold > 0 && protocol_frame->compression_algorithm != NONE) {
        return dissect_be_uncompress(tvb, pinfo, tree, ctx, frame_data) + 1;
    }

    return dissect_be_core(tvb, pinfo, tree, ctx, frame_data) + 1;
}

bool dissect_be_core_heuristic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    if (tvb_reported_length(tvb) == 0 || tvb_get_uint8(tvb, 0) != MSG_GAME) {
        return false;
    }
    raknet_conversation_set_dissector(pinfo, mcbe_handle);
    if (tree) tree = proto_tree_get_root(tree);

    conversation_t *conv = find_or_create_conversation(pinfo);
    mc_protocol_context *ctx = conversation_get_proto_data(conv, proto_mcbe);
    if (!ctx) {
        ctx = wmem_alloc(wmem_file_scope(), sizeof(mc_protocol_context));
        ctx->client_state = is_compatible_protocol_data() ? INITIAL : NOT_COMPATIBLE;
        ctx->server_state = is_compatible_protocol_data() ? INITIAL : NOT_COMPATIBLE;
        ctx->server_port = pinfo->destport;
        copy_address(&ctx->server_address, &pinfo->dst);
        ctx->encrypted = false;
        ctx->secret_key = NULL;
        ctx->server_cipher = NULL;
        ctx->client_cipher = NULL;
        mcbe_context *protocol_ctx = wmem_alloc(wmem_file_scope(), sizeof(mcbe_context));
        protocol_ctx->compression_threshold = -1;
        protocol_ctx->compression_algorithm = NONE;
        protocol_ctx->client_counter = 0;
        protocol_ctx->server_counter = 0;
        ctx->protocol_data = protocol_ctx;
        ctx->global_data = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
        conversation_add_proto_data(conv, proto_mcbe, ctx);
    }

    mc_frame_data *frame_data = p_get_proto_data(wmem_file_scope(), pinfo, proto_mcbe, 0);
    if (!frame_data) {
        frame_data = wmem_alloc(wmem_file_scope(), sizeof(mc_frame_data));
        frame_data->client_state = ctx->client_state;
        frame_data->server_state = ctx->server_state;
        frame_data->encrypted = ctx->encrypted;
        frame_data->protocol_data = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
        mcbe_frame_data *protocol_frame = wmem_alloc(wmem_file_scope(), sizeof(mcbe_frame_data));
        protocol_frame->decrypted_data = NULL;
        protocol_frame->compression_threshold = -1;
        protocol_frame->compression_algorithm = NONE;
        wmem_map_insert(frame_data->protocol_data, GUINT_TO_POINTER(pinfo->curr_proto_layer_num), protocol_frame);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_mcbe, 0, frame_data);
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, MCBE_SHORT_NAME);
    col_set_str(pinfo->cinfo, COL_INFO, "[C => S] ");
    dissect_be_core(tvb_new_subset_length(tvb, 1, tvb_reported_length(tvb) - 1), pinfo, tree, ctx, frame_data);

    return true;
}
