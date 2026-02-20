//
// Created by Nickid2018 on 2023/7/13.
//

#include <epan/conversation.h>
#include <epan/dissectors/packet-raknet.h>
#include <epan/proto_data.h>

#include "be_dissect.h"

#include <epan/exceptions.h>

#include "be_protocol.h"
#include "mc_dissector.h"
#include "protocol/protocol_data.h"
#include "protocol/storage/storage.h"

dissector_handle_t mcbe_handle;

extern int ett_mc_be;
extern int hf_invalid_data_be;
extern int hf_packet_id_be;
extern int hf_packet_length_be;

void proto_reg_handoff_mcbe() {
    mcbe_handle = create_dissector_handle(dissect_be_conv, proto_mcbe);
    raknet_add_udp_dissector(MCBE_PORT, mcbe_handle);
}

void mark_session_invalid_be(packet_info *pinfo) {
    conversation_t *conv = find_or_create_conversation(pinfo);
    mc_protocol_context *ctx = conversation_get_proto_data(conv, proto_mcbe);
    ctx->client_state = ctx->server_state = INVALID;
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

    int32_t len;
    int32_t len_len = read_var_int(tvb, 0, &len);
    if (is_invalid(len_len)) {
        col_set_str(pinfo->cinfo, COL_INFO, "[Invalid] Invalid Compression VarInt");
        mark_session_invalid_be(pinfo);
        return report_len;
    }

    int32_t offset = len_len;
    tvbuff_t *new_tvb = NULL;
    switch (frame_data->compression_algorithm) {
        case SNAPPY:
            new_tvb = tvb_child_uncompress_snappy(tvb, tvb, offset, report_len - offset);
            break;
        case ZLIB:
            new_tvb = tvb_child_uncompress_zlib(tvb, tvb, offset, report_len - offset);
            break;
        default:
            col_set_str(pinfo->cinfo, COL_INFO, "[Invalid] Invalid Compression Algorithm");
            mark_session_invalid_be(pinfo);
            return report_len;
    }
    if (new_tvb == NULL) {
        col_set_str(pinfo->cinfo, COL_INFO, "[Invalid] Uncompression failed");
        return report_len;
    }

    add_new_data_source(pinfo, new_tvb, "Uncompressed packet");
    return dissect_be_core(new_tvb, pinfo, tree, ctx, frame_data);
}

int dissect_be_conv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    int32_t report_len = tvb_reported_length(tvb);
    if (tvb_get_uint8(tvb, 0) != MSG_GAME) {
        return report_len;
    }
    tvb = tvb_new_subset_length(tvb, 1, report_len - 1);

    conversation_t *conv = find_or_create_conversation(pinfo);
    mc_protocol_context *ctx = conversation_get_proto_data(conv, proto_mcbe);
    if (!ctx) {
        ctx = wmem_alloc(wmem_file_scope(), sizeof(mc_protocol_context));
        ctx->client_state = is_compatible_protocol_data() ? INITIAL : NOT_COMPATIBLE;
        ctx->server_state = is_compatible_protocol_data() ? INITIAL : NOT_COMPATIBLE;
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
        conversation_add_proto_data(conv, proto_mcbe, ctx);
    }

    mc_frame_data *frame_data = p_get_proto_data(wmem_file_scope(), pinfo, proto_mcbe, 0);
    if (!frame_data) {
        frame_data = wmem_alloc(wmem_file_scope(), sizeof(mc_frame_data));
        frame_data->client_state = ctx->client_state;
        frame_data->server_state = ctx->server_state;
        frame_data->encrypted = ctx->encrypted;
        frame_data->decrypted_data_head = NULL;
        frame_data->decrypted_data_tail = NULL;
        frame_data->first_compression_packet = false;
        frame_data->compression_threshold = ctx->compression_threshold;
        frame_data->compression_algorithm = ctx->compression_algorithm;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_mcbe, 0, frame_data);
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
    if (frame_data->encrypted)
        col_append_str(pinfo->cinfo, COL_INFO, "(Encrypted) ");

    if (frame_data->compression_threshold > 0 && frame_data->compression_algorithm != NONE) {
        return dissect_be_uncompress(tvb, pinfo, tree, ctx, frame_data) + 1;
    }

    return dissect_be_core(tvb, pinfo, tree, ctx, frame_data) + 1;
}
