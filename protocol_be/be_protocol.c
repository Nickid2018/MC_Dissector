//
// Created by nickid2018 on 2026/2/20.
//

#include "be_dissect.h"
#include "be_protocol.h"
#include "protocol/storage/storage.h"

extern protocol_storage *storage_be;
extern int hf_packet_id_be;
extern int hf_packet_name_be;
extern int hf_unknown_packet_be;
extern int hf_invalid_data_be;

extern gchar *pref_secret_key_be;

char *BE_STATE_NAME[] = {
    "Initial", "Game",
    "Invalid", "Not Compatible", "Protocol Not Found", "Secret Key Not Found"
};

int32_t read_packet_len(tvbuff_t *tvb, int32_t offset) {
    int32_t packet_len;
    int32_t len = read_var_int(tvb, offset, &packet_len);
    if (is_invalid(len)) return INVALID_DATA;
    return packet_len + len;
}

int try_change_state(
    tvbuff_t *tvb, int32_t offset, packet_info *pinfo,
    mc_protocol_context *ctx, mc_frame_data *frame_data, bool is_client
) {
    be_state now_state = frame_data->client_state;
    protocol_dissector_set *set = now_state == INITIAL ? get_initial_protocol(storage_be) : ctx->dissector_set;
    if (set == NULL) return INVALID_DATA;

    int32_t packet_len;
    int32_t len = read_var_int(tvb, offset, &packet_len);
    if (is_invalid(len)) return INVALID_DATA;
    offset += len;
    if (packet_len + offset > tvb_reported_length(tvb)) return INVALID_DATA;

    int32_t packet_id;
    len = read_var_int(tvb, offset, &packet_id);
    if (is_invalid(len)) return INVALID_DATA;
    offset += len;

    wmem_map_t *state_to_next = wmem_map_lookup(set->state_to_next, (void *) (uint64_t) now_state);
    wmem_map_t *special_mark = wmem_map_lookup(set->special_mark, (void *) (uint64_t) now_state);

    if (wmem_map_contains(state_to_next, (void *) (uint64_t) packet_id)) {
        ctx->client_state = ctx->server_state = GAME;
    }

    if (wmem_map_contains(special_mark, (void *) (uint64_t) packet_id)) {
        char *mark = wmem_map_lookup(special_mark, (void *) (uint64_t) packet_id);

        if (strcmp(mark, "login") == 0) {
            int32_t protocol_version = tvb_get_int32(tvb, offset, ENC_BIG_ENDIAN);
            ctx->protocol_version = protocol_version;
            wmem_map_insert(ctx->global_data, "protocol_version", (void *) (uint64_t) protocol_version);
            ctx->dissector_set = get_protocol_set(storage_be, protocol_version);
            if (ctx->dissector_set == NULL)
                ctx->client_state = ctx->server_state = PROTOCOL_NOT_FOUND;
            else
                ctx->client_state = ctx->server_state = GAME;
        }

        if (strcmp(mark, "encrypt") == 0) {
            ctx->encrypted = true;
            if (pref_secret_key_be == NULL || strlen(pref_secret_key_be) != 64) {
                ctx->server_state = ctx->client_state = SECRET_KEY_NOT_FOUND;
            } else {
                uint8_t *secret_key = wmem_alloc(wmem_file_scope(), 32);
                bool failed = false;
                for (int i = 0; i < 32; i++) {
                    gchar hex[3] = {pref_secret_key_be[i * 2], pref_secret_key_be[i * 2 + 1], '\0'};
                    errno = 0;
                    secret_key[i] = (uint8_t) strtol(hex, NULL, 16);
                    if (errno != 0) {
                        failed = true;
                        break;
                    }
                }
                if (failed) {
                    ctx->server_state = ctx->client_state = SECRET_KEY_NOT_FOUND;
                } else {
                    ctx->secret_key = secret_key;
                }
            }
        }

        if (strcmp(mark, "network_settings") == 0) {
            uint16_t compress_threshold = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
            uint16_t compress_algorithm = tvb_get_uint16(tvb, offset + 2, ENC_LITTLE_ENDIAN);
            ctx->compression_threshold = compress_threshold;
            ctx->compression_algorithm = compress_algorithm;
        }
    }

    return packet_len + len;
}

void handle_packet(
    proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int32_t offset,
    mc_protocol_context *ctx, be_state state, bool is_client
) {
    protocol_dissector_set *set = state == INITIAL ? get_initial_protocol(storage_be) : ctx->dissector_set;

    int32_t packet_len;
    int32_t len = read_var_int(tvb, offset, &packet_len);
    offset += len;

    int32_t packet_id;
    len = read_var_int(tvb, offset, &packet_id);
    offset += len;

    proto_tree_add_uint(tree, hf_packet_id_be, tvb, 0, len, packet_id);
    uint32_t count = (uint64_t) wmem_map_lookup(set->count_by_state, (void *) (uint64_t) state);
    if (packet_id >= count) {
        proto_tree_add_string(tree, hf_unknown_packet_be, tvb, 0, 1, "Unknown Packet ID");
        return;
    }

    char **key = wmem_map_lookup(set->registry_keys, (void *) (uint64_t) state);
    char **name = wmem_map_lookup(set->readable_names, (void *) (uint64_t) state);
    protocol_dissector **d = wmem_map_lookup(set->dissectors_by_state, (void *) (uint64_t) state);
    proto_tree_add_string_format_value(
        tree, hf_packet_name_be, tvb, 0, len, key[packet_id],
        "%s (%s)", name[packet_id], key[packet_id]
    );

    wmem_map_t *packet_save = wmem_map_new(pinfo->pool, g_str_hash, g_str_equal);
    int32_t sub_len = d[packet_id]->dissect_protocol(
        tree, pinfo, tvb, offset, pinfo->pool, d[packet_id], "Packet Data", packet_save, NULL
    );
    if (sub_len + len != packet_len && sub_len != DISSECT_ERROR)
        proto_tree_add_string_format_value(
            tree, hf_invalid_data_be, tvb, offset, packet_len - len,
            "length mismatch", "Packet length mismatch, expected %d, got %d", packet_len - len,
            sub_len
        );
}
