//
// Created by Nickid2018 on 2023/7/16.
//

#include <epan/packet.h>
#include "je_protocol.h"
#include "../mc_dissector.h"
#include "je_protocol_constants.h"

int hf_invalid_data_je = -1;
int hf_ignored_packet_je = -1;
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
int hf_f32_x = -1;
int hf_f32_y = -1;
int hf_f32_z = -1;
int hf_f32_w = -1;
int hf_f64_x = -1;
int hf_f64_y = -1;
int hf_f64_z = -1;
int hf_slot_present = -1;
int hf_item_id = -1;
int hf_item_count = -1;
int hf_nbt_data = -1;
int hf_particle_id = -1;
int hf_varint_blockstate = -1;
int hf_red_factor = -1;
int hf_green_factor = -1;
int hf_blue_factor = -1;
int hf_scale = -1;
int hf_from_red_factor = -1;
int hf_from_green_factor = -1;
int hf_from_blue_factor = -1;
int hf_to_red_factor = -1;
int hf_to_green_factor = -1;
int hf_to_blue_factor = -1;
int hf_position_type = -1;
int hf_entity_id = -1;
int hf_entity_eye_height = -1;
int hf_destination = -1;
int hf_ticks = -1;
int hf_delay_in_ticks_before_shown = -1;
int hf_id = -1;
int hf_signature = -1;
int hf_pitch_float = -1;
int hf_yaw_float = -1;
int hf_roll_float = -1;
int hf_villager_type = -1;
int hf_villager_profession = -1;
int hf_level = -1;
int hf_category = -1;
int hf_group = -1;
int hf_experience = -1;
int hf_cook_time = -1;
int hf_tag_name = -1;
int hf_tag_entry = -1;
int hf_i16_y = -1;
int hf_varint_type = -1;
int hf_uuid = -1;
int hf_expire_time = -1;
int hf_key_bytes = -1;
int hf_name = -1;
int hf_key_string = -1;
int hf_value_string = -1;
int hf_signature_string = -1;
int hf_children_int = -1;
int hf_redirect_node = -1;
int hf_parser = -1;
int hf_suggestion_type = -1;
int hf_reason = -1;
int hf_server_id = -1;
int hf_public_key = -1;
int hf_verify_token = -1;
int hf_user_name = -1;
int hf_threshold_int = -1;
int hf_message_id = -1;
int hf_channel_str = -1;
int hf_data = -1;
int hf_shared_secret = -1;

int hf_chunk_data = -1;
// --------------------
int hf_position_xzy = -1;
int hf_position_xz = -1;
int hf_command_flags = -1;
int hf_command_arg_limit = -1;
int hf_command_entity_arg = -1;
int hf_command_score_holder_arg = -1;
int hf_advancement_flags = -1;
int hf_chunk_coords = -1;
// --------------------
int hf_x_26 = -1;
int hf_z_26 = -1;
int hf_y_12 = -1;
int hf_x_4 = -1;
int hf_z_4 = -1;
int hf_unused_3 = -1;
int hf_has_custom_suggestions_1 = -1;
int hf_has_redirect_node_1 = -1;
int hf_has_command_1 = -1;
int hf_command_node_type_2 = -1;
int hf_unused_6 = -1;
int hf_max_present_1 = -1;
int hf_min_present_1 = -1;
int hf_only_allow_players_1 = -1;
int hf_only_allow_entities_1 = -1;
int hf_unused_7 = -1;
int hf_allow_multiple_1 = -1;
int hf_unused_29 = -1;
int hf_hidden_1 = -1;
int hf_show_toast_1 = -1;
int hf_has_background_texture_1 = -1;
int hf_x_22 = -1;
int hf_z_22 = -1;
int hf_y_20 = -1;
// --------------------
int *positionXZY[] = {&hf_x_26, &hf_z_26, &hf_y_12, NULL};
int *positionXZ[] = {&hf_x_4, &hf_z_4, NULL};
int *command_flags[] = {&hf_unused_3, &hf_has_custom_suggestions_1, &hf_has_redirect_node_1,
                        &hf_has_command_1, &hf_command_node_type_2, NULL};
int *command_arg_limit[] = {&hf_unused_6, &hf_max_present_1, &hf_min_present_1, NULL};
int *command_arg_entity[] = {&hf_unused_6, &hf_only_allow_players_1, &hf_only_allow_entities_1, NULL};
int *command_arg_score_holder[] = {&hf_unused_7, &hf_allow_multiple_1, NULL};
int *advancement_display[] = {&hf_unused_29, &hf_hidden_1, &hf_show_toast_1, &hf_has_background_texture_1,
                              NULL};
int *chunk_coordinates[] = {&hf_x_22, &hf_z_22, &hf_y_20, NULL};
// --------------------

int ett_mcje = -1;
int ett_je_proto = -1;
int ett_sub_je = -1;
wmem_map_t *name_hf_map_je = NULL;
wmem_map_t *unknown_hf_map_je = NULL;
wmem_map_t *bitmask_hf_map_je = NULL;

module_t *pref_mcje = NULL;
gchar *pref_ignore_packets_je = "c:map_chunk";

void proto_register_mcje() {
    proto_mcje = proto_register_protocol(MCJE_NAME, MCJE_SHORT_NAME, MCJE_FILTER);

    static gint *ett_je[] = {&ett_mcje, &ett_je_proto, &ett_sub_je};
    static hf_register_info hf_je[] = {
            DEFINE_HF(hf_invalid_data_je, "Invalid Data", "mcje.invalid_data", STRING, NONE)
            DEFINE_HF(hf_ignored_packet_je, "Ignored Packet", "mcje.ignored_packet", STRING, NONE)
            DEFINE_HF(hf_packet_length_je, "Packet Length", "mcje.packet_length", UINT32, DEC)
            DEFINE_HF(hf_packet_data_length_je, "Packet Data Length", "mcje.packet_data_length", UINT32, DEC)
            DEFINE_HF(hf_packet_id_je, "Packet ID", "mcje.packet_id", UINT8, HEX)
            DEFINE_HF(hf_packet_name_je, "Packet Name", "mcje.packet_name", STRING, NONE)
            DEFINE_HF(hf_protocol_version_je, "Protocol Version", "mcje.protocol_version", STRING, NONE)
            DEFINE_HF(hf_server_address_je, "Server Address", "mcje.server_address", STRING, NONE)
            DEFINE_HF(hf_next_state_je, "Next State", "mcje.next_state", STRING, NONE)
            DEFINE_HF(hf_ping_time_je, "Ping Time", "mcje.ping_time", UINT64, DEC)
            DEFINE_HF(hf_server_status_je, "Server Status", "mcje.server_status", STRING, NONE)

            // Unknowns ------------------------------------------------------------------------------------------------
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

            // Regular Names -------------------------------------------------------------------------------------------
            DEFINE_HF(hf_f32_x, "X", "mcje.f32_x", FLOAT, DEC)
            DEFINE_HF(hf_f32_y, "Y", "mcje.f32_y", FLOAT, DEC)
            DEFINE_HF(hf_f32_z, "Z", "mcje.f32_z", FLOAT, DEC)
            DEFINE_HF(hf_f32_w, "W", "mcje.f32_w", FLOAT, DEC)
            DEFINE_HF(hf_f64_x, "X", "mcje.f64_x", DOUBLE, DEC)
            DEFINE_HF(hf_f64_y, "Y", "mcje.f64_y", DOUBLE, DEC)
            DEFINE_HF(hf_f64_z, "Z", "mcje.f64_z", DOUBLE, DEC)
            DEFINE_HF(hf_slot_present, "Contains Item Stack", "mcje.slot_present", BOOLEAN, NONE)
            DEFINE_HF(hf_item_id, "Item ID", "mcje.item_id", UINT32, DEC)
            DEFINE_HF(hf_item_count, "Item Count", "mcje.item_count", INT8, DEC)
            DEFINE_HF(hf_nbt_data, "NBT Data", "mcje.nbt_data", BYTES, NONE)
            DEFINE_HF(hf_particle_id, "Particle ID", "mcje.particle_id", UINT32, DEC)
            DEFINE_HF(hf_varint_blockstate, "Block State", "mcje.varint_blockstate", UINT32, DEC)
            DEFINE_HF(hf_red_factor, "Red Factor", "mcje.red_factor", FLOAT, DEC)
            DEFINE_HF(hf_green_factor, "Green Factor", "mcje.green_factor", FLOAT, DEC)
            DEFINE_HF(hf_blue_factor, "Blue Factor", "mcje.blue_factor", FLOAT, DEC)
            DEFINE_HF(hf_scale, "Scale", "mcje.scale", FLOAT, DEC)
            DEFINE_HF(hf_from_red_factor, "From Red Factor", "mcje.red_factor", FLOAT, DEC)
            DEFINE_HF(hf_from_green_factor, "From Green Factor", "mcje.green_factor", FLOAT, DEC)
            DEFINE_HF(hf_from_blue_factor, "Form Blue Factor", "mcje.blue_factor", FLOAT, DEC)
            DEFINE_HF(hf_to_red_factor, "To Red Factor", "mcje.red_factor", FLOAT, DEC)
            DEFINE_HF(hf_to_green_factor, "To Green Factor", "mcje.green_factor", FLOAT, DEC)
            DEFINE_HF(hf_to_blue_factor, "To Blue Factor", "mcje.blue_factor", FLOAT, DEC)
            DEFINE_HF(hf_position_type, "Position Type", "mcje.position_type", STRING, NONE)
            DEFINE_HF(hf_entity_id, "Entity ID", "mcje.entity_id", UINT32, DEC)
            DEFINE_HF(hf_entity_eye_height, "Eye Height", "mcje.entity_eye_height", UINT32, DEC)
            DEFINE_HF(hf_destination, "Destination", "mcje.destination", UINT32, DEC)
            DEFINE_HF(hf_ticks, "Ticks", "mcje.ticks", UINT32, DEC)
            DEFINE_HF(hf_delay_in_ticks_before_shown, "Delay in Ticks before Shown", "mcje.delay_in_ticks_before_shown",
                      UINT32, DEC)
            DEFINE_HF(hf_id, "ID", "mcje.id", UINT32, DEC)
            DEFINE_HF(hf_signature, "Signature", "mcje.signature", BYTES, NONE)
            DEFINE_HF(hf_pitch_float, "Pitch", "mcje.pitch", FLOAT, DEC)
            DEFINE_HF(hf_yaw_float, "Yaw", "mcje.yaw", FLOAT, DEC)
            DEFINE_HF(hf_roll_float, "Roll", "mcje.roll", FLOAT, DEC)
            DEFINE_HF(hf_villager_type, "Villager Type", "mcje.villager_type", UINT32, DEC)
            DEFINE_HF(hf_villager_profession, "Villager Profession", "mcje.villager_profession", UINT32, DEC)
            DEFINE_HF(hf_level, "Level", "mcje.level", UINT32, DEC)
            DEFINE_HF(hf_category, "Category", "mcje.category", UINT32, DEC)
            DEFINE_HF(hf_group, "Group", "mcje.group", STRING, NONE)
            DEFINE_HF(hf_experience, "Experience", "mcje.experience", FLOAT, DEC)
            DEFINE_HF(hf_cook_time, "Cook Time", "mcje.cook_time", UINT32, DEC)
            DEFINE_HF(hf_tag_name, "Tag Name", "mcje.tag_name", STRING, NONE)
            DEFINE_HF(hf_tag_entry, "Tag Entry", "mcje.tag_entry", UINT32, DEC)
            DEFINE_HF(hf_i16_y, "Y", "mcje.i16_y", INT16, DEC)
            DEFINE_HF(hf_varint_type, "Type", "mcje.varint_type", UINT32, DEC)
            DEFINE_HF(hf_uuid, "UUID", "mcje.uuid", GUID, NONE)
            DEFINE_HF(hf_expire_time, "Expire Time", "mcje.expire_time", INT64, DEC)
            DEFINE_HF(hf_key_bytes, "Key Bytes", "mcje.key_bytes", BYTES, NONE)
            DEFINE_HF(hf_name, "Name", "mcje.name", STRING, NONE)
            DEFINE_HF(hf_key_string, "Key", "mcje.key_string", STRING, NONE)
            DEFINE_HF(hf_value_string, "Value", "mcje.value_string", STRING, NONE)
            DEFINE_HF(hf_signature_string, "Signature", "mcje.signature_string", STRING, NONE)
            DEFINE_HF(hf_children_int, "Children", "mcje.children_int", UINT32, DEC)
            DEFINE_HF(hf_redirect_node, "Redirect Node", "mcje.redirect_node", UINT32, DEC)
            DEFINE_HF(hf_parser, "Parser", "mcje.parser", STRING, NONE)
            DEFINE_HF(hf_suggestion_type, "Suggestion Type", "mcje.suggestion_type", STRING, NONE)
            DEFINE_HF(hf_reason, "Reason", "mcje.reason", STRING, NONE)
            DEFINE_HF(hf_server_id, "Server ID", "mcje.server_id", STRING, NONE)
            DEFINE_HF(hf_public_key, "Public Key", "mcje.public_key", BYTES, NONE)
            DEFINE_HF(hf_verify_token, "Verify Token", "mcje.verify_token", BYTES, NONE)
            DEFINE_HF(hf_user_name, "User Name", "mcje.user_name", STRING, NONE)
            DEFINE_HF(hf_threshold_int, "Threshold", "mcje.threshold", UINT32, DEC)
            DEFINE_HF(hf_message_id, "Message ID", "mcje.message_id", UINT32, DEC)
            DEFINE_HF(hf_channel_str, "Channel", "mcje.channel_str", STRING, NONE)
            DEFINE_HF(hf_data, "Data", "mcje.data", BYTES, NONE)
            DEFINE_HF(hf_shared_secret, "Shared Secret", "mcje.shared_secret", BYTES, NONE)

            DEFINE_HF(hf_chunk_data, "Chunk Data", "mcje.chunk_data", BYTES, NONE)

            // BITMASK Parents -----------------------------------------------------------------------------------------
            DEFINE_HF(hf_position_xzy, "Position", "mcje.position_xzy", INT64, NO_DISPLAY_VALUE | BASE_DEC)
            DEFINE_HF(hf_position_xz, "Chunk Position", "mcje.position_xz", INT8, NO_DISPLAY_VALUE | BASE_DEC)
            DEFINE_HF(hf_command_flags, "Command Flags", "mcje.command_flags", UINT8, NO_DISPLAY_VALUE | BASE_DEC)
            DEFINE_HF(hf_command_arg_limit, "Command Argument Limit", "mcje.command_arg_limit", UINT8,
                      NO_DISPLAY_VALUE | BASE_DEC)
            DEFINE_HF(hf_command_entity_arg, "Command Entity Argument", "mcje.command_entity_arg", UINT8,
                      NO_DISPLAY_VALUE | BASE_DEC)
            DEFINE_HF(hf_command_score_holder_arg, "Command Score Holder Argument", "mcje.command_score_holder_arg",
                      UINT8, NO_DISPLAY_VALUE | BASE_DEC)
            DEFINE_HF(hf_advancement_flags, "Advancement Display Flags", "mcje.advancement_flags", UINT32,
                      NO_DISPLAY_VALUE | BASE_DEC)
            DEFINE_HF(hf_chunk_coords, "Chunk Coordinates", "mcje.chunk_coords", INT64, NO_DISPLAY_VALUE | BASE_DEC)

            // BITMASKS ------------------------------------------------------------------------------------------------
            DEFINE_HF_BITMASK(hf_x_26, "X", "mcje.x26", INT64, DEC, 0xFFFFFFC000000000)
            DEFINE_HF_BITMASK(hf_z_26, "Z", "mcje.z26", INT64, DEC, 0x0000003FFFFFF000)
            DEFINE_HF_BITMASK(hf_y_12, "Y", "mcje.y12", INT64, DEC, 0x0000000000000FFF)
            DEFINE_HF_BITMASK(hf_x_4, "X", "mcje.x4", INT8, DEC, 0xF0)
            DEFINE_HF_BITMASK(hf_z_4, "Z", "mcje.z4", INT8, DEC, 0x0F)
            DEFINE_HF_BITMASK(hf_unused_3, "Unused Bits", "mcje.unused3", UINT8, NO_DISPLAY_VALUE | BASE_DEC, 0xE0)
            DEFINE_HF_BITMASK(hf_has_custom_suggestions_1, "Has Custom Suggestions", "mcje.has_custom_suggestions",
                              BOOLEAN, NONE, 0x10)
            DEFINE_HF_BITMASK(hf_has_redirect_node_1, "Has Redirect Node", "mcje.has_redirect_node", BOOLEAN, NONE,
                              0x08)
            DEFINE_HF_BITMASK(hf_has_command_1, "Executable", "mcje.has_command", BOOLEAN, NONE, 0x04)
            DEFINE_HF_BITMASK(hf_command_node_type_2, "Command Node Type", "mcje.command_node_type", UINT8, DEC, 0x03)
            DEFINE_HF_BITMASK(hf_unused_6, "Unused Bits", "mcje.unused6", UINT8, NO_DISPLAY_VALUE | BASE_DEC, 0xFC)
            DEFINE_HF_BITMASK(hf_max_present_1, "Max Present", "mcje.max_present", BOOLEAN, NONE, 0x02)
            DEFINE_HF_BITMASK(hf_min_present_1, "Min Present", "mcje.min_present", BOOLEAN, NONE, 0x01)
            DEFINE_HF_BITMASK(hf_only_allow_players_1, "Only Allow Players", "mcje.only_allow_players", BOOLEAN, NONE,
                              0x02)
            DEFINE_HF_BITMASK(hf_only_allow_entities_1, "Only Allow Entities", "mcje.only_allow_entities", BOOLEAN,
                              NONE, 0x01)
            DEFINE_HF_BITMASK(hf_unused_7, "Unused Bits", "mcje.unused7", UINT8, NO_DISPLAY_VALUE | BASE_DEC, 0xFE)
            DEFINE_HF_BITMASK(hf_allow_multiple_1, "Allow Multiple", "mcje.allow_multiple", BOOLEAN, NONE, 0x01)
            DEFINE_HF_BITMASK(hf_unused_29, "Unused Bits", "mcje.unused29", UINT8, NO_DISPLAY_VALUE | BASE_DEC, 0xFFF8)
            DEFINE_HF_BITMASK(hf_hidden_1, "Hidden", "mcje.hidden1", BOOLEAN, NONE, 0x04)
            DEFINE_HF_BITMASK(hf_show_toast_1, "Show Toast", "mcje.show_toast", BOOLEAN, NONE, 0x02)
            DEFINE_HF_BITMASK(hf_has_background_texture_1, "Has Background Texture", "mcje.has_background_texture",
                              BOOLEAN, NONE, 0x01)
            DEFINE_HF_BITMASK(hf_x_22, "X", "mcje.x22", INT64, DEC, 0xFFFFFC0000000000)
            DEFINE_HF_BITMASK(hf_z_22, "Z", "mcje.z22", INT64, DEC, 0x000003FFFFF00000)
            DEFINE_HF_BITMASK(hf_y_20, "Y", "mcje.y20", INT64, DEC, 0x00000000000FFFFF)
    };
    proto_register_field_array(proto_mcje, hf_je, array_length(hf_je));
    proto_register_subtree_array(ett_je, array_length(ett_je));

    // Unknown fields --------------------------------------------------------------------------------------------------
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

    // Field Names -----------------------------------------------------------------------------------------------------
    name_hf_map_je = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    ADD_HF("ver3f/x", hf_f32_x);
    ADD_HF("ver3f/y", hf_f32_y);
    ADD_HF("ver3f/z", hf_f32_z);
    ADD_HF("vec4f/x", hf_f32_x);
    ADD_HF("vec4f/y", hf_f32_y);
    ADD_HF("vec4f/z", hf_f32_z);
    ADD_HF("vec4f/w", hf_f32_w);
    ADD_HF("vec3f64/x", hf_f64_x);
    ADD_HF("vec3f64/y", hf_f64_y);
    ADD_HF("vec3f64/z", hf_f64_z);
    ADD_HF("slot/present", hf_slot_present);
    ADD_HF("slot/[unnamed]/itemId", hf_item_id);
    ADD_HF("slot/[unnamed]/itemCount", hf_item_count);
    ADD_HF("nbtData", hf_nbt_data);
    ADD_HF("particleData/particleId", hf_particle_id);
    ADD_HF("particleData/blockState", hf_varint_blockstate);
    ADD_HF("particleData/red", hf_red_factor);
    ADD_HF("particleData/green", hf_green_factor);
    ADD_HF("particleData/blue", hf_blue_factor);
    ADD_HF("particleData/scale", hf_scale);
    ADD_HF("particleData/fromRed", hf_from_red_factor);
    ADD_HF("particleData/fromGreen", hf_from_green_factor);
    ADD_HF("particleData/fromBlue", hf_from_blue_factor);
    ADD_HF("particleData/toRed", hf_to_red_factor);
    ADD_HF("particleData/toGreen", hf_to_green_factor);
    ADD_HF("particleData/toBlue", hf_to_blue_factor);
    ADD_HF("particleData/positionType", hf_position_type);
    ADD_HF("particleData/entityId", hf_entity_id);
    ADD_HF("particleData/entityEyeHeight", hf_entity_eye_height);
    ADD_HF("particleData/destination", hf_destination);
    ADD_HF("particleData/ticks", hf_ticks);
    ADD_HF("particleData/delayInTicksBeforeShown", hf_delay_in_ticks_before_shown);
    ADD_HF("previousMessages/id", hf_id);
    ADD_HF("previousMessages/signature", hf_signature);
    ADD_HF("entityMetadataItem/pitch", hf_pitch_float);
    ADD_HF("entityMetadataItem/yaw", hf_yaw_float);
    ADD_HF("entityMetadataItem/roll", hf_roll_float);
    ADD_HF("villagerType", hf_villager_type);
    ADD_HF("villagerProfession", hf_villager_profession);
    ADD_HF("level", hf_level);
    ADD_HF("minecraft_simple_recipe_format/category", hf_category);
    ADD_HF("minecraft_smelting_format/group", hf_group);
    ADD_HF("minecraft_smelting_format/category", hf_category);
    ADD_HF("minecraft_smelting_format/experience", hf_experience);
    ADD_HF("minecraft_smelting_format/cookTime", hf_cook_time);
    ADD_HF("tags/tagName", hf_tag_name);
    ADD_HF("tags/entries", hf_tag_entry);
    ADD_HF("chunkBlockEntity/y", hf_i16_y);
    ADD_HF("chunkBlockEntity/type", hf_varint_type);
    ADD_HF("uuid", hf_uuid);
    ADD_HF("publicKey/expireTime", hf_expire_time);
    ADD_HF("publicKey/keyBytes", hf_key_bytes);
    ADD_HF("publicKey/keySignature", hf_signature);
    ADD_HF("game_profile/name", hf_name);
    ADD_HF("game_profile/properties/key", hf_key_string);
    ADD_HF("game_profile/properties/value", hf_value_string);
    ADD_HF("game_profile/properties/signature", hf_signature_string);
    ADD_HF("command_node/children", hf_children_int);
    ADD_HF("command_node/redirectNode", hf_redirect_node);
    ADD_HF("command_node/extraNodeData/name", hf_name);
    ADD_HF("command_node/extraNodeData/parser", hf_parser);
    ADD_HF("command_node/extraNodeData/suggestionType", hf_suggestion_type);
    ADD_HF("serverId", hf_server_id);
    ADD_HF("publicKey", hf_public_key);
    ADD_HF("verifyToken", hf_verify_token);
    ADD_HF("username", hf_user_name);
    ADD_HF("success/properties/key", hf_key_string);
    ADD_HF("success/properties/value", hf_value_string);
    ADD_HF("success/properties/signature", hf_signature_string);
    ADD_HF("compress/threshold", hf_threshold_int);
    ADD_HF("login_plugin_request/messageId", hf_message_id);
    ADD_HF("login_plugin_request/channel", hf_channel_str);
    ADD_HF("login_plugin_request/data", hf_data);
    ADD_HF("playerUUID", hf_uuid);
    ADD_HF("sharedSecret", hf_shared_secret);
    ADD_HF("login_plugin_response/messageId", hf_message_id);
    ADD_HF("login_plugin_response/data", hf_data);

    ADD_HF("chunkData", hf_chunk_data);

    // BITMASKS --------------------------------------------------------------------------------------------------------
    bitmask_hf_map_je = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    wmem_map_insert(bitmask_hf_map_je, g_strdup("[26]x[26]z[12]y"), positionXZY);
    ADD_HF("[26]x[26]z[12]y", hf_position_xzy);
    wmem_map_insert(bitmask_hf_map_je, g_strdup("[4]x[4]z"), positionXZ);
    ADD_HF("[4]x[4]z", hf_position_xz);
    wmem_map_insert(bitmask_hf_map_je,
                    g_strdup(
                            "[3]unused[1]has_custom_suggestions[1]has_redirect_node[1]has_command[2]command_node_type"),
                    command_flags);
    ADD_HF("[3]unused[1]has_custom_suggestions[1]has_redirect_node[1]has_command[2]command_node_type",
           hf_command_flags);
    wmem_map_insert(bitmask_hf_map_je, g_strdup("[6]unused[1]max_present[1]min_present"), command_arg_limit);
    ADD_HF("[6]unused[1]max_present[1]min_present", hf_command_arg_limit);
    wmem_map_insert(bitmask_hf_map_je, g_strdup("[6]unused[1]onlyAllowPlayers[1]onlyAllowEntities"),
                    command_arg_entity);
    ADD_HF("[6]unused[1]onlyAllowPlayers[1]onlyAllowEntities", hf_command_entity_arg);
    wmem_map_insert(bitmask_hf_map_je, g_strdup("[7]unused[1]allowMultiple"), command_arg_score_holder);
    ADD_HF("[7]unused[1]allowMultiple", hf_command_score_holder_arg);
    wmem_map_insert(bitmask_hf_map_je, g_strdup("[29]_unused[1]hidden[1]show_toast[1]has_background_texture"),
                    advancement_display);
    ADD_HF("[29]_unused[1]hidden[1]show_toast[1]has_background_texture", hf_advancement_flags);
    wmem_map_insert(bitmask_hf_map_je, g_strdup("[22]x[22]z[20]y"), chunk_coordinates);
    ADD_HF("[22]x[22]z[20]y", hf_chunk_coords);

    // Preference ------------------------------------------------------------------------------------------------------
    pref_mcje = prefs_register_protocol(proto_mcje, NULL);
    prefs_register_string_preference(pref_mcje, "ignore_packets", "Ignore Packets",
                                     "Ignore packets with the given names", (const char **) &pref_ignore_packets_je);

    init_je();
    init_je_constants();
}