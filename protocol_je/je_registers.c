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
int hf_rotation_f32 = -1;
int hf_id = -1;
int hf_signature = -1;
int hf_id_u8 = -1;
int hf_type_string = -1;
int hf_byte = -1;
int hf_int = -1;
int hf_long = -1;
int hf_float = -1;
int hf_string = -1;
int hf_component = -1;
int hf_boolean = -1;
int hf_pitch_float = -1;
int hf_yaw_float = -1;
int hf_roll_float = -1;
int hf_direction = -1;
int hf_villager_type = -1;
int hf_villager_profession = -1;
int hf_level = -1;
int hf_uint = -1;
int hf_pose = -1;
int hf_cat_variant = -1;
int hf_frog_variant = -1;
int hf_global_pos = -1;
int hf_painting_variant = -1;
int hf_sniffer_state = -1;
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
int hf_properties = -1;
int hf_registry = -1;
int hf_min = -1;
int hf_max = -1;
int hf_min_i64 = -1;
int hf_max_i64 = -1;
int hf_min_f32 = -1;
int hf_max_f32 = -1;
int hf_min_f64 = -1;
int hf_max_f64 = -1;
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
int hf_pitch_i8 = -1;
int hf_yaw_i8 = -1;
int hf_head_pitch_i8 = -1;
int hf_chunk_data = -1;
int hf_object_data = -1;
int hf_vx_i16 = -1;
int hf_vy_i16 = -1;
int hf_vz_i16 = -1;
int hf_count = -1;
int hf_animation = -1;
int hf_category_id = -1;
int hf_stat_id = -1;
int hf_value = -1;
int hf_reset = -1;
int hf_parent_id_string = -1;
int hf_title = -1;
int hf_desc = -1;
int hf_frame_type = -1;
int hf_background_texture = -1;
int hf_send_telemetry_data = -1;
int hf_id_string = -1;
int hf_criterion_id = -1;
int hf_criterion_progress = -1;
int hf_destroy_stage = -1;
int hf_action = -1;
int hf_byte1 = -1;
int hf_byte2 = -1;
int hf_block_id = -1;
int hf_health = -1;
int hf_color = -1;
int hf_dividers = -1;
int hf_flags = -1;
int hf_difficulty = -1;
int hf_difficulty_locked = -1;
int hf_transaction_id = -1;
int hf_completion_start = -1;
int hf_length = -1;
int hf_match = -1;
int hf_tooltip = -1;
int hf_root_index = -1;
int hf_feet_eyes = -1;
int hf_is_entity = -1;
int hf_entity_feet_eyes = -1;
int hf_window_id = -1;
int hf_inventory_type = -1;
int hf_state_id = -1;
int hf_property_i16 = -1;
int hf_value_i16 = -1;
int hf_slot = -1;
int hf_cooldown_ticks = -1;
int hf_message = -1;
int hf_type = -1;
int hf_target = -1;
int hf_entity_id_i32 = -1;
int hf_entity_status = -1;
int hf_radius = -1;
int hf_i8_x = -1;
int hf_i8_y = -1;
int hf_i8_z = -1;
int hf_player_motion_x = -1;
int hf_player_motion_y = -1;
int hf_player_motion_z = -1;
int hf_chunk_x = -1;
int hf_chunk_z = -1;
int hf_event = -1;
int hf_event_param = -1;
int hf_nb_slots = -1;
int hf_keep_alive_id = -1;
int hf_i32_x = -1;
int hf_i32_z = -1;
int hf_heightmaps = -1;
int hf_sky_light_mask = -1;
int hf_block_light_mask = -1;
int hf_empty_sky_light_mask = -1;
int hf_empty_block_light_mask = -1;
int hf_skylight = -1;
int hf_blocklight = -1;
int hf_type_i32 = -1;
int hf_data_i32 = -1;
int hf_global = -1;
int hf_long_distance = -1;
int hf_offset_x = -1;
int hf_offset_y = -1;
int hf_offset_z = -1;
int hf_particle_data = -1;
int hf_particles = -1;
int hf_is_hardcore = -1;
int hf_gamemode = -1;
int hf_previous_gamemode = -1;
int hf_world_names = -1;
int hf_dimension_codec = -1;
int hf_world_type = -1;
int hf_world_name = -1;
int hf_hashed_seed = -1;
int hf_max_players = -1;
int hf_view_distance = -1;
int hf_simulation_distance = -1;
int hf_reduced_debug_info = -1;
int hf_enable_respawn_screen = -1;
int hf_is_debug = -1;
int hf_is_flat = -1;
int hf_dimension_name = -1;
int hf_portal_cooldown = -1;
int hf_map_id = -1;
int hf_scale_i8 = -1;
int hf_locked = -1;
int hf_columns = -1;
int hf_rows = -1;
int hf_u8_x = -1;
int hf_u8_y = -1;
int hf_trade_disabled = -1;
int hf_nb_trade_uses = -1;
int hf_max_nb_trade_uses = -1;
int hf_xp = -1;
int hf_special_price = -1;
int hf_price_multiplier = -1;
int hf_demand = -1;
int hf_experience_uint = -1;
int hf_is_regular_villager = -1;
int hf_can_restock = -1;
int hf_dx = -1;
int hf_dy = -1;
int hf_dz = -1;
int hf_on_ground = -1;
int hf_hand = -1;
int hf_is_front_text = -1;
int hf_recipe = -1;
int hf_flying_speed = -1;
int hf_walking_speed = -1;
int hf_index_uint = -1;
int hf_plain_message = -1;
int hf_timestamp = -1;
int hf_salt = -1;
int hf_unsigned_chat_content = -1;
int hf_filter_type = -1;
int hf_network_name = -1;
int hf_network_target_name = -1;
int hf_duration = -1;
int hf_player_id = -1;
int hf_action_i8 = -1;
int hf_listed = -1;
int hf_latency = -1;
int hf_flags_i8 = -1;
int hf_teleport_id = -1;
int hf_crafting_book_open = -1;
int hf_filtering_craftable = -1;
int hf_smelting_book_open = -1;
int hf_filtering_smeltable = -1;
int hf_blast_furnace_open = -1;
int hf_filtering_blast_furnace = -1;
int hf_smoker_book_open = -1;
int hf_filtering_smoker = -1;
int hf_effect_id = -1;
int hf_url = -1;
int hf_hash = -1;
int hf_forced = -1;
int hf_prompt_message = -1;
int hf_copy_metadata = -1;
int hf_head_yaw = -1;
int hf_camera_id = -1;
int hf_chunk_x_uint = -1;
int hf_chunk_z_uint = -1;
int hf_position_i8 = -1;
int hf_vehicle_id = -1;
int hf_experience_bar = -1;
int hf_total_experience = -1;
int hf_food = -1;
int hf_food_saturation = -1;
int hf_display_text = -1;
int hf_team = -1;
int hf_mode = -1;
int hf_friendly_fire = -1;
int hf_name_tag_visibility = -1;
int hf_collision_rule = -1;
int hf_formatting = -1;
int hf_prefix = -1;
int hf_suffix = -1;
int hf_item_name = -1;
int hf_score_name = -1;
int hf_angle = -1;
int hf_age = -1;
int hf_time = -1;
int hf_sound_id = -1;
int hf_resource = -1;
int hf_range = -1;
int hf_sound_category = -1;
int hf_volume = -1;
int hf_pitch_sound = -1;
int hf_seed = -1;
int hf_source = -1;
int hf_sound = -1;
int hf_i32_y = -1;
int hf_content = -1;
int hf_is_action_bar = -1;
int hf_header = -1;
int hf_footer = -1;
int hf_collected_entity_id = -1;
int hf_collector_entity_id = -1;
int hf_pickup_item_count = -1;
int hf_value_f64 = -1;
int hf_amount = -1;
int hf_operation = -1;
int hf_amplifier = -1;
int hf_hide_particles = -1;
int hf_factor_codec = -1;
int hf_motd = -1;
int hf_icon_bytes = -1;
int hf_enforces_secure_chat = -1;
int hf_recipe_id = -1;
int hf_width = -1;
int hf_height = -1;
int hf_show_notification = -1;
int hf_tag_type = -1;
int hf_sequence_id = -1;
int hf_old_diameter = -1;
int hf_new_diameter = -1;
int hf_speed = -1;
int hf_portal_teleport_boundary = -1;
int hf_warning_blocks = -1;
int hf_warning_time = -1;
int hf_id_i32 = -1;
int hf_text = -1;
int hf_diameter = -1;
int hf_fade_in = -1;
int hf_stay = -1;
int hf_fade_out = -1;
int hf_source_type_id = -1;
int hf_source_cause_id = -1;
int hf_source_direct_id = -1;
int hf_command = -1;
int hf_argument_name = -1;
int hf_message_count = -1;
int hf_acknowledged = -1;
int hf_offset = -1;
int hf_count_uint = -1;
int hf_primary_effect = -1;
int hf_secondary_effect = -1;
int hf_track_output = -1;
int hf_offset_x_int = -1;
int hf_offset_y_int = -1;
int hf_offset_z_int = -1;
int hf_size_x = -1;
int hf_size_y = -1;
int hf_size_z = -1;
int hf_mirror = -1;
int hf_rotation = -1;
int hf_metadata = -1;
int hf_integrity = -1;
int hf_seed_uint = -1;
int hf_action_id = -1;
int hf_locale = -1;
int hf_view_distance_int = -1;
int hf_chat_flags = -1;
int hf_chat_color = -1;
int hf_skin_parts = -1;
int hf_main_hand = -1;
int hf_enable_text_filtering = -1;
int hf_enable_server_listing = -1;
int hf_window_id_i8 = -1;
int hf_enchantment = -1;
int hf_mouse_button = -1;
int hf_location = -1;
int hf_target_uint = -1;
int hf_mouse = -1;
int hf_sneaking = -1;
int hf_levels = -1;
int hf_keep_jigsaws = -1;
int hf_left_paddle = -1;
int hf_right_paddle = -1;
int hf_make_all = -1;
int hf_status = -1;
int hf_face = -1;
int hf_jump_boost = -1;
int hf_sideways = -1;
int hf_forward = -1;
int hf_jump = -1;
int hf_book_id = -1;
int hf_book_open = -1;
int hf_filter_active = -1;
int hf_result = -1;
int hf_pool = -1;
int hf_final_state = -1;
int hf_joint_type = -1;
int hf_text_1 = -1;
int hf_text_2 = -1;
int hf_text_3 = -1;
int hf_text_4 = -1;
int hf_cursor_x = -1;
int hf_cursor_y = -1;
int hf_cursor_z = -1;
int hf_inside_block = -1;
int hf_tab_id = -1;
// --------------------
int hf_killer_id = -1;
// --------------------
int hf_x_26 = -1;
int hf_z_26 = -1;
int hf_y_12 = -1;
int hf_x_4 = -1;
int hf_z_4 = -1;
int hf_has_custom_suggestions_1 = -1;
int hf_has_redirect_node_1 = -1;
int hf_has_command_1 = -1;
int hf_command_node_type_2 = -1;
int hf_max_present_1 = -1;
int hf_min_present_1 = -1;
int hf_only_allow_players_1 = -1;
int hf_only_allow_entities_1 = -1;
int hf_allow_multiple_1 = -1;
int hf_hidden_1 = -1;
int hf_show_toast_1 = -1;
int hf_has_background_texture_1 = -1;
int hf_x_22 = -1;
int hf_z_22 = -1;
int hf_y_20 = -1;
// --------------------
int *positionXZY[] = {&hf_x_26, &hf_z_26, &hf_y_12};
int *positionXZ[] = {&hf_x_4, &hf_z_4};
int *command_flags[] = {NULL, &hf_has_custom_suggestions_1, &hf_has_redirect_node_1,
                        &hf_has_command_1, &hf_command_node_type_2};
int *command_arg_limit[] = {NULL, &hf_max_present_1, &hf_min_present_1};
int *command_arg_entity[] = {NULL, &hf_only_allow_players_1, &hf_only_allow_entities_1};
int *command_arg_score_holder[] = {NULL, &hf_allow_multiple_1};
int *advancement_display[] = {NULL, &hf_hidden_1, &hf_show_toast_1, &hf_has_background_texture_1};
int *chunk_coordinates[] = {&hf_x_22, &hf_z_22, &hf_y_20};
// --------------------
true_false_string tf_string[] = {
        {"true", "false"},
};
value_string command_node_string[] = {
        {0, "root"},
        {1, "literal"},
        {2, "argument"},
        {0, NULL}
};

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
            DEFINE_HF(hf_rotation_f32, "Rotation", "mcje.rotation", FLOAT, DEC)
            DEFINE_HF(hf_id, "ID", "mcje.id", UINT32, DEC)
            DEFINE_HF(hf_signature, "Signature", "mcje.signature", BYTES, NONE)
            DEFINE_HF(hf_id_u8, "ID", "mcje.id", UINT8, DEC)
            DEFINE_HF(hf_type_string, "Type", "mcje.type", STRING, NONE)
            DEFINE_HF(hf_byte, "Byte", "mcje.byte", INT8, DEC)
            DEFINE_HF(hf_int, "Integer", "mcje.int", UINT32, DEC)
            DEFINE_HF(hf_long, "Long Integer", "mcje.long", INT64, DEC)
            DEFINE_HF(hf_float, "Float", "mcje.float", FLOAT, DEC)
            DEFINE_HF(hf_string, "String", "mcje.string", STRING, NONE)
            DEFINE_HF(hf_component, "Component", "mcje.component", STRING, NONE)
            DEFINE_HF(hf_boolean, "Boolean", "mcje.boolean", BOOLEAN, NONE)
            DEFINE_HF(hf_direction, "Direction", "mcje.direction", UINT32, DEC)
            DEFINE_HF(hf_pitch_float, "Pitch", "mcje.pitch", FLOAT, DEC)
            DEFINE_HF(hf_yaw_float, "Yaw", "mcje.yaw", FLOAT, DEC)
            DEFINE_HF(hf_roll_float, "Roll", "mcje.roll", FLOAT, DEC)
            DEFINE_HF(hf_villager_type, "Villager Type", "mcje.villager_type", UINT32, DEC)
            DEFINE_HF(hf_villager_profession, "Villager Profession", "mcje.villager_profession", UINT32, DEC)
            DEFINE_HF(hf_level, "Level", "mcje.level", UINT32, DEC)
            DEFINE_HF(hf_uint, "Unsigned Integer", "mcje.uint", UINT32, DEC)
            DEFINE_HF(hf_pose, "Pose", "mcje.pose", UINT32, DEC)
            DEFINE_HF(hf_cat_variant, "Cat Variant", "mcje.cat_variant", UINT32, DEC)
            DEFINE_HF(hf_frog_variant, "Frog Variant", "mcje.frog_variant", UINT32, DEC)
            DEFINE_HF(hf_global_pos, "Global Position", "mcje.global_pos", STRING, NONE)
            DEFINE_HF(hf_painting_variant, "Painting Variant", "mcje.painting_variant", UINT32, DEC)
            DEFINE_HF(hf_sniffer_state, "Sniffer State", "mcje.sniffer_state", UINT32, DEC)
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
            DEFINE_HF(hf_properties, "Properties", "mcje.properties", STRING, NONE)
            DEFINE_HF(hf_registry, "Registry", "mcje.registry", STRING, NONE)
            DEFINE_HF(hf_min, "Min", "mcje.min", INT32, DEC)
            DEFINE_HF(hf_max, "Max", "mcje.max", INT32, DEC)
            DEFINE_HF(hf_min_i64, "Min", "mcje.min_i64", INT64, DEC)
            DEFINE_HF(hf_max_i64, "Max", "mcje.max_i64", INT64, DEC)
            DEFINE_HF(hf_min_f32, "Min", "mcje.min_f32", FLOAT, DEC)
            DEFINE_HF(hf_max_f32, "Max", "mcje.max_f32", FLOAT, DEC)
            DEFINE_HF(hf_min_f64, "Min", "mcje.min_f64", DOUBLE, DEC)
            DEFINE_HF(hf_max_f64, "Max", "mcje.max_f64", DOUBLE, DEC)
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
            DEFINE_HF(hf_pitch_i8, "Pitch", "mcje.pitch_i8", INT8, DEC)
            DEFINE_HF(hf_yaw_i8, "Yaw", "mcje.yaw_i8", INT8, DEC)
            DEFINE_HF(hf_head_pitch_i8, "Head Pitch", "mcje.head_pitch_i8", INT8, DEC)
            DEFINE_HF(hf_object_data, "Object Data", "mcje.object_data", UINT32, DEC)
            DEFINE_HF(hf_vx_i16, "Velocity X", "mcje.vx_i16", INT16, DEC)
            DEFINE_HF(hf_vy_i16, "Velocity Y", "mcje.vy_i16", INT16, DEC)
            DEFINE_HF(hf_vz_i16, "Velocity Z", "mcje.vz_i16", INT16, DEC)
            DEFINE_HF(hf_count, "Count", "mcje.count", INT16, DEC)
            DEFINE_HF(hf_animation, "Animation", "mcje.animation", UINT8, DEC)
            DEFINE_HF(hf_category_id, "Category ID", "mcje.category_id", UINT32, DEC)
            DEFINE_HF(hf_stat_id, "Statistic ID", "mcje.stat_id", UINT32, DEC)
            DEFINE_HF(hf_value, "Value", "mcje.value", UINT32, DEC)
            DEFINE_HF(hf_reset, "Reset", "mcje.reset", BOOLEAN, DEC)
            DEFINE_HF(hf_parent_id_string, "Parent ID", "mcje.parent_id_string", STRING, NONE)
            DEFINE_HF(hf_title, "Title", "mcje.title", STRING, NONE)
            DEFINE_HF(hf_desc, "Description", "mcje.desc", STRING, NONE)
            DEFINE_HF(hf_frame_type, "Frame Type", "mcje.frame_type", UINT32, DEC)
            DEFINE_HF(hf_background_texture, "Background Texture", "mcje.background_texture", STRING, NONE)
            DEFINE_HF(hf_send_telemetry_data, "Send Telemetry Data", "mcje.send_telemetry_data", BOOLEAN, DEC)
            DEFINE_HF(hf_id_string, "ID", "mcje.id_string", STRING, NONE)
            DEFINE_HF(hf_criterion_id, "Criterion ID", "mcje.criterion_id", STRING, NONE)
            DEFINE_HF(hf_criterion_progress, "Criterion Progress", "mcje.criterion_progress", INT64, DEC)
            DEFINE_HF(hf_destroy_stage, "Destroy Stage", "mcje.destroy_stage", INT8, DEC)
            DEFINE_HF(hf_action, "Action", "mcje.action", UINT32, DEC)
            DEFINE_HF(hf_byte1, "Byte 1", "mcje.byte1", UINT8, DEC)
            DEFINE_HF(hf_byte2, "Byte 2", "mcje.byte2", UINT8, DEC)
            DEFINE_HF(hf_block_id, "Block ID", "mcje.block_id", UINT32, DEC)
            DEFINE_HF(hf_health, "Health", "mcje.health", FLOAT, DEC)
            DEFINE_HF(hf_color, "Color", "mcje.color", UINT32, DEC)
            DEFINE_HF(hf_dividers, "Dividers", "mcje.dividers", UINT32, DEC)
            DEFINE_HF(hf_flags, "Flags", "mcje.flags", UINT8, DEC)
            DEFINE_HF(hf_difficulty, "Difficulty", "mcje.difficulty", UINT8, DEC)
            DEFINE_HF(hf_difficulty_locked, "Difficulty Locked", "mcje.difficulty_locked", BOOLEAN, DEC)
            DEFINE_HF(hf_transaction_id, "Transaction ID", "mcje.transaction_id", UINT32, DEC)
            DEFINE_HF(hf_completion_start, "Completion Start", "mcje.completion_start", UINT32, DEC)
            DEFINE_HF(hf_length, "Length", "mcje.length", UINT32, DEC)
            DEFINE_HF(hf_match, "Match", "mcje.match", STRING, NONE)
            DEFINE_HF(hf_tooltip, "Tooltip", "mcje.tooltip", STRING, NONE)
            DEFINE_HF(hf_root_index, "Root Index", "mcje.root_index", UINT32, DEC)
            DEFINE_HF(hf_feet_eyes, "Feet Eyes", "mcje.feet_eyes", UINT32, DEC)
            DEFINE_HF(hf_is_entity, "Is Entity", "mcje.is_entity", BOOLEAN, DEC)
            DEFINE_HF(hf_entity_feet_eyes, "Entity Feet Eyes", "mcje.entity_feet_eyes", STRING, NONE)
            DEFINE_HF(hf_window_id, "Window ID", "mcje.window_id", UINT32, DEC)
            DEFINE_HF(hf_inventory_type, "Inventory Type", "mcje.inventory_type", UINT32, DEC)
            DEFINE_HF(hf_state_id, "State ID", "mcje.state_id", UINT32, DEC)
            DEFINE_HF(hf_property_i16, "Property", "mcje.property_i16", INT16, DEC)
            DEFINE_HF(hf_value_i16, "Value", "mcje.value_i16", INT16, DEC)
            DEFINE_HF(hf_slot, "Slot", "mcje.slot", INT16, DEC)
            DEFINE_HF(hf_cooldown_ticks, "Cooldown Ticks", "mcje.cooldown_ticks", UINT32, DEC)
            DEFINE_HF(hf_message, "Message", "mcje.message", STRING, NONE)
            DEFINE_HF(hf_type, "Type", "mcje.type", UINT32, DEC)
            DEFINE_HF(hf_target, "Target", "mcje.target", STRING, NONE)
            DEFINE_HF(hf_entity_id_i32, "Entity ID", "mcje.entity_id_i32", INT32, DEC)
            DEFINE_HF(hf_entity_status, "Entity Status", "mcje.entity_status", INT8, DEC)
            DEFINE_HF(hf_radius, "Radius", "mcje.radius", FLOAT, DEC)
            DEFINE_HF(hf_i8_x, "X", "mcje.x_i8", INT8, DEC)
            DEFINE_HF(hf_i8_y, "Y", "mcje.y_i8", INT8, DEC)
            DEFINE_HF(hf_i8_z, "Z", "mcje.z_i8", INT8, DEC)
            DEFINE_HF(hf_player_motion_x, "Player Motion X", "mcje.player_motion_x", FLOAT, DEC)
            DEFINE_HF(hf_player_motion_y, "Player Motion Y", "mcje.player_motion_y", FLOAT, DEC)
            DEFINE_HF(hf_player_motion_z, "Player Motion Z", "mcje.player_motion_z", FLOAT, DEC)
            DEFINE_HF(hf_chunk_x, "Chunk X", "mcje.chunk_x", INT32, DEC)
            DEFINE_HF(hf_chunk_z, "Chunk Z", "mcje.chunk_z", INT32, DEC)
            DEFINE_HF(hf_event, "Event", "mcje.event", UINT8, DEC)
            DEFINE_HF(hf_event_param, "Event Param", "mcje.event_param", FLOAT, DEC)
            DEFINE_HF(hf_nb_slots, "Slot Count", "mcje.nb_slots", UINT32, DEC)
            DEFINE_HF(hf_keep_alive_id, "Keep Alive ID", "mcje.keep_alive_id", INT64, DEC)
            DEFINE_HF(hf_i32_x, "X", "mcje.x_i32", INT32, DEC)
            DEFINE_HF(hf_i32_z, "Z", "mcje.z_i32", INT32, DEC)
            DEFINE_HF(hf_heightmaps, "Heightmaps", "mcje.heightmaps", BYTES, NONE)
            DEFINE_HF(hf_chunk_data, "Chunk Data", "mcje.chunk_data", BYTES, NONE)
            DEFINE_HF(hf_sky_light_mask, "Sky Light Mask", "mcje.sky_light_mask", INT64, DEC)
            DEFINE_HF(hf_block_light_mask, "Block Light Mask", "mcje.block_light_mask", INT64, DEC)
            DEFINE_HF(hf_empty_sky_light_mask, "Empty Sky Light Mask", "mcje.empty_sky_light_mask", INT64, DEC)
            DEFINE_HF(hf_empty_block_light_mask, "Empty Block Light Mask", "mcje.empty_block_light_mask", INT64, DEC)
            DEFINE_HF(hf_skylight, "Sky Light", "mcje.skylight", UINT8, DEC)
            DEFINE_HF(hf_blocklight, "Block Light", "mcje.blocklight", UINT8, DEC)
            DEFINE_HF(hf_type_i32, "Type", "mcje.type_i32", INT32, DEC)
            DEFINE_HF(hf_data_i32, "Data", "mcje.data_i32", INT32, DEC)
            DEFINE_HF(hf_global, "Global", "mcje.global", BOOLEAN, NONE)
            DEFINE_HF(hf_long_distance, "Look Distance", "mcje.look_distance", BOOLEAN, NONE)
            DEFINE_HF(hf_offset_x, "Offset X", "mcje.offset_x", FLOAT, DEC)
            DEFINE_HF(hf_offset_y, "Offset Y", "mcje.offset_y", FLOAT, DEC)
            DEFINE_HF(hf_offset_z, "Offset Z", "mcje.offset_z", FLOAT, DEC)
            DEFINE_HF(hf_particle_data, "Particle Data", "mcje.particle_data", FLOAT, DEC)
            DEFINE_HF(hf_particles, "Particles", "mcje.particles", INT32, DEC)
            DEFINE_HF(hf_is_hardcore, "Is Hardcore", "mcje.is_hardcore", BOOLEAN, NONE)
            DEFINE_HF(hf_gamemode, "Game Mode", "mcje.gamemode", UINT8, DEC)
            DEFINE_HF(hf_previous_gamemode, "Previous Game Mode", "mcje.previous_gamemode", INT8, DEC)
            DEFINE_HF(hf_world_names, "World Names", "mcje.world_names", STRING, NONE)
            DEFINE_HF(hf_dimension_codec, "Dimension Codec", "mcje.dimension_codec", BYTES, NONE)
            DEFINE_HF(hf_world_type, "World Type", "mcje.world_type", STRING, NONE)
            DEFINE_HF(hf_world_name, "World Name", "mcje.world_name", STRING, NONE)
            DEFINE_HF(hf_hashed_seed, "Hashed Seed", "mcje.hashed_seed", INT64, DEC)
            DEFINE_HF(hf_max_players, "Max Players", "mcje.max_players", UINT32, DEC)
            DEFINE_HF(hf_view_distance, "View Distance", "mcje.view_distance", UINT32, DEC)
            DEFINE_HF(hf_simulation_distance, "Simulation Distance", "mcje.simulation_distance", UINT32, DEC)
            DEFINE_HF(hf_reduced_debug_info, "Reduced Debug Info", "mcje.reduced_debug_info", BOOLEAN, NONE)
            DEFINE_HF(hf_enable_respawn_screen, "Enable Respawn Screen", "mcje.enable_respawn_screen", BOOLEAN, NONE)
            DEFINE_HF(hf_is_debug, "Is Debug", "mcje.is_debug", BOOLEAN, NONE)
            DEFINE_HF(hf_is_flat, "Is Flat", "mcje.is_flat", BOOLEAN, NONE)
            DEFINE_HF(hf_dimension_name, "Dimension Name", "mcje.dimension_name", STRING, NONE)
            DEFINE_HF(hf_portal_cooldown, "Portal Cooldown", "mcje.portal_cooldown", UINT32, DEC)
            DEFINE_HF(hf_map_id, "Map ID", "mcje.map_id", UINT32, DEC)
            DEFINE_HF(hf_scale_i8, "Scale", "mcje.scale_i8", INT8, DEC)
            DEFINE_HF(hf_locked, "Locked", "mcje.locked", BOOLEAN, NONE)
            DEFINE_HF(hf_columns, "Columns", "mcje.columns", UINT8, DEC)
            DEFINE_HF(hf_rows, "Rows", "mcje.rows", UINT8, DEC)
            DEFINE_HF(hf_u8_x, "X", "mcje.x_u8", UINT8, DEC)
            DEFINE_HF(hf_u8_y, "Y", "mcje.y_u8", UINT8, DEC)
            DEFINE_HF(hf_trade_disabled, "Trade Disabled", "mcje.trade_disabled", BOOLEAN, NONE)
            DEFINE_HF(hf_nb_trade_uses, "Trade Uses", "mcje.nb_trade_uses", INT32, DEC)
            DEFINE_HF(hf_max_nb_trade_uses, "Max Trade Uses", "mcje.max_nb_trade_uses", INT32, DEC)
            DEFINE_HF(hf_xp, "XP", "mcje.xp", INT32, DEC)
            DEFINE_HF(hf_special_price, "Special Price", "mcje.special_price", INT32, DEC)
            DEFINE_HF(hf_price_multiplier, "Price Multiplier", "mcje.price_multiplier", FLOAT, DEC)
            DEFINE_HF(hf_demand, "Demand", "mcje.demand", INT32, DEC)
            DEFINE_HF(hf_experience_uint, "Experience", "mcje.experience_uint", UINT32, DEC)
            DEFINE_HF(hf_is_regular_villager, "Is Regular Villager", "mcje.is_regular_villager", BOOLEAN, NONE)
            DEFINE_HF(hf_can_restock, "Can Restock", "mcje.can_restock", BOOLEAN, NONE)
            DEFINE_HF(hf_dx, "Delta X", "mcje.dx", INT16, DEC)
            DEFINE_HF(hf_dy, "Delta Y", "mcje.dy", INT16, DEC)
            DEFINE_HF(hf_dz, "Delta Z", "mcje.dz", INT16, DEC)
            DEFINE_HF(hf_on_ground, "On Ground", "mcje.on_ground", BOOLEAN, NONE)
            DEFINE_HF(hf_hand, "Hand", "mcje.hand", UINT32, DEC)
            DEFINE_HF(hf_is_front_text, "Is Front Text", "mcje.is_front_text", BOOLEAN, NONE)
            DEFINE_HF(hf_recipe, "Recipe", "mcje.recipe", STRING, NONE)
            DEFINE_HF(hf_flying_speed, "Flying Speed", "mcje.flying_speed", FLOAT, DEC)
            DEFINE_HF(hf_walking_speed, "Walking Speed", "mcje.walking_speed", FLOAT, DEC)
            DEFINE_HF(hf_index_uint, "Index", "mcje.index_uint", UINT32, DEC)
            DEFINE_HF(hf_plain_message, "Plain Message", "mcje.plain_message", STRING, NONE)
            DEFINE_HF(hf_timestamp, "Timestamp", "mcje.timestamp", INT64, DEC)
            DEFINE_HF(hf_salt, "Salt", "mcje.salt", INT64, DEC)
            DEFINE_HF(hf_unsigned_chat_content, "Unsigned Chat Content", "mcje.unsigned_chat_content", STRING, NONE)
            DEFINE_HF(hf_filter_type, "Filter Type", "mcje.filter_type", UINT32, DEC)
            DEFINE_HF(hf_network_name, "Network Name", "mcje.network_name", STRING, NONE)
            DEFINE_HF(hf_network_target_name, "Network Target Name", "mcje.network_target_name", STRING, NONE)
            DEFINE_HF(hf_duration, "Duration", "mcje.duration", UINT32, DEC)
            DEFINE_HF(hf_player_id, "Player ID", "mcje.player_id", UINT32, DEC)
            DEFINE_HF(hf_action_i8, "Action", "mcje.action_i8", INT8, DEC)
            DEFINE_HF(hf_listed, "Listed", "mcje.listed", BOOLEAN, NONE)
            DEFINE_HF(hf_latency, "Latency", "mcje.latency", UINT32, DEC)
            DEFINE_HF(hf_flags_i8, "Flags", "mcje.flags_i8", INT8, DEC)
            DEFINE_HF(hf_teleport_id, "Teleport ID", "mcje.teleport_id", UINT32, DEC)
            DEFINE_HF(hf_crafting_book_open, "Crafting Book Open", "mcje.crafting_book_open", BOOLEAN, NONE)
            DEFINE_HF(hf_filtering_craftable, "Filtering Craftable", "mcje.filtering_craftable", BOOLEAN, NONE)
            DEFINE_HF(hf_smelting_book_open, "Smelting Book Open", "mcje.smelting_book_open", BOOLEAN, NONE)
            DEFINE_HF(hf_filtering_smeltable, "Filtering Smeltable", "mcje.filtering_smeltable", BOOLEAN, NONE)
            DEFINE_HF(hf_blast_furnace_open, "Blasting Furnace Open", "mcje.blasting_furnace_open", BOOLEAN, NONE)
            DEFINE_HF(hf_filtering_blast_furnace, "Filtering Blast Furnace", "mcje.filtering_blast_furnace", BOOLEAN,
                      NONE)
            DEFINE_HF(hf_smoker_book_open, "Smoker Book Open", "mcje.smoker_book_open", BOOLEAN, NONE)
            DEFINE_HF(hf_filtering_smoker, "Filtering Smoker", "mcje.filtering_smoker", BOOLEAN, NONE)
            DEFINE_HF(hf_effect_id, "Effect ID", "mcje.effect_id", UINT32, DEC)
            DEFINE_HF(hf_url, "URL", "mcje.url", STRING, NONE)
            DEFINE_HF(hf_hash, "Hash", "mcje.hash", STRING, NONE)
            DEFINE_HF(hf_forced, "Forced", "mcje.forced", BOOLEAN, NONE)
            DEFINE_HF(hf_prompt_message, "Prompt Message", "mcje.prompt_message", STRING, NONE)
            DEFINE_HF(hf_copy_metadata, "Copy Metadata", "mcje.copy_metadata", BOOLEAN, NONE)
            DEFINE_HF(hf_head_yaw, "Head Yaw", "mcje.head_yaw", INT8, DEC)
            DEFINE_HF(hf_camera_id, "Camera ID", "mcje.camera_id", UINT32, DEC)
            DEFINE_HF(hf_chunk_x_uint, "Chunk X", "mcje.chunk_x_uint", UINT32, DEC)
            DEFINE_HF(hf_chunk_z_uint, "Chunk Z", "mcje.chunk_z_uint", UINT32, DEC)
            DEFINE_HF(hf_position_i8, "Position", "mcje.position_i8", INT8, DEC)
            DEFINE_HF(hf_vehicle_id, "Vehicle ID", "mcje.vehicle_id", INT32, DEC)
            DEFINE_HF(hf_experience_bar, "Experience Bar", "mcje.experience_bar", FLOAT, DEC)
            DEFINE_HF(hf_total_experience, "Total Experience", "mcje.total_experience", UINT32, DEC)
            DEFINE_HF(hf_food, "Food", "mcje.food", UINT32, DEC)
            DEFINE_HF(hf_food_saturation, "Food Saturation", "mcje.food_saturation", FLOAT, DEC)
            DEFINE_HF(hf_display_text, "Display Text", "mcje.display_text", STRING, NONE)
            DEFINE_HF(hf_team, "Team", "mcje.team", STRING, NONE)
            DEFINE_HF(hf_mode, "Mode", "mcje.mode", UINT32, DEC)
            DEFINE_HF(hf_friendly_fire, "Friendly Fire", "mcje.friendly_fire", UINT8, DEC)
            DEFINE_HF(hf_name_tag_visibility, "Name Tag Visibility", "mcje.name_tag_visibility", STRING, NONE)
            DEFINE_HF(hf_collision_rule, "Collision Rule", "mcje.collision_rule", STRING, NONE)
            DEFINE_HF(hf_formatting, "Formatting", "mcje.formatting", UINT32, DEC)
            DEFINE_HF(hf_prefix, "Prefix", "mcje.prefix", STRING, NONE)
            DEFINE_HF(hf_suffix, "Suffix", "mcje.suffix", STRING, NONE)
            DEFINE_HF(hf_item_name, "Item Name", "mcje.item_name", STRING, NONE)
            DEFINE_HF(hf_score_name, "Score Name", "mcje.score_name", STRING, NONE)
            DEFINE_HF(hf_angle, "Angle", "mcje.angle", FLOAT, DEC)
            DEFINE_HF(hf_age, "Age", "mcje.age", INT64, DEC)
            DEFINE_HF(hf_time, "Time", "mcje.time", INT64, DEC)
            DEFINE_HF(hf_sound_id, "Sound ID", "mcje.sound_id", UINT32, DEC)
            DEFINE_HF(hf_resource, "Resource", "mcje.resource", STRING, NONE)
            DEFINE_HF(hf_range, "Range", "mcje.range", FLOAT, DEC)
            DEFINE_HF(hf_sound_category, "Sound Category", "mcje.sound_category", UINT32, DEC)
            DEFINE_HF(hf_volume, "Volume", "mcje.volume", FLOAT, DEC)
            DEFINE_HF(hf_pitch_sound, "Pitch", "mcje.pitch_sound", FLOAT, DEC)
            DEFINE_HF(hf_seed, "Seed", "mcje.seed", INT64, DEC)
            DEFINE_HF(hf_source, "Source", "mcje.source", UINT32, DEC)
            DEFINE_HF(hf_sound, "Sound", "mcje.sound", STRING, NONE)
            DEFINE_HF(hf_i32_y, "Y", "mcje.i32_y", INT32, DEC)
            DEFINE_HF(hf_content, "Content", "mcje.content", STRING, NONE)
            DEFINE_HF(hf_is_action_bar, "Is Action Bar", "mcje.is_action_bar", BOOLEAN, NONE)
            DEFINE_HF(hf_header, "Header", "mcje.header", STRING, NONE)
            DEFINE_HF(hf_footer, "Footer", "mcje.footer", STRING, NONE)
            DEFINE_HF(hf_collected_entity_id, "Collected Entity ID", "mcje.collected_entity_id", UINT32, DEC)
            DEFINE_HF(hf_collector_entity_id, "Collector Entity ID", "mcje.collector_entity_id", UINT32, DEC)
            DEFINE_HF(hf_pickup_item_count, "Pickup Item Count", "mcje.pickup_item_count", UINT32, DEC)
            DEFINE_HF(hf_value_f64, "Value", "mcje.value_f64", DOUBLE, DEC)
            DEFINE_HF(hf_amount, "Amount", "mcje.amount", DOUBLE, DEC)
            DEFINE_HF(hf_operation, "Operation", "mcje.operation", INT8, DEC)
            DEFINE_HF(hf_amplifier, "Amplifier", "mcje.amplifier", INT8, DEC)
            DEFINE_HF(hf_hide_particles, "Hide Particles", "mcje.hide_particles", INT8, DEC)
            DEFINE_HF(hf_factor_codec, "Factor Codec", "mcje.factor_codec", BYTES, NONE)
            DEFINE_HF(hf_motd, "MOTD", "mcje.motd", STRING, NONE)
            DEFINE_HF(hf_icon_bytes, "Icon Bytes", "mcje.icon_bytes", BYTES, NONE)
            DEFINE_HF(hf_enforces_secure_chat, "Enforces Secure Chat", "mcje.enforces_secure_chat", BOOLEAN, NONE)
            DEFINE_HF(hf_recipe_id, "Recipe ID", "mcje.recipe_id", STRING, NONE)
            DEFINE_HF(hf_width, "Width", "mcje.width", UINT32, DEC)
            DEFINE_HF(hf_height, "Height", "mcje.height", UINT32, DEC)
            DEFINE_HF(hf_show_notification, "Show Notification", "mcje.show_notification", BOOLEAN, NONE)
            DEFINE_HF(hf_tag_type, "Tag Type", "mcje.tag_type", STRING, NONE)
            DEFINE_HF(hf_sequence_id, "Sequence ID", "mcje.sequence_id", UINT32, DEC)
            DEFINE_HF(hf_old_diameter, "Old Diameter", "mcje.old_diameter", DOUBLE, DEC)
            DEFINE_HF(hf_new_diameter, "New Diameter", "mcje.new_diameter", DOUBLE, DEC)
            DEFINE_HF(hf_speed, "Speed", "mcje.speed", UINT32, DEC)
            DEFINE_HF(hf_portal_teleport_boundary, "Portal Teleport Boundary", "mcje.portal_teleport_boundary", UINT32,
                      DEC)
            DEFINE_HF(hf_warning_blocks, "Warning Blocks", "mcje.warning_blocks", UINT32, DEC)
            DEFINE_HF(hf_warning_time, "Warning Time", "mcje.warning_time", UINT32, DEC)
            DEFINE_HF(hf_id_i32, "ID", "mcje.id_i32", INT32, DEC)
            DEFINE_HF(hf_text, "Text", "mcje.text", STRING, NONE)
            DEFINE_HF(hf_diameter, "Diameter", "mcje.diameter", DOUBLE, DEC)
            DEFINE_HF(hf_fade_in, "Fade In", "mcje.fade_in", INT32, DEC)
            DEFINE_HF(hf_stay, "Stay", "mcje.stay", INT32, DEC)
            DEFINE_HF(hf_fade_out, "Fade Out", "mcje.fade_out", INT32, DEC)
            DEFINE_HF(hf_source_type_id, "Source Type ID", "mcje.source_type_id", UINT32, DEC)
            DEFINE_HF(hf_source_cause_id, "Source Cause ID", "mcje.source_cause_id", UINT32, DEC)
            DEFINE_HF(hf_source_direct_id, "Source Direct ID", "mcje.source_direct_id", UINT32, DEC)
            DEFINE_HF(hf_command, "Command", "mcje.command", STRING, NONE)
            DEFINE_HF(hf_argument_name, "Argument Name", "mcje.argument_name", STRING, NONE)
            DEFINE_HF(hf_message_count, "Message Count", "mcje.message_count", UINT32, DEC)
            DEFINE_HF(hf_acknowledged, "Acknowledged", "mcje.acknowledged", BYTES, NONE)
            DEFINE_HF(hf_offset, "Offset", "mcje.offset", UINT32, DEC)
            DEFINE_HF(hf_primary_effect, "Primary Effect", "mcje.primary_effect", UINT32, DEC)
            DEFINE_HF(hf_secondary_effect, "Secondary Effect", "mcje.secondary_effect", UINT32, DEC)
            DEFINE_HF(hf_track_output, "Track Output", "mcje.track_output", BOOLEAN, NONE)
            DEFINE_HF(hf_offset_x_int, "Offset X", "mcje.offset_x_int", INT32, DEC)
            DEFINE_HF(hf_offset_y_int, "Offset Y", "mcje.offset_y_int", INT32, DEC)
            DEFINE_HF(hf_offset_z_int, "Offset Z", "mcje.offset_z_int", INT32, DEC)
            DEFINE_HF(hf_size_x, "Size X", "mcje.size_x", INT32, DEC)
            DEFINE_HF(hf_size_y, "Size Y", "mcje.size_y", INT32, DEC)
            DEFINE_HF(hf_size_z, "Size Z", "mcje.size_z", INT32, DEC)
            DEFINE_HF(hf_mirror, "Mirror", "mcje.mirror", UINT32, DEC)
            DEFINE_HF(hf_rotation, "Rotation", "mcje.rotation", UINT32, DEC)
            DEFINE_HF(hf_metadata, "Metadata", "mcje.metadata", STRING, NONE)
            DEFINE_HF(hf_integrity, "Integrity", "mcje.integrity", FLOAT, DEC)
            DEFINE_HF(hf_seed_uint, "Seed", "mcje.seed_uint", UINT32, DEC)
            DEFINE_HF(hf_action_id, "Action ID", "mcje.action_id", UINT32, DEC)
            DEFINE_HF(hf_locale, "Locale", "mcje.locale", STRING, NONE)
            DEFINE_HF(hf_view_distance_int, "View Distance", "mcje.view_distance_int", INT32, DEC)
            DEFINE_HF(hf_chat_flags, "Chat Flags", "mcje.chat_flags", UINT32, DEC)
            DEFINE_HF(hf_chat_color, "Chat Colors", "mcje.chat_color", BOOLEAN, NONE)
            DEFINE_HF(hf_skin_parts, "Skin Parts", "mcje.skin_parts", UINT8, DEC)
            DEFINE_HF(hf_main_hand, "Main Hand", "mcje.main_hand", UINT32, DEC)
            DEFINE_HF(hf_enable_text_filtering, "Enable Text Filtering", "mcje.enable_text_filtering", BOOLEAN, NONE)
            DEFINE_HF(hf_enable_server_listing, "Enable Server Listing", "mcje.enable_server_listing", BOOLEAN, NONE)
            DEFINE_HF(hf_window_id_i8, "Window ID", "mcje.window_id_i8", INT8, DEC)
            DEFINE_HF(hf_enchantment, "Enchantment", "mcje.enchantment", INT8, DEC)
            DEFINE_HF(hf_mouse_button, "Mouse Button", "mcje.mouse_button", INT8, DEC)
            DEFINE_HF(hf_location, "Location", "mcje.location", INT16, DEC)
            DEFINE_HF(hf_target_uint, "Target", "mcje.target_uint", UINT32, DEC)
            DEFINE_HF(hf_mouse, "Mouse", "mcje.mouse", UINT32, DEC)
            DEFINE_HF(hf_sneaking, "Sneaking", "mcje.sneaking", BOOLEAN, NONE)
            DEFINE_HF(hf_levels, "Levels", "mcje.levels", UINT32, DEC)
            DEFINE_HF(hf_keep_jigsaws, "Keep Jigsaws", "mcje.keep_jigsaws", BOOLEAN, NONE)
            DEFINE_HF(hf_left_paddle, "Left Paddle", "mcje.left_paddle", BOOLEAN, NONE)
            DEFINE_HF(hf_right_paddle, "Right Paddle", "mcje.right_paddle", BOOLEAN, NONE)
            DEFINE_HF(hf_make_all, "Make All", "mcje.make_all", BOOLEAN, NONE)
            DEFINE_HF(hf_status, "Status", "mcje.status", UINT32, DEC)
            DEFINE_HF(hf_face, "Face", "mcje.face", INT8, DEC)
            DEFINE_HF(hf_jump_boost, "Jump Boost", "mcje.jump_boost", UINT8, DEC)
            DEFINE_HF(hf_sideways, "Sideways", "mcje.sideways", FLOAT, DEC)
            DEFINE_HF(hf_forward, "Forward", "mcje.forward", FLOAT, DEC)
            DEFINE_HF(hf_jump, "Jump", "mcje.jump", UINT8, DEC)
            DEFINE_HF(hf_book_id, "Book ID", "mcje.book_id", UINT32, DEC)
            DEFINE_HF(hf_book_open, "Book Open", "mcje.book_open", BOOLEAN, NONE)
            DEFINE_HF(hf_filter_active, "Filter Active", "mcje.filter_active", BOOLEAN, NONE)
            DEFINE_HF(hf_result, "Result", "mcje.result", UINT32, DEC)
            DEFINE_HF(hf_pool, "Pool", "mcje.pool", STRING, NONE)
            DEFINE_HF(hf_final_state, "Final State", "mcje.final_state", STRING, NONE)
            DEFINE_HF(hf_joint_type, "Joint Type", "mcje.joint_type", STRING, NONE)
            DEFINE_HF(hf_text_1, "Text 1", "mcje.text_1", STRING, NONE)
            DEFINE_HF(hf_text_2, "Text 2", "mcje.text_2", STRING, NONE)
            DEFINE_HF(hf_text_3, "Text 3", "mcje.text_3", STRING, NONE)
            DEFINE_HF(hf_text_4, "Text 4", "mcje.text_4", STRING, NONE)
            DEFINE_HF(hf_cursor_x, "Cursor X", "mcje.cursor_x", FLOAT, DEC)
            DEFINE_HF(hf_cursor_y, "Cursor Y", "mcje.cursor_y", FLOAT, DEC)
            DEFINE_HF(hf_cursor_z, "Cursor Z", "mcje.cursor_z", FLOAT, DEC)
            DEFINE_HF(hf_inside_block, "Inside Block", "mcje.inside_block", BOOLEAN, NONE)
            DEFINE_HF(hf_tab_id, "Tab ID", "mcje.tab_id", STRING, NONE)
            DEFINE_HF(hf_killer_id, "Killer ID", "mcje.killer_id", INT32, DEC)

            // BITMASKS ------------------------------------------------------------------------------------------------
            DEFINE_HF_BITMASK(hf_x_26, "X", "mcje.x26", INT64, DEC, 0xFFFFFFC000000000)
            DEFINE_HF_BITMASK(hf_z_26, "Z", "mcje.z26", INT64, DEC, 0x0000003FFFFFF000)
            DEFINE_HF_BITMASK(hf_y_12, "Y", "mcje.y12", INT64, DEC, 0x0000000000000FFF)
            DEFINE_HF_BITMASK(hf_x_4, "X", "mcje.x4", INT8, DEC, 0xF0)
            DEFINE_HF_BITMASK(hf_z_4, "Z", "mcje.z4", INT8, DEC, 0x0F)
            DEFINE_HF_BITMASK_TF(hf_has_custom_suggestions_1, "Has Custom Suggestions", "mcje.has_custom_suggestions",
                                 0x10, tf_string)
            DEFINE_HF_BITMASK_TF(hf_has_redirect_node_1, "Has Redirect Node", "mcje.has_redirect_node", 0x08, tf_string)
            DEFINE_HF_BITMASK_TF(hf_has_command_1, "Executable", "mcje.has_command", 0x04, tf_string)
            DEFINE_HF_BITMASK_VAL(hf_command_node_type_2, "Command Node Type", "mcje.command_node_type", UINT8, DEC,
                                  0x03, command_node_string)
            DEFINE_HF_BITMASK_TF(hf_max_present_1, "Max Present", "mcje.max_present", 0x02, tf_string)
            DEFINE_HF_BITMASK_TF(hf_min_present_1, "Min Present", "mcje.min_present", 0x01, tf_string)
            DEFINE_HF_BITMASK_TF(hf_only_allow_players_1, "Only Allow Players", "mcje.only_allow_players", 0x02,
                                 tf_string)
            DEFINE_HF_BITMASK_TF(hf_only_allow_entities_1, "Only Allow Entities", "mcje.only_allow_entities", 0x01,
                                 tf_string)
            DEFINE_HF_BITMASK_TF(hf_allow_multiple_1, "Allow Multiple", "mcje.allow_multiple", 0x01, tf_string)
            DEFINE_HF_BITMASK_TF(hf_hidden_1, "Hidden", "mcje.hidden1", 0x04, tf_string)
            DEFINE_HF_BITMASK_TF(hf_show_toast_1, "Show Toast", "mcje.show_toast", 0x02, tf_string)
            DEFINE_HF_BITMASK_TF(hf_has_background_texture_1, "Has Background Texture", "mcje.has_background_texture",
                                 0x01, tf_string)
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
    ADD_HF("particleData/rotation", hf_rotation_f32);
    ADD_HF("previousMessages/id", hf_id);
    ADD_HF("previousMessages/signature", hf_signature);
    ADD_HF("entityMetadataItem[byte]", hf_byte);
    ADD_HF("entityMetadataItem[int]", hf_int);
    ADD_HF("entityMetadataItem[long]", hf_long);
    ADD_HF("entityMetadataItem[float]", hf_float);
    ADD_HF("entityMetadataItem[string]", hf_string);
    ADD_HF("entityMetadataItem[component]", hf_component);
    ADD_HF("entityMetadataItem[optional_component]", hf_component);
    ADD_HF("entityMetadataItem[boolean]", hf_boolean);
    ADD_HF("entityMetadataItem/pitch", hf_pitch_float);
    ADD_HF("entityMetadataItem/yaw", hf_yaw_float);
    ADD_HF("entityMetadataItem/roll", hf_roll_float);
    ADD_HF("entityMetadataItem[direction]", hf_direction);
    ADD_HF("entityMetadataItem[optional_uuid]", hf_uuid);
    ADD_HF("entityMetadataItem[block_state]", hf_varint_blockstate);
    ADD_HF("entityMetadataItem[optional_block_state]", hf_varint_blockstate);
    ADD_HF("entityMetadataItem[compound_tag]", hf_nbt_data);
    ADD_HF("entityMetadataItem/villagerType", hf_villager_type);
    ADD_HF("entityMetadataItem/villagerProfession", hf_villager_profession);
    ADD_HF("entityMetadataItem/level", hf_level);
    ADD_HF("entityMetadataItem[optional_unsigned_int]", hf_uint);
    ADD_HF("entityMetadataItem[pose]", hf_pose);
    ADD_HF("entityMetadataItem[cat_variant]", hf_cat_variant);
    ADD_HF("entityMetadataItem[frog_variant]", hf_frog_variant);
    ADD_HF("entityMetadataItem[optional_global_pos]", hf_global_pos);
    ADD_HF("entityMetadataItem[painting_variant]", hf_painting_variant);
    ADD_HF("entityMetadataItem[sniffer_state]", hf_sniffer_state);
    ADD_HF("entityMetadata/key", hf_id_u8);
    ADD_HF("entityMetadata/type", hf_type_string);
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
    ADD_HF("command_node/extraNodeData/properties", hf_properties);
    ADD_HF("command_node/extraNodeData/properties/min", hf_min);
    ADD_HF("command_node/extraNodeData/properties/max", hf_max);
    ADD_HF("command_node/extraNodeData/properties/min[brigadier:long]", hf_min_i64);
    ADD_HF("command_node/extraNodeData/properties/max[brigadier:long]", hf_max_i64);
    ADD_HF("command_node/extraNodeData/properties/min[brigadier:float]", hf_min_f32);
    ADD_HF("command_node/extraNodeData/properties/max[brigadier:float]", hf_max_f32);
    ADD_HF("command_node/extraNodeData/properties/min[brigadier:double]", hf_min_f64);
    ADD_HF("command_node/extraNodeData/properties/max[brigadier:double]", hf_max_f64);
    ADD_HF("command_node/extraNodeData/properties/registry", hf_registry);
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
    ADD_HF("spawn_entity/entityId", hf_entity_id);
    ADD_HF("spawn_entity/objectUUID", hf_uuid);
    ADD_HF("spawn_entity/type", hf_varint_type);
    ADD_HF("spawn_entity/x", hf_f64_x);
    ADD_HF("spawn_entity/y", hf_f64_y);
    ADD_HF("spawn_entity/z", hf_f64_z);
    ADD_HF("spawn_entity/pitch", hf_pitch_i8);
    ADD_HF("spawn_entity/yaw", hf_yaw_i8);
    ADD_HF("spawn_entity/headPitch", hf_head_pitch_i8);
    ADD_HF("spawn_entity/objectData", hf_object_data);
    ADD_HF("spawn_entity/velocityX", hf_vx_i16);
    ADD_HF("spawn_entity/velocityY", hf_vy_i16);
    ADD_HF("spawn_entity/velocityZ", hf_vz_i16);
    ADD_HF("spawn_entity_experience_orb/entityId", hf_entity_id);
    ADD_HF("spawn_entity_experience_orb/x", hf_f64_x);
    ADD_HF("spawn_entity_experience_orb/y", hf_f64_y);
    ADD_HF("spawn_entity_experience_orb/z", hf_f64_z);
    ADD_HF("spawn_entity_experience_orb/count", hf_count);
    ADD_HF("named_entity_spawn/entityId", hf_entity_id);
    ADD_HF("named_entity_spawn/playerUUID", hf_uuid);
    ADD_HF("named_entity_spawn/x", hf_f64_x);
    ADD_HF("named_entity_spawn/y", hf_f64_y);
    ADD_HF("named_entity_spawn/z", hf_f64_z);
    ADD_HF("spawn_entity/yaw", hf_yaw_i8);
    ADD_HF("spawn_entity/pitch", hf_pitch_i8);
    ADD_HF("animation/entityId", hf_entity_id);
    ADD_HF("animation/animation", hf_animation);
    ADD_HF("statistics/entries/categoryId", hf_category_id);
    ADD_HF("statistics/entries/statisticId", hf_stat_id);
    ADD_HF("statistics/entries/value", hf_value);
    ADD_HF("advancements/reset", hf_reset);
    ADD_HF("advancements/advancementMapping/key", hf_key_string);
    ADD_HF("advancements/advancementMapping/value/parentId", hf_parent_id_string);
    ADD_HF("advancements/advancementMapping/value/displayData/title", hf_title);
    ADD_HF("advancements/advancementMapping/value/displayData/description", hf_desc);
    ADD_HF("advancements/advancementMapping/value/displayData/frameType", hf_frame_type);
    ADD_HF("advancements/advancementMapping/value/displayData/backgroundTexture", hf_background_texture);
    ADD_HF("advancements/advancementMapping/value/displayData/xCord", hf_f32_x);
    ADD_HF("advancements/advancementMapping/value/displayData/yCord", hf_f32_y);
    ADD_HF("advancements/advancementMapping/value/criteria/key", hf_key_string);
    ADD_HF("advancements/advancementMapping/value/criteria/value", hf_value_string);
    ADD_HF("advancements/advancementMapping/value/sendsTelemtryData", hf_send_telemetry_data);
    ADD_HF("advancements/identifiers", hf_id_string);
    ADD_HF("advancements/progressMapping/key", hf_key_string);
    ADD_HF("advancements/progressMapping/value/criterionIdentifier", hf_criterion_id);
    ADD_HF("advancements/progressMapping/value/criterionProgress", hf_criterion_progress);
    ADD_HF("block_break_animation/entityId", hf_entity_id);
    ADD_HF("block_break_animation/destroyStage", hf_destroy_stage);
    ADD_HF("tile_entity_data/action", hf_action);
    ADD_HF("tile_entity_data/nbtData", hf_nbt_data);
    ADD_HF("block_action/byte1", hf_byte1);
    ADD_HF("block_action/byte2", hf_byte2);
    ADD_HF("block_action/blockId", hf_block_id);
    ADD_HF("block_change/type", hf_varint_blockstate);
    ADD_HF("boss_bar/entityUUID", hf_uuid);
    ADD_HF("boss_bar/action", hf_action);
    ADD_HF("boss_bar/title", hf_title);
    ADD_HF("boss_bar/health", hf_health);
    ADD_HF("boss_bar/color", hf_color);
    ADD_HF("boss_bar/dividers", hf_dividers);
    ADD_HF("boss_bar/flags", hf_flags);
    ADD_HF("difficulty/difficulty", hf_difficulty);
    ADD_HF("difficulty/difficultyLocked", hf_difficulty_locked);
    ADD_HF("tab_complete/transactionId", hf_transaction_id);
    ADD_HF("tab_complete/start", hf_completion_start);
    ADD_HF("tab_complete/length", hf_length);
    ADD_HF("tab_complete/matches/match", hf_match);
    ADD_HF("tab_complete/matches/tooltip", hf_tooltip);
    ADD_HF("declare_commands/rootIndex", hf_root_index);
    ADD_HF("face_player/feet_eyes", hf_feet_eyes);
    ADD_HF("face_player/x", hf_f64_x);
    ADD_HF("face_player/y", hf_f64_y);
    ADD_HF("face_player/z", hf_f64_z);
    ADD_HF("face_player/isEntity", hf_is_entity);
    ADD_HF("face_player/entityId", hf_entity_id);
    ADD_HF("face_player/entity_feet_eyes", hf_entity_feet_eyes);
    ADD_HF("nbt_query_response/transactionId", hf_transaction_id);
    ADD_HF("nbt_query_response/nbt", hf_nbt_data);
    ADD_HF("close_window/windowId", hf_window_id);
    ADD_HF("open_window/windowId", hf_window_id);
    ADD_HF("open_window/inventoryType", hf_inventory_type);
    ADD_HF("open_window/windowTitle", hf_title);
    ADD_HF("window_items/windowId", hf_window_id);
    ADD_HF("window_items/stateId", hf_state_id);
    ADD_HF("craft_progress_bar/windowId", hf_window_id);
    ADD_HF("craft_progress_bar/property", hf_property_i16);
    ADD_HF("craft_progress_bar/value", hf_value_i16);
    ADD_HF("set_slot/windowId", hf_window_id_i8);
    ADD_HF("set_slot/stateId", hf_state_id);
    ADD_HF("set_slot/slot", hf_slot);
    ADD_HF("set_cooldown/itemID", hf_item_id);
    ADD_HF("set_cooldown/cooldownTicks", hf_cooldown_ticks);
    ADD_HF("chat_suggestions/action", hf_action);
    ADD_HF("custom_payload/channel", hf_channel_str);
    ADD_HF("custom_payload/data", hf_data);
    ADD_HF("hide_message/id", hf_id);
    ADD_HF("hide_message/signature", hf_signature);
    ADD_HF("kick_disconnect/reason", hf_reason);
    ADD_HF("profileless_chat/message", hf_message);
    ADD_HF("profileless_chat/type", hf_type);
    ADD_HF("profileless_chat/name", hf_name);
    ADD_HF("profileless_chat/target", hf_target);
    ADD_HF("entity_status/entityId", hf_entity_id_i32);
    ADD_HF("entity_status/entityStatus", hf_entity_status);
    ADD_HF("explosion/x", hf_f64_x);
    ADD_HF("explosion/y", hf_f64_y);
    ADD_HF("explosion/z", hf_f64_z);
    ADD_HF("explosion/radius", hf_radius);
    ADD_HF("explosion/affectedBlockOffsets/x", hf_i8_x);
    ADD_HF("explosion/affectedBlockOffsets/y", hf_i8_y);
    ADD_HF("explosion/affectedBlockOffsets/z", hf_i8_z);
    ADD_HF("explosion/playerMotionX", hf_player_motion_x);
    ADD_HF("explosion/playerMotionY", hf_player_motion_y);
    ADD_HF("explosion/playerMotionZ", hf_player_motion_z);
    ADD_HF("unload_chunk/chunkX", hf_chunk_x);
    ADD_HF("unload_chunk/chunkZ", hf_chunk_z);
    ADD_HF("game_state_change/reason", hf_event);
    ADD_HF("game_state_change/gameMode", hf_event_param);
    ADD_HF("open_horse_window/windowId", hf_window_id);
    ADD_HF("open_horse_window/nbSlots", hf_nb_slots);
    ADD_HF("open_horse_window/entityId", hf_entity_id_i32);
    ADD_HF("keep_alive/keepAliveId", hf_keep_alive_id);
    ADD_HF("map_chunk/x", hf_i32_x);
    ADD_HF("map_chunk/z", hf_i32_z);
    ADD_HF("map_chunk/heightmaps", hf_heightmaps);
    ADD_HF("map_chunk/chunkData", hf_chunk_data);
    ADD_HF("map_chunk/skyLightMask", hf_sky_light_mask);
    ADD_HF("map_chunk/blockLightMask", hf_block_light_mask);
    ADD_HF("map_chunk/emptySkyLightMask", hf_empty_sky_light_mask);
    ADD_HF("map_chunk/emptyBlockLightMask", hf_empty_block_light_mask);
    ADD_HF("map_chunk/skyLight", hf_skylight);
    ADD_HF("map_chunk/blockLight", hf_blocklight);
    ADD_HF("world_event/effectId", hf_type_i32);
    ADD_HF("world_event/data", hf_data_i32);
    ADD_HF("world_event/global", hf_global);
    ADD_HF("world_particles/particleId", hf_particle_id);
    ADD_HF("world_particles/longDistance", hf_long_distance);
    ADD_HF("world_particles/x", hf_f64_x);
    ADD_HF("world_particles/y", hf_f64_y);
    ADD_HF("world_particles/z", hf_f64_z);
    ADD_HF("world_particles/offsetX", hf_offset_x);
    ADD_HF("world_particles/offsetY", hf_offset_y);
    ADD_HF("world_particles/offsetZ", hf_offset_z);
    ADD_HF("world_particles/particleData", hf_particle_data);
    ADD_HF("world_particles/particles", hf_particles);
    ADD_HF("update_light/chunkX", hf_chunk_x);
    ADD_HF("update_light/chunkZ", hf_chunk_z);
    ADD_HF("update_light/skyLightMask", hf_sky_light_mask);
    ADD_HF("update_light/blockLightMask", hf_block_light_mask);
    ADD_HF("update_light/emptySkyLightMask", hf_empty_sky_light_mask);
    ADD_HF("update_light/emptyBlockLightMask", hf_empty_block_light_mask);
    ADD_HF("update_light/skyLight", hf_skylight);
    ADD_HF("update_light/blockLight", hf_blocklight);
    ADD_HF("login/entityId", hf_entity_id_i32);
    ADD_HF("login/isHardcore", hf_is_hardcore);
    ADD_HF("login/gameMode", hf_gamemode);
    ADD_HF("login/previousGameMode", hf_previous_gamemode);
    ADD_HF("login/worldNames", hf_world_names);
    ADD_HF("login/dimensionCodec", hf_dimension_codec);
    ADD_HF("login/worldType", hf_world_type);
    ADD_HF("login/worldName", hf_world_name);
    ADD_HF("login/hashedSeed", hf_hashed_seed);
    ADD_HF("login/maxPlayers", hf_max_players);
    ADD_HF("login/viewDistance", hf_view_distance);
    ADD_HF("login/simulationDistance", hf_simulation_distance);
    ADD_HF("login/reducedDebugInfo", hf_reduced_debug_info);
    ADD_HF("login/enableRespawnScreen", hf_enable_respawn_screen);
    ADD_HF("login/isDebug", hf_is_debug);
    ADD_HF("login/isFlat", hf_is_flat);
    ADD_HF("login/dimensionName", hf_dimension_name);
    ADD_HF("login/portalCooldown", hf_portal_cooldown);
    ADD_HF("map/itemDamage", hf_map_id);
    ADD_HF("map/scale", hf_scale_i8);
    ADD_HF("map/locked", hf_locked);
    ADD_HF("map/icons/type", hf_type);
    ADD_HF("map/icons/x", hf_i8_x);
    ADD_HF("map/icons/z", hf_i8_z);
    ADD_HF("map/icons/direction", hf_direction);
    ADD_HF("map/icons/displayName", hf_name);
    ADD_HF("map/columns", hf_columns);
    ADD_HF("map/rows", hf_rows);
    ADD_HF("map/x", hf_u8_x);
    ADD_HF("map/y", hf_u8_y);
    ADD_HF("map/data", hf_data);
    ADD_HF("trade_list/windowId", hf_window_id);
    ADD_HF("trade_list/trades/tradeDisabled", hf_trade_disabled);
    ADD_HF("trade_list/trades/nbTradeUses", hf_nb_trade_uses);
    ADD_HF("trade_list/trades/maximumNbTradeUses", hf_max_nb_trade_uses);
    ADD_HF("trade_list/trades/xp", hf_xp);
    ADD_HF("trade_list/trades/specialPrice", hf_special_price);
    ADD_HF("trade_list/trades/priceMultiplier", hf_price_multiplier);
    ADD_HF("trade_list/trades/demand", hf_demand);
    ADD_HF("trade_list/villagerLevel", hf_level);
    ADD_HF("trade_list/experience", hf_experience_uint);
    ADD_HF("trade_list/isRegularVillager", hf_is_regular_villager);
    ADD_HF("trade_list/canRestock", hf_can_restock);
    ADD_HF("rel_entity_move/entityId", hf_entity_id);
    ADD_HF("rel_entity_move/dX", hf_dx);
    ADD_HF("rel_entity_move/dY", hf_dy);
    ADD_HF("rel_entity_move/dZ", hf_dz);
    ADD_HF("rel_entity_move/onGround", hf_on_ground);
    ADD_HF("entity_move_look/entityId", hf_entity_id);
    ADD_HF("entity_move_look/dX", hf_dx);
    ADD_HF("entity_move_look/dY", hf_dy);
    ADD_HF("entity_move_look/dZ", hf_dz);
    ADD_HF("entity_move_look/yaw", hf_yaw_i8);
    ADD_HF("entity_move_look/pitch", hf_pitch_i8);
    ADD_HF("entity_move_look/onGround", hf_on_ground);
    ADD_HF("entity_look/entityId", hf_entity_id);
    ADD_HF("entity_look/yaw", hf_yaw_i8);
    ADD_HF("entity_look/pitch", hf_pitch_i8);
    ADD_HF("entity_look/onGround", hf_on_ground);
    ADD_HF("vehicle_move/x", hf_f64_x);
    ADD_HF("vehicle_move/y", hf_f64_y);
    ADD_HF("vehicle_move/z", hf_f64_z);
    ADD_HF("vehicle_move/yaw", hf_yaw_float);
    ADD_HF("vehicle_move/pitch", hf_pitch_float);
    ADD_HF("open_book/hand", hf_hand);
    ADD_HF("open_sign_entity/isFrontText", hf_is_front_text);
    ADD_HF("craft_recipe_response/windowId", hf_window_id);
    ADD_HF("craft_recipe_response/recipe", hf_recipe);
    ADD_HF("abilities/flags", hf_flags_i8);
    ADD_HF("abilities/flyingSpeed", hf_flying_speed);
    ADD_HF("abilities/walkingSpeed", hf_walking_speed);
    ADD_HF("player_chat/senderUuid", hf_uuid);
    ADD_HF("player_chat/index", hf_index_uint);
    ADD_HF("player_chat/signature", hf_signature);
    ADD_HF("player_chat/plainMessage", hf_plain_message);
    ADD_HF("player_chat/timestamp", hf_timestamp);
    ADD_HF("player_chat/salt", hf_salt);
    ADD_HF("player_chat/unsignedChatContent", hf_unsigned_chat_content);
    ADD_HF("player_chat/filterType", hf_filter_type);
    ADD_HF("player_chat/type", hf_varint_type);
    ADD_HF("player_chat/networkName", hf_network_name);
    ADD_HF("player_chat/networkTargetName", hf_network_target_name);
    ADD_HF("end_combat_event/duration", hf_duration);
    ADD_HF("death_combat_event/playerId", hf_player_id);
    ADD_HF("death_combat_event/message", hf_message);
    ADD_HF("player_info/action", hf_action_i8);
    ADD_HF("player_info/data/uuid", hf_uuid);
    ADD_HF("player_info/data/gamemode", hf_gamemode);
    ADD_HF("player_info/data/listed", hf_listed);
    ADD_HF("player_info/data/latency", hf_latency);
    ADD_HF("player_info/data/displayName", hf_name);
    ADD_HF("position/x", hf_f64_x);
    ADD_HF("position/y", hf_f64_y);
    ADD_HF("position/z", hf_f64_z);
    ADD_HF("position/yaw", hf_yaw_float);
    ADD_HF("position/pitch", hf_pitch_float);
    ADD_HF("position/flags", hf_flags_i8);
    ADD_HF("position/teleportId", hf_teleport_id);
    ADD_HF("unlock_recipes/action", hf_action);
    ADD_HF("unlock_recipes/craftingBookOpen", hf_crafting_book_open);
    ADD_HF("unlock_recipes/filteringCraftable", hf_filtering_craftable);
    ADD_HF("unlock_recipes/smeltingBookOpen", hf_smelting_book_open);
    ADD_HF("unlock_recipes/filteringSmeltable", hf_filtering_smeltable);
    ADD_HF("unlock_recipes/blastFurnaceOpen", hf_blast_furnace_open);
    ADD_HF("unlock_recipes/filteringBlastFurnace", hf_filtering_blast_furnace);
    ADD_HF("unlock_recipes/smokerBookOpen", hf_smoker_book_open);
    ADD_HF("unlock_recipes/filteringSmoker", hf_filtering_smoker);
    ADD_HF("remove_entity_effect/entityId", hf_entity_id);
    ADD_HF("remove_entity_effect/effectId", hf_effect_id);
    ADD_HF("resource_pack_send/url", hf_url);
    ADD_HF("resource_pack_send/hash", hf_hash);
    ADD_HF("resource_pack_send/forced", hf_forced);
    ADD_HF("resource_pack_send/promptMessage", hf_prompt_message);
    ADD_HF("respawn/dimension", hf_dimension_name);
    ADD_HF("respawn/worldName", hf_world_name);
    ADD_HF("respawn/hashedSeed", hf_hashed_seed);
    ADD_HF("respawn/gamemode", hf_gamemode);
    ADD_HF("respawn/previousGamemode", hf_previous_gamemode);
    ADD_HF("respawn/isDebug", hf_is_debug);
    ADD_HF("respawn/isFlat", hf_is_flat);
    ADD_HF("respawn/copyMetadata", hf_copy_metadata);
    ADD_HF("respawn/death/dimensionName", hf_dimension_name);
    ADD_HF("respawn/portalCooldown", hf_portal_cooldown);
    ADD_HF("entity_head_rotation/entityId", hf_entity_id);
    ADD_HF("entity_head_rotation/headYaw", hf_head_yaw);
    ADD_HF("camera/cameraId", hf_camera_id);
    ADD_HF("update_view_position/chunkX", hf_chunk_x_uint);
    ADD_HF("update_view_position/chunkZ", hf_chunk_z_uint);
    ADD_HF("update_view_distance/viewDistance", hf_view_distance);
    ADD_HF("scoreboard_display_objective/position", hf_position_i8);
    ADD_HF("scoreboard_display_objective/name", hf_name);
    ADD_HF("entity_metadata/entityId", hf_entity_id);
    ADD_HF("attach_entity/entityId", hf_entity_id_i32);
    ADD_HF("attach_entity/vehicleId", hf_vehicle_id);
    ADD_HF("entity_velocity/entityId", hf_entity_id);
    ADD_HF("entity_velocity/velocityX", hf_vx_i16);
    ADD_HF("entity_velocity/velocityY", hf_vy_i16);
    ADD_HF("entity_velocity/velocityZ", hf_vz_i16);
    ADD_HF("entity_equipment/entityId", hf_entity_id);
    ADD_HF("entity_equipment/equipments/slot", hf_slot);
    ADD_HF("experience/experienceBar", hf_experience_bar);
    ADD_HF("experience/totalExperience", hf_total_experience);
    ADD_HF("experience/level", hf_level);
    ADD_HF("update_health/health", hf_health);
    ADD_HF("update_health/food", hf_food);
    ADD_HF("update_health/foodSaturation", hf_food_saturation);
    ADD_HF("scoreboard_objective/name", hf_name);
    ADD_HF("scoreboard_objective/action", hf_action_i8);
    ADD_HF("scoreboard_objective/displayText", hf_display_text);
    ADD_HF("scoreboard_objective/type", hf_type);
    ADD_HF("set_passengers/entityId", hf_entity_id);
    ADD_HF("teams/team", hf_team);
    ADD_HF("teams/mode", hf_mode);
    ADD_HF("teams/name", hf_name);
    ADD_HF("teams/friendlyFire", hf_friendly_fire);
    ADD_HF("teams/nameTagVisibility", hf_name_tag_visibility);
    ADD_HF("teams/collisionRule", hf_collision_rule);
    ADD_HF("teams/formatting", hf_formatting);
    ADD_HF("teams/prefix", hf_prefix);
    ADD_HF("teams/suffix", hf_suffix);
    ADD_HF("scoreboard_score/itemName", hf_item_name);
    ADD_HF("scoreboard_score/action", hf_action);
    ADD_HF("scoreboard_score/scoreName", hf_score_name);
    ADD_HF("scoreboard_score/value", hf_value);
    ADD_HF("spawn_position/angle", hf_angle);
    ADD_HF("update_time/age", hf_age);
    ADD_HF("update_time/time", hf_time);
    ADD_HF("entity_sound_effect/soundId", hf_sound_id);
    ADD_HF("entity_sound_effect/soundEvent/resource", hf_resource);
    ADD_HF("entity_sound_effect/soundEvent/range", hf_range);
    ADD_HF("entity_sound_effect/soundCategory", hf_sound_category);
    ADD_HF("entity_sound_effect/entityId", hf_entity_id);
    ADD_HF("entity_sound_effect/volume", hf_volume);
    ADD_HF("entity_sound_effect/pitch", hf_pitch_sound);
    ADD_HF("entity_sound_effect/seed", hf_seed);
    ADD_HF("stop_sound/flags", hf_flags_i8);
    ADD_HF("stop_sound/source", hf_source);
    ADD_HF("stop_sound/sound", hf_sound);
    ADD_HF("sound_effect/soundId", hf_sound_id);
    ADD_HF("sound_effect/soundEvent/resource", hf_resource);
    ADD_HF("sound_effect/soundEvent/range", hf_range);
    ADD_HF("sound_effect/soundCategory", hf_sound_category);
    ADD_HF("sound_effect/x", hf_i32_x);
    ADD_HF("sound_effect/y", hf_i32_y);
    ADD_HF("sound_effect/z", hf_i32_z);
    ADD_HF("sound_effect/volume", hf_volume);
    ADD_HF("sound_effect/pitch", hf_pitch_sound);
    ADD_HF("sound_effect/seed", hf_seed);
    ADD_HF("system_chat/content", hf_content);
    ADD_HF("system_chat/isActionBar", hf_is_action_bar);
    ADD_HF("playerlist_header/header", hf_header);
    ADD_HF("playerlist_header/footer", hf_footer);
    ADD_HF("collect/collectedEntityId", hf_collected_entity_id);
    ADD_HF("collect/collectorEntityId", hf_collector_entity_id);
    ADD_HF("collect/pickupItemCount", hf_pickup_item_count);
    ADD_HF("entity_teleport/entityId", hf_entity_id);
    ADD_HF("entity_teleport/x", hf_f64_x);
    ADD_HF("entity_teleport/y", hf_f64_y);
    ADD_HF("entity_teleport/z", hf_f64_z);
    ADD_HF("entity_teleport/yaw", hf_yaw_i8);
    ADD_HF("entity_teleport/pitch", hf_pitch_i8);
    ADD_HF("entity_teleport/onGround", hf_on_ground);
    ADD_HF("entity_update_attributes/entityId", hf_entity_id);
    ADD_HF("entity_update_attributes/properties/key", hf_key_string);
    ADD_HF("entity_update_attributes/properties/value", hf_value_f64);
    ADD_HF("entity_update_attributes/properties/modifiers/uuid", hf_uuid);
    ADD_HF("entity_update_attributes/properties/modifiers/amount", hf_amount);
    ADD_HF("entity_update_attributes/properties/modifiers/operation", hf_operation);
    ADD_HF("entity_effect/entityId", hf_entity_id);
    ADD_HF("entity_effect/effectId", hf_effect_id);
    ADD_HF("entity_effect/amplifier", hf_amplifier);
    ADD_HF("entity_effect/duration", hf_duration);
    ADD_HF("entity_effect/hideParticles", hf_hide_particles);
    ADD_HF("entity_effect/factorCodec", hf_factor_codec);
    ADD_HF("select_advancement_tab/id", hf_id_string);
    ADD_HF("server_data/motd", hf_motd);
    ADD_HF("server_data/iconBytes", hf_icon_bytes);
    ADD_HF("server_data/enforcesSecureChat", hf_enforces_secure_chat);
    ADD_HF("type", hf_type_string);
    ADD_HF("recipeId", hf_recipe_id);
    ADD_HF("declare_recipes/data/group", hf_group);
    ADD_HF("declare_recipes/data/category", hf_category);
    ADD_HF("declare_recipes/data/width", hf_width);
    ADD_HF("declare_recipes/data/height", hf_height);
    ADD_HF("declare_recipes/data/showNotification", hf_show_notification);
    ADD_HF("tags/tags/tagType", hf_tag_type);
    ADD_HF("acknowledge_player_digging/sequenceId", hf_sequence_id);
    ADD_HF("clear_titles/reset", hf_reset);
    ADD_HF("initialize_world_border/x", hf_f64_x);
    ADD_HF("initialize_world_border/z", hf_f64_z);
    ADD_HF("initialize_world_border/oldDiameter", hf_old_diameter);
    ADD_HF("initialize_world_border/newDiameter", hf_new_diameter);
    ADD_HF("initialize_world_border/speed", hf_speed);
    ADD_HF("initialize_world_border/portalTeleportBoundary", hf_portal_teleport_boundary);
    ADD_HF("initialize_world_border/warningBlocks", hf_warning_blocks);
    ADD_HF("initialize_world_border/warningTime", hf_warning_time);
    ADD_HF("action_bar/text", hf_text);
    ADD_HF("world_border_center/x", hf_f64_x);
    ADD_HF("world_border_center/z", hf_f64_z);
    ADD_HF("world_border_lerp_size/oldDiameter", hf_old_diameter);
    ADD_HF("world_border_lerp_size/newDiameter", hf_new_diameter);
    ADD_HF("world_border_lerp_size/speed", hf_speed);
    ADD_HF("world_border_size/diameter", hf_diameter);
    ADD_HF("world_border_warning_delay/warningTime", hf_warning_time);
    ADD_HF("world_border_warning_reach/warningBlocks", hf_warning_blocks);
    ADD_HF("ping/id", hf_id_i32);
    ADD_HF("set_title_subtitle/text", hf_text);
    ADD_HF("set_title_text/text", hf_text);
    ADD_HF("set_title_time/fadeIn", hf_fade_in);
    ADD_HF("set_title_time/stay", hf_stay);
    ADD_HF("set_title_time/fadeOut", hf_fade_out);
    ADD_HF("simulation_distance/distance", hf_simulation_distance);
    ADD_HF("chunk_biomes/biomes/data", hf_data);
    ADD_HF("damage_event/entityId", hf_entity_id);
    ADD_HF("damage_event/sourceTypeId", hf_source_type_id);
    ADD_HF("damage_event/sourceCauseId", hf_source_cause_id);
    ADD_HF("damage_event/sourceDirectId", hf_source_direct_id);
    ADD_HF("hurt_animation/entityId", hf_entity_id);
    ADD_HF("hurt_animation/yaw", hf_yaw_float);
    ADD_HF("teleport_confirm/teleportId", hf_teleport_id);
    ADD_HF("query_block_nbt/transactionId", hf_transaction_id);
    ADD_HF("chat_command/command", hf_command);
    ADD_HF("chat_command/timestamp", hf_timestamp);
    ADD_HF("chat_command/salt", hf_salt);
    ADD_HF("chat_command/argumentSignatures/argumentName", hf_argument_name);
    ADD_HF("chat_command/argumentSignatures/signature", hf_signature);
    ADD_HF("chat_command/messageCount", hf_message_count);
    ADD_HF("chat_command/acknowledged", hf_acknowledged);
    ADD_HF("chat_message/message", hf_message);
    ADD_HF("chat_message/timestamp", hf_timestamp);
    ADD_HF("chat_message/salt", hf_salt);
    ADD_HF("chat_message/signature", hf_signature);
    ADD_HF("chat_message/offset", hf_offset);
    ADD_HF("chat_message/acknowledged", hf_acknowledged);
    ADD_HF("set_difficulty/newDifficulty", hf_difficulty);
    ADD_HF("message_acknowledgement/count", hf_count_uint);
    ADD_HF("edit_book/hand", hf_hand);
    ADD_HF("edit_book/title", hf_title);
    ADD_HF("query_entity_nbt/transactionId", hf_transaction_id);
    ADD_HF("query_entity_nbt/entityId", hf_entity_id);
    ADD_HF("pick_item/slot", hf_slot);
    ADD_HF("name_item/name", hf_name);
    ADD_HF("select_trade/slot", hf_slot);
    ADD_HF("set_beacon_effect/primary_effect", hf_primary_effect);
    ADD_HF("set_beacon_effect/secondary_effect", hf_secondary_effect);
    ADD_HF("update_command_block/command", hf_command);
    ADD_HF("update_command_block/mode", hf_mode);
    ADD_HF("update_command_block/flags", hf_flags);
    ADD_HF("update_command_block_minecart/entityId", hf_entity_id);
    ADD_HF("update_command_block_minecart/command", hf_command);
    ADD_HF("update_command_block_minecart/track_output", hf_track_output);
    ADD_HF("update_structure_block/action", hf_action);
    ADD_HF("update_structure_block/mode", hf_mode);
    ADD_HF("update_structure_block/name", hf_name);
    ADD_HF("update_structure_block/offset_x", hf_offset_x_int);
    ADD_HF("update_structure_block/offset_y", hf_offset_y_int);
    ADD_HF("update_structure_block/offset_z", hf_offset_z_int);
    ADD_HF("update_structure_block/size_x", hf_size_x);
    ADD_HF("update_structure_block/size_y", hf_size_y);
    ADD_HF("update_structure_block/size_z", hf_size_z);
    ADD_HF("update_structure_block/mirror", hf_mirror);
    ADD_HF("update_structure_block/rotation", hf_rotation);
    ADD_HF("update_structure_block/metadata", hf_metadata);
    ADD_HF("update_structure_block/integrity", hf_integrity);
    ADD_HF("update_structure_block/seed", hf_seed);
    ADD_HF("update_structure_block/flags", hf_flags);
    ADD_HF("tab_complete/transactionId", hf_transaction_id);
    ADD_HF("tab_complete/text", hf_text);
    ADD_HF("client_command/actionId", hf_action_id);
    ADD_HF("settings/locale", hf_locale);
    ADD_HF("settings/viewDistance", hf_view_distance_int);
    ADD_HF("settings/chatFlags", hf_chat_flags);
    ADD_HF("settings/chatColors", hf_chat_color);
    ADD_HF("settings/skinParts", hf_skin_parts);
    ADD_HF("settings/mainHand", hf_main_hand);
    ADD_HF("settings/enableTextFiltering", hf_enable_text_filtering);
    ADD_HF("settings/enableServerListing", hf_enable_server_listing);
    ADD_HF("enchant_item/windowId", hf_window_id_i8);
    ADD_HF("enchant_item/enchantment", hf_enchantment);
    ADD_HF("window_click/windowId", hf_window_id);
    ADD_HF("window_click/stateId", hf_state_id);
    ADD_HF("window_click/slot", hf_slot);
    ADD_HF("window_click/mouseButton", hf_mouse_button);
    ADD_HF("window_click/mode", hf_mode);
    ADD_HF("window_click/changedSlots/location", hf_location);
    ADD_HF("close_window/windowId", hf_window_id);
    ADD_HF("use_entity/target", hf_target_uint);
    ADD_HF("use_entity/mouse", hf_mouse);
    ADD_HF("use_entity/x", hf_f32_x);
    ADD_HF("use_entity/y", hf_f32_y);
    ADD_HF("use_entity/z", hf_f32_z);
    ADD_HF("use_entity/hand", hf_hand);
    ADD_HF("use_entity/sneaking", hf_sneaking);
    ADD_HF("generate_structure/levels", hf_levels);
    ADD_HF("generate_structure/keepJigsaws", hf_keep_jigsaws);
    ADD_HF("lock_difficulty/locked", hf_locked);
    ADD_HF("position/onGround", hf_on_ground);
    ADD_HF("position_look/x", hf_f64_x);
    ADD_HF("position_look/y", hf_f64_y);
    ADD_HF("position_look/z", hf_f64_z);
    ADD_HF("position_look/yaw", hf_yaw_float);
    ADD_HF("position_look/pitch", hf_pitch_float);
    ADD_HF("position_look/onGround", hf_on_ground);
    ADD_HF("look/yaw", hf_yaw_float);
    ADD_HF("look/pitch", hf_pitch_float);
    ADD_HF("look/onGround", hf_on_ground);
    ADD_HF("flying/onGround", hf_on_ground);
    ADD_HF("steer_boat/leftPaddle", hf_left_paddle);
    ADD_HF("steer_boat/rightPaddle", hf_right_paddle);
    ADD_HF("craft_recipe_request/windowId", hf_window_id_i8);
    ADD_HF("craft_recipe_request/recipe", hf_recipe);
    ADD_HF("craft_recipe_request/makeAll", hf_make_all);
    ADD_HF("block_dig/status", hf_status);
    ADD_HF("block_dig/face", hf_face);
    ADD_HF("block_dig/sequence", hf_sequence_id);
    ADD_HF("entity_action/entityId", hf_entity_id);
    ADD_HF("entity_action/actionId", hf_action_id);
    ADD_HF("entity_action/jumpBoost", hf_jump_boost);
    ADD_HF("steer_vehicle/sideways", hf_sideways);
    ADD_HF("steer_vehicle/forward", hf_forward);
    ADD_HF("steer_vehicle/jump", hf_jump);
    ADD_HF("displayed_recipe/recipeId", hf_recipe_id);
    ADD_HF("recipe_book/bookId", hf_book_id);
    ADD_HF("recipe_book/bookOpen", hf_book_open);
    ADD_HF("recipe_book/filterActive", hf_filter_active);
    ADD_HF("resource_pack_receive/result", hf_result);
    ADD_HF("held_item_slot/slotId", hf_slot);
    ADD_HF("set_creative_slot/slot", hf_slot);
    ADD_HF("update_jigsaw_block/name", hf_name);
    ADD_HF("update_jigsaw_block/target", hf_target);
    ADD_HF("update_jigsaw_block/pool", hf_pool);
    ADD_HF("update_jigsaw_block/finalState", hf_final_state);
    ADD_HF("update_jigsaw_block/jointType", hf_joint_type);
    ADD_HF("update_sign/isFrontText", hf_is_front_text);
    ADD_HF("update_sign/text1", hf_text_1);
    ADD_HF("update_sign/text2", hf_text_2);
    ADD_HF("update_sign/text3", hf_text_3);
    ADD_HF("update_sign/text4", hf_text_4);
    ADD_HF("arm_animation/hand", hf_hand);
    ADD_HF("spectate/target", hf_uuid);
    ADD_HF("block_place/hand", hf_hand);
    ADD_HF("block_place/direction", hf_direction);
    ADD_HF("block_place/cursorX", hf_cursor_x);
    ADD_HF("block_place/cursorY", hf_cursor_y);
    ADD_HF("block_place/cursorZ", hf_cursor_z);
    ADD_HF("block_place/insideBlock", hf_inside_block);
    ADD_HF("block_place/sequence", hf_sequence_id);
    ADD_HF("use_item/hand", hf_hand);
    ADD_HF("use_item/sequence", hf_sequence_id);
    ADD_HF("advancement_tab/action", hf_action);
    ADD_HF("advancement_tab/tabId", hf_tab_id);
    ADD_HF("pong/id", hf_id_i32);
    ADD_HF("chat_session_update/sessionUUID", hf_uuid);
    ADD_HF("chat_session_update/expireTime", hf_expire_time);
    ADD_HF("chat_session_update/publicKey", hf_public_key);
    ADD_HF("chat_session_update/signature", hf_signature);
    ADD_HF("end_combat_event/entityId", hf_killer_id);
    ADD_HF("death_combat_event/entityId", hf_killer_id);

    // BITMASKS --------------------------------------------------------------------------------------------------------
    bitmask_hf_map_je = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
    wmem_map_insert(bitmask_hf_map_je, "[26]x[26]z[12]y", positionXZY);
    wmem_map_insert(bitmask_hf_map_je, "[4]x[4]z", positionXZ);
    wmem_map_insert(bitmask_hf_map_je,
                    "[3]unused[1]has_custom_suggestions[1]has_redirect_node[1]has_command[2]command_node_type",
                    command_flags);
    wmem_map_insert(bitmask_hf_map_je, "[6]unused[1]max_present[1]min_present", command_arg_limit);
    wmem_map_insert(bitmask_hf_map_je, "[6]unused[1]onlyAllowPlayers[1]onlyAllowEntities", command_arg_entity);
    wmem_map_insert(bitmask_hf_map_je, "[7]unused[1]allowMultiple", command_arg_score_holder);
    wmem_map_insert(bitmask_hf_map_je, "[29]_unused[1]hidden[1]show_toast[1]has_background_texture",
                    advancement_display);
    wmem_map_insert(bitmask_hf_map_je, "[22]x[22]z[20]y", chunk_coordinates);

    // Preference ------------------------------------------------------------------------------------------------------
    pref_mcje = prefs_register_protocol(proto_mcje, NULL);
    prefs_register_string_preference(pref_mcje, "ignore_packets", "Ignore Packets",
                                     "Ignore packets with the given names", (const char **) &pref_ignore_packets_je);

    init_je();
    init_je_constants();
}