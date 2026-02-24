//
// Created by Nickid2018 on 2023/7/16.
//

#include <epan/packet.h>
#include "mc_dissector.h"
#include "je_dissect.h"
#include "protocol/storage/storage.h"

// NO FORMAT: Keep alignment
char *JE_PROTOCOL_STATES[] = {
    "handshaking_server", "play_server", "status_server", "login_server", "configuration_server", "", "", "",
    "",                   "play_client", "status_client", "login_client", "configuration_client", "", "", "",
};

// ett
int ett_mc_je = -1;
int ett_proto_je = -1;
int ett_sub_je = -1;

// hf lines
int hf_int8_je = -1;
int hf_uint8_je = -1;
int hf_hint8_je = -1;
int hf_int16_je = -1;
int hf_uint16_je = -1;
int hf_hint16_je = -1;
int hf_int32_je = -1;
int hf_uint32_je = -1;
int hf_hint32_je = -1;
int hf_varint_je = -1;
int hf_int64_je = -1;
int hf_uint64_je = -1;
int hf_hint64_je = -1;
int hf_varlong_je = -1;
int hf_float_je = -1;
int hf_double_je = -1;
int hf_bytes_je = -1;
int hf_string_je = -1;
int hf_boolean_je = -1;
int hf_uuid_je = -1;

int hf_generated_je = -1;
int hf_invalid_data_je = -1;
int hf_parsing_error_je = -1;
int hf_ignored_packet_je = -1;
int hf_packet_length_je = -1;
int hf_packet_data_length_je = -1;
int hf_packet_id_je = -1;
int hf_packet_name_je = -1;
int hf_unknown_packet_je = -1;

gchar *pref_ignore_packets_je = "";
gchar *pref_secret_key_je = NULL;
gchar *pref_key_log_filepath_je = NULL;
bool pref_do_nbt_decode_je = false;

protocol_dissector_settings *settings_je = NULL;
protocol_storage *storage_je = NULL;

#define DEFINE_HF(name, desc, key, type, dis) {&name, {desc, key, FT_##type, BASE_##dis, NULL, 0x0, NULL, HFILL}},

void proto_register_mcje() {
    proto_mcje = proto_register_protocol(MCJE_NAME, MCJE_SHORT_NAME, MCJE_FILTER);

    static hf_register_info hf_je[] = {
        // Common data types and function types
        DEFINE_HF(hf_int8_je, "[int8]", "mcje.int8", INT8, DEC)
        DEFINE_HF(hf_uint8_je, "[uint8]", "mcje.uint8", UINT8, DEC)
        DEFINE_HF(hf_hint8_je, "[uint8]", "mcje.hint8", UINT8, HEX)
        DEFINE_HF(hf_int16_je, "[int16]", "mcje.int16", INT16, DEC)
        DEFINE_HF(hf_uint16_je, "[uint16]", "mcje.uint16", UINT16, DEC)
        DEFINE_HF(hf_hint16_je, "[uint16]", "mcje.hint16", UINT16, HEX)
        DEFINE_HF(hf_int32_je, "[int32]", "mcje.int32", INT32, DEC)
        DEFINE_HF(hf_uint32_je, "[uint32]", "mcje.uint32", UINT32, DEC)
        DEFINE_HF(hf_hint32_je, "[uint32]", "mcje.hint32", UINT32, HEX)
        DEFINE_HF(hf_varint_je, "[var int]", "mcje.varint", INT32, DEC)
        DEFINE_HF(hf_int64_je, "[int64]", "mcje.int64", INT64, DEC)
        DEFINE_HF(hf_uint64_je, "[uint64]", "mcje.uint64", UINT64, DEC)
        DEFINE_HF(hf_hint64_je, "[uint64]", "mcje.hint64", UINT64, HEX)
        DEFINE_HF(hf_varlong_je, "[var long]", "mcje.varlong", INT64, DEC)
        DEFINE_HF(hf_float_je, "[f32]", "mcje.float", FLOAT, DEC)
        DEFINE_HF(hf_double_je, "[f64]", "mcje.double", DOUBLE, DEC)
        DEFINE_HF(hf_bytes_je, "[buffer]", "mcje.bytes", BYTES, NONE)
        DEFINE_HF(hf_string_je, "[string]", "mcje.string", STRING, NONE)
        DEFINE_HF(hf_boolean_je, "[boolean]", "mcje.boolean", BOOLEAN, NONE)
        DEFINE_HF(hf_uuid_je, "[UUID]", "mcje.uuid", GUID, NONE)
        DEFINE_HF(hf_generated_je, "(generated)", "mcje.generated", STRING, NONE)
        DEFINE_HF(hf_invalid_data_je, "[INVALID]", "mcje.invalid_data", STRING, NONE)
        DEFINE_HF(hf_parsing_error_je, "[PARSING ERROR]", "mcje.parsing_error", STRING, NONE)
        DEFINE_HF(hf_ignored_packet_je, "Ignored Packet", "mcje.ignored_packet", STRING, NONE)
        // JE dissector data types
        DEFINE_HF(hf_packet_length_je, "Packet Length", "mcje.packet_length", UINT32, DEC)
        DEFINE_HF(hf_packet_data_length_je, "Packet Data Length", "mcje.packet_data_length", UINT32, DEC)
        DEFINE_HF(hf_packet_id_je, "Packet ID", "mcjeje.packet_id", UINT8, HEX)
        DEFINE_HF(hf_packet_name_je, "Packet Name", "mcjeje.packet_name", STRING, NONE)
        DEFINE_HF(hf_unknown_packet_je, "Unknown Packet", "mcje.unknown_packet", STRING, NONE)
    };
    proto_register_field_array(proto_mcje, hf_je, array_length(hf_je));

    static gint *etts[] = {&ett_mc_je, &ett_proto_je, &ett_sub_je};
    proto_register_subtree_array(etts, array_length(etts));
}

void pref_register_mcje() {
    prefs_register_string_preference(
        pref_mcje, "ignore_packets", "Ignore Packets",
        "Ignore packets with the given names", (const char **) &pref_ignore_packets_je
    );
    prefs_register_string_preference(
        pref_mcje, "secret_key", "Secret Key",
        "Secret key for decryption", (const char **) &pref_secret_key_je
    );
    prefs_register_filename_preference(
        pref_mcje, "key_log_filepath", "Key Log File",
        "", (const char **) &pref_key_log_filepath_je, false
    );
    prefs_register_bool_preference(
        pref_mcje, "do_nbt_decode", "NBT Decoding",
        "Decode NBT data", &pref_do_nbt_decode_je
    );
}

void init_storage_je() {
    if (settings_je != NULL) {
        wmem_free(wmem_epan_scope(), settings_je);
    }
    settings_je = wmem_new(wmem_epan_scope(), protocol_dissector_settings);
    settings_je->ett_tree = ett_mc_je;
    settings_je->hf_indexes[hf_int8] = hf_int8_je;
    settings_je->hf_indexes[hf_uint8] = hf_uint8_je;
    settings_je->hf_indexes[hf_hint8] = hf_hint8_je;
    settings_je->hf_indexes[hf_int16] = hf_int16_je;
    settings_je->hf_indexes[hf_uint16] = hf_uint16_je;
    settings_je->hf_indexes[hf_hint16] = hf_hint16_je;
    settings_je->hf_indexes[hf_int32] = hf_int32_je;
    settings_je->hf_indexes[hf_uint32] = hf_uint32_je;
    settings_je->hf_indexes[hf_hint32] = hf_hint32_je;
    settings_je->hf_indexes[hf_varint] = hf_varint_je;
    settings_je->hf_indexes[hf_int64] = hf_int64_je;
    settings_je->hf_indexes[hf_uint64] = hf_uint64_je;
    settings_je->hf_indexes[hf_hint64] = hf_hint64_je;
    settings_je->hf_indexes[hf_varlong] = hf_varlong_je;
    settings_je->hf_indexes[hf_float] = hf_float_je;
    settings_je->hf_indexes[hf_double] = hf_double_je;
    settings_je->hf_indexes[hf_bytes] = hf_bytes_je;
    settings_je->hf_indexes[hf_string] = hf_string_je;
    settings_je->hf_indexes[hf_boolean] = hf_boolean_je;
    settings_je->hf_indexes[hf_uuid] = hf_uuid_je;
    settings_je->hf_indexes[hf_generated] = hf_generated_je;
    settings_je->hf_indexes[hf_invalid_data] = hf_invalid_data_je;
    settings_je->hf_indexes[hf_parsing_error] = hf_parsing_error_je;
    settings_je->hf_indexes[hf_ignored_packet] = hf_ignored_packet_je;
    settings_je->endian = ENC_BIG_ENDIAN;
    settings_je->total_states = 16;
    settings_je->state_names = JE_PROTOCOL_STATES;

    if (storage_je != NULL) {
        clear_storage(storage_je);
        wmem_free(wmem_epan_scope(), storage_je);
    }
    storage_je = create_storage("java_edition", settings_je);
}
