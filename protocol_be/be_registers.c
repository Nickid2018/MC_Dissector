//
// Created by Nickid2018 on 2023/7/16.
//

#include <epan/packet.h>
#include "be_dissect.h"
#include "mc_dissector.h"
#include "protocol/storage/storage.h"

char *BE_PROTOCOL_STATES[] = {"initial", "game"};

// ett
int ett_mc_be = -1;
int ett_proto_be = -1;
int ett_sub_be = -1;

// hf lines
int hf_int8_be = -1;
int hf_uint8_be = -1;
int hf_hint8_be = -1;
int hf_int16_be = -1;
int hf_uint16_be = -1;
int hf_hint16_be = -1;
int hf_int32_be = -1;
int hf_uint32_be = -1;
int hf_hint32_be = -1;
int hf_varint_be = -1;
int hf_int64_be = -1;
int hf_uint64_be = -1;
int hf_hint64_be = -1;
int hf_varlong_be = -1;
int hf_float_be = -1;
int hf_double_be = -1;
int hf_bytes_be = -1;
int hf_string_be = -1;
int hf_boolean_be = -1;
int hf_uuid_be = -1;

int hf_generated_be = -1;
int hf_invalid_data_be = -1;
int hf_parsing_error_be = -1;
int hf_ignored_packet_be = -1;
int hf_packet_length_be = -1;
int hf_packet_data_length_be = -1;
int hf_packet_id_be = -1;
int hf_packet_name_be = -1;
int hf_unknown_packet_be = -1;

bool pref_do_nbt_decode_be = false;

protocol_dissector_settings *settings_be;
protocol_storage *storage_be;

#define DEFINE_HF(name, desc, key, type, dis) {&name, {desc, key, FT_## type, BASE_## dis, NULL, 0x0, NULL, HFILL}},

void proto_register_mcbe() {
    proto_mcbe = proto_register_protocol(MCBE_NAME, MCBE_SHORT_NAME, MCBE_FILTER);

    static hf_register_info hf_be[] = {
        // Common data types and function types
        DEFINE_HF(hf_int8_be, "[int8]", "mcbe.int8", INT8, DEC)
        DEFINE_HF(hf_uint8_be, "[uint8]", "mcbe.uint8", UINT8, DEC)
        DEFINE_HF(hf_hint8_be, "[uint8]", "mcbe.hint8", UINT8, HEX)
        DEFINE_HF(hf_int16_be, "[int16]", "mcbe.int16", INT16, DEC)
        DEFINE_HF(hf_uint16_be, "[uint16]", "mcbe.uint16", UINT16, DEC)
        DEFINE_HF(hf_hint16_be, "[uint16]", "mcbe.hint16", UINT16, HEX)
        DEFINE_HF(hf_int32_be, "[int32]", "mcbe.int32", INT32, DEC)
        DEFINE_HF(hf_uint32_be, "[uint32]", "mcbe.uint32", UINT32, DEC)
        DEFINE_HF(hf_hint32_be, "[uint32]", "mcbe.hint32", UINT32, HEX)
        DEFINE_HF(hf_varint_be, "[var int]", "mcbe.varint", INT32, DEC)
        DEFINE_HF(hf_int64_be, "[int64]", "mcbe.int64", INT64, DEC)
        DEFINE_HF(hf_uint64_be, "[uint64]", "mcbe.uint64", UINT64, DEC)
        DEFINE_HF(hf_hint64_be, "[uint64]", "mcbe.hint64", UINT64, HEX)
        DEFINE_HF(hf_varlong_be, "[var long]", "mcbe.varlong", INT64, DEC)
        DEFINE_HF(hf_float_be, "[f32]", "mcbe.float", FLOAT, DEC)
        DEFINE_HF(hf_double_be, "[f64]", "mcbe.double", DOUBLE, DEC)
        DEFINE_HF(hf_bytes_be, "[buffer]", "mcbe.bytes", BYTES, NONE)
        DEFINE_HF(hf_string_be, "[string]", "mcbe.string", STRING, NONE)
        DEFINE_HF(hf_boolean_be, "[boolean]", "mcbe.boolean", BOOLEAN, NONE)
        DEFINE_HF(hf_uuid_be, "[UUID]", "mcbe.uuid", GUID, NONE)
        DEFINE_HF(hf_generated_be, "(generated)", "mcbe.generated", STRING, NONE)
        DEFINE_HF(hf_invalid_data_be, "[INVALID]", "mcbe.invalid_data", STRING, NONE)
        DEFINE_HF(hf_parsing_error_be, "[PARSING ERROR]", "mcbe.parsing_error", STRING, NONE)
        DEFINE_HF(hf_ignored_packet_be, "Ignored Packet", "mcbe.ignored_packet", STRING, NONE)
        // BE dissector data types
        DEFINE_HF(hf_packet_length_be, "Packet Length", "mcbe.packet_length", UINT32, DEC)
        DEFINE_HF(hf_packet_data_length_be, "Packet Data Length", "mcbe.packet_data_length", UINT32, DEC)
        DEFINE_HF(hf_packet_id_be, "Packet ID", "mcbebe.packet_id", UINT8, HEX)
        DEFINE_HF(hf_packet_name_be, "Packet Name", "mcbebe.packet_name", STRING, NONE)
        DEFINE_HF(hf_unknown_packet_be, "Unknown Packet", "mcbe.unknown_packet", STRING, NONE)
    };
    proto_register_field_array(proto_mcbe, hf_be, array_length(hf_be));

    static gint *etts[] = {&ett_mc_be, &ett_proto_be, &ett_sub_be};
    proto_register_subtree_array(etts, array_length(etts));
}

void pref_register_mcbe() {
    prefs_register_bool_preference(
        pref_mcbe, "do_nbt_decode", "NBT Decoding",
        "Decode NBT data", &pref_do_nbt_decode_be
    );
}

void init_storage_be() {
    if (settings_be != NULL) {
        wmem_free(wmem_epan_scope(), settings_be->hf_indexes);
        wmem_free(wmem_epan_scope(), settings_be);
    }
    settings_be = wmem_new(wmem_epan_scope(), protocol_dissector_settings);
    settings_be->ett_tree = ett_mc_be;
    settings_be->hf_indexes[hf_int8] = hf_int8_be;
    settings_be->hf_indexes[hf_uint8] = hf_uint8_be;
    settings_be->hf_indexes[hf_hint8] = hf_hint8_be;
    settings_be->hf_indexes[hf_int16] = hf_int16_be;
    settings_be->hf_indexes[hf_uint16] = hf_uint16_be;
    settings_be->hf_indexes[hf_hint16] = hf_hint16_be;
    settings_be->hf_indexes[hf_int32] = hf_int32_be;
    settings_be->hf_indexes[hf_uint32] = hf_uint32_be;
    settings_be->hf_indexes[hf_hint32] = hf_hint32_be;
    settings_be->hf_indexes[hf_varint] = hf_varint_be;
    settings_be->hf_indexes[hf_int64] = hf_int64_be;
    settings_be->hf_indexes[hf_uint64] = hf_uint64_be;
    settings_be->hf_indexes[hf_hint64] = hf_hint64_be;
    settings_be->hf_indexes[hf_varlong] = hf_varlong_be;
    settings_be->hf_indexes[hf_float] = hf_float_be;
    settings_be->hf_indexes[hf_double] = hf_double_be;
    settings_be->hf_indexes[hf_bytes] = hf_bytes_be;
    settings_be->hf_indexes[hf_string] = hf_string_be;
    settings_be->hf_indexes[hf_boolean] = hf_boolean_be;
    settings_be->hf_indexes[hf_uuid] = hf_uuid_be;
    settings_be->hf_indexes[hf_generated] = hf_generated_be;
    settings_be->hf_indexes[hf_invalid_data] = hf_invalid_data_be;
    settings_be->hf_indexes[hf_parsing_error] = hf_parsing_error_be;
    settings_be->hf_indexes[hf_ignored_packet] = hf_ignored_packet_be;
    settings_be->endian = ENC_LITTLE_ENDIAN;
    settings_be->total_states = 2;
    settings_be->state_names = BE_PROTOCOL_STATES;

    if (storage_be != NULL) {
        clear_storage(storage_be);
        wmem_free(wmem_epan_scope(), storage_be);
    }
    storage_be = create_storage("bedrock_edition", settings_be);
}