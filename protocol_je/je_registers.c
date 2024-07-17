//
// Created by Nickid2018 on 2023/7/16.
//

#include <epan/packet.h>
#include "mc_dissector.h"
#include "strings_je.h"
#include "je_protocol.h"

// ett
int ett_mcje = -1;
int ett_je_proto = -1;
int ett_sub_je = -1;

// hf lines
int hf_int8_je = -1;
int hf_uint8_je = -1;
int hf_int16_je = -1;
int hf_uint16_je = -1;
int hf_int_je = -1;
int hf_uint_je = -1;
int hf_varint_je = -1;
int hf_int64_je = -1;
int hf_uint64_je = -1;
int hf_varlong_je = -1;
int hf_float_je = -1;
int hf_double_je = -1;
int hf_bytes_je = -1;
int hf_string_je = -1;
int hf_boolean_je = -1;
int hf_uuid_je = -1;

int hf_generated_je = -1;
int hf_invalid_data_je = -1;
int hf_ignored_packet_je = -1;
int hf_packet_length_je = -1;
int hf_packet_data_length_je = -1;
int hf_packet_id_je = -1;
int hf_packet_name_je = -1;
int hf_unknown_packet_je = -1;
int hf_protocol_version_je = -1;
int hf_server_address_je = -1;
int hf_next_state_je = -1;
int hf_ping_time_je = -1;
int hf_server_status_je = -1;
int hf_legacy_slp_payload = -1;

#define DEFINE_HF(name, desc, key, type, dis) {&name, {desc, key, FT_##type, BASE_##dis, NULL, 0x0, NULL, HFILL}},

void proto_register_mcje() {
    proto_mcje = proto_register_protocol(MCJE_NAME, MCJE_SHORT_NAME, MCJE_FILTER);

    register_string_je();

    static hf_register_info hf_je[] = {
            DEFINE_HF(hf_int8_je, " [int8]", "mcje.int8", INT8, DEC)
            DEFINE_HF(hf_uint8_je, " [uint8]", "mcje.uint8", UINT8, DEC)
            DEFINE_HF(hf_int16_je, " [int16]", "mcje.int16", INT16, DEC)
            DEFINE_HF(hf_uint16_je, " [uint16]", "mcje.uint16", UINT16, DEC)
            DEFINE_HF(hf_int_je, " [int32]", "mcje.int", INT32, DEC)
            DEFINE_HF(hf_uint_je, " [uint32]", "mcje.uint", UINT32, DEC)
            DEFINE_HF(hf_varint_je, " [var int]", "mcje.varint", UINT32, DEC)
            DEFINE_HF(hf_int64_je, " [int64]", "mcje.int64", INT64, DEC)
            DEFINE_HF(hf_uint64_je, " [uint64]", "mcje.uint64", UINT64, DEC)
            DEFINE_HF(hf_varlong_je, " [var long]", "mcje.varlong", UINT32, DEC)
            DEFINE_HF(hf_float_je, " [f32]", "mcje.float", FLOAT, DEC)
            DEFINE_HF(hf_double_je, " [f64]", "mcje.double", DOUBLE, DEC)
            DEFINE_HF(hf_bytes_je, " [buffer]", "mcje.bytes", BYTES, NONE)
            DEFINE_HF(hf_string_je, " [string]", "mcje.string", STRING, NONE)
            DEFINE_HF(hf_boolean_je, " [boolean]", "mcje.boolean", BOOLEAN, NONE)
            DEFINE_HF(hf_uuid_je, " [UUID]", "mcje.uuid", GUID, NONE)
            DEFINE_HF(hf_generated_je, " (generated)", "mcje.generated", STRING, NONE)
            DEFINE_HF(hf_invalid_data_je, "Invalid Data", "mcje.invalid_data", STRING, NONE)
            DEFINE_HF(hf_ignored_packet_je, "Ignored Packet", "mcje.ignored_packet", STRING, NONE)
            DEFINE_HF(hf_packet_length_je, "Packet Length", "mcje.packet_length", UINT32, DEC)
            DEFINE_HF(hf_packet_data_length_je, "Packet Data Length", "mcje.packet_data_length", UINT32, DEC)
            DEFINE_HF(hf_packet_id_je, "Packet ID", "mcje.packet_id", UINT8, HEX)
            DEFINE_HF(hf_packet_name_je, "Packet Name", "mcje.packet_name", STRING, NONE)
            DEFINE_HF(hf_unknown_packet_je, "Packet Name", "mcje.unknown_packet", STRING, NONE)
            DEFINE_HF(hf_protocol_version_je, "Protocol Version", "mcje.protocol_version", STRING, NONE)
            DEFINE_HF(hf_server_address_je, "Server Address", "mcje.server_address", STRING, NONE)
            DEFINE_HF(hf_next_state_je, "Next State", "mcje.next_state", STRING, NONE)
            DEFINE_HF(hf_ping_time_je, "Ping Time", "mcje.ping_time", INT64, DEC)
            DEFINE_HF(hf_server_status_je, "Server Status", "mcje.server_status", STRING, NONE)
            DEFINE_HF(hf_legacy_slp_payload, "Legacy SLP Payload", "mcje.legacy_slp_payload", UINT8, DEC)
    };
    proto_register_field_array(proto_mcje, hf_je, array_length(hf_je));

    static gint *ett_je[] = {&ett_mcje, &ett_je_proto, &ett_sub_je};
    proto_register_subtree_array(ett_je, array_length(ett_je));
}