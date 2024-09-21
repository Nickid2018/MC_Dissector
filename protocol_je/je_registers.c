//
// Created by Nickid2018 on 2023/7/16.
//

#include <epan/packet.h>
#include "mc_dissector.h"
#include "je_protocol.h"

// ett
int ett_mc = -1;
int ett_proto = -1;
int ett_sub = -1;

// hf lines
int hf_int8 = -1;
int hf_uint8 = -1;
int hf_hint8 = -1;
int hf_int16 = -1;
int hf_uint16 = -1;
int hf_hint16 = -1;
int hf_int32 = -1;
int hf_uint32 = -1;
int hf_hint32 = -1;
int hf_varint = -1;
int hf_int64 = -1;
int hf_uint64 = -1;
int hf_hint64 = -1;
int hf_varlong = -1;
int hf_float = -1;
int hf_double = -1;
int hf_bytes = -1;
int hf_string = -1;
int hf_boolean = -1;
int hf_uuid = -1;

int hf_generated = -1;
int hf_invalid_data = -1;
int hf_parsing_error = -1;
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

    static hf_register_info hf_je[] = {
            DEFINE_HF(hf_int8, "[int8]", "mc.int8", INT8, DEC)
            DEFINE_HF(hf_uint8, "[uint8]", "mc.uint8", UINT8, DEC)
            DEFINE_HF(hf_hint8, "[uint8]", "mc.hint8", UINT8, HEX)
            DEFINE_HF(hf_int16, "[int16]", "mc.int16", INT16, DEC)
            DEFINE_HF(hf_uint16, "[uint16]", "mc.uint16", UINT16, DEC)
            DEFINE_HF(hf_hint16, "[uint16]", "mc.hint16", UINT16, HEX)
            DEFINE_HF(hf_int32, "[int32]", "mc.int32", INT32, DEC)
            DEFINE_HF(hf_uint32, "[uint32]", "mc.uint32", UINT32, DEC)
            DEFINE_HF(hf_hint32, "[uint32]", "mc.hint32", UINT32, HEX)
            DEFINE_HF(hf_varint, "[var int]", "mc.varint", UINT32, DEC)
            DEFINE_HF(hf_int64, "[int64]", "mc.int64", INT64, DEC)
            DEFINE_HF(hf_uint64, "[uint64]", "mc.uint64", UINT64, DEC)
            DEFINE_HF(hf_hint64, "[uint64]", "mc.hint64", UINT64, HEX)
            DEFINE_HF(hf_varlong, "[var long]", "mc.varlong", UINT64, DEC)
            DEFINE_HF(hf_float, "[f32]", "mc.float", FLOAT, DEC)
            DEFINE_HF(hf_double, "[f64]", "mc.double", DOUBLE, DEC)
            DEFINE_HF(hf_bytes, "[buffer]", "mc.bytes", BYTES, NONE)
            DEFINE_HF(hf_string, "[string]", "mc.string", STRING, NONE)
            DEFINE_HF(hf_boolean, "[boolean]", "mc.boolean", BOOLEAN, NONE)
            DEFINE_HF(hf_uuid, "[UUID]", "mc.uuid", GUID, NONE)
            DEFINE_HF(hf_generated, "(generated)", "mc.generated", STRING, NONE)
            DEFINE_HF(hf_invalid_data, "[INVALID]", "mc.invalid_data", STRING, NONE)
            DEFINE_HF(hf_parsing_error, "[PARSING ERROR]", "mc.parsing_error", STRING, NONE)
            DEFINE_HF(hf_ignored_packet_je, "Ignored Packet", "mc.ignored_packet", STRING, NONE)
            DEFINE_HF(hf_packet_length_je, "Packet Length", "mc.packet_length", UINT32, DEC)
            DEFINE_HF(hf_packet_data_length_je, "Packet Data Length", "mc.packet_data_length", UINT32, DEC)
            DEFINE_HF(hf_packet_id_je, "Packet ID", "mcje.packet_id", UINT8, HEX)
            DEFINE_HF(hf_packet_name_je, "Packet Name", "mcje.packet_name", STRING, NONE)
            DEFINE_HF(hf_unknown_packet_je, "Packet Name", "mc.unknown_packet", STRING, NONE)
            DEFINE_HF(hf_protocol_version_je, "Protocol Version", "mcje.protocol_version", STRING, NONE)
            DEFINE_HF(hf_server_address_je, "Server Address", "mcje.server_address", STRING, NONE)
            DEFINE_HF(hf_next_state_je, "Next State", "mcje.next_state", STRING, NONE)
            DEFINE_HF(hf_ping_time_je, "Ping Time", "mcje.ping_time", INT64, DEC)
            DEFINE_HF(hf_server_status_je, "Server Status", "mcje.server_status", STRING, NONE)
            DEFINE_HF(hf_legacy_slp_payload, "Legacy SLP Payload", "mcje.legacy_slp_payload", UINT8, DEC)
    };
    proto_register_field_array(proto_mcje, hf_je, array_length(hf_je));

    static gint *etts[] = {&ett_mc, &ett_proto, &ett_sub};
    proto_register_subtree_array(etts, array_length(etts));
}