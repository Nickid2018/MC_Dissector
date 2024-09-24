//
// Created by Nickid2018 on 2023/7/12.
//
#include <ws_version.h>
#include <wsutil/filesystem.h>

#include "mc_dissector.h"
#include "protocol/protocol_data.h"
#include "protocol_je/je_dissect.h"
#include "protocol_be/be_dissect.h"

WS_DLL_PUBLIC_DEF _U_ const gchar plugin_version[] = "0.0.0";
WS_DLL_PUBLIC_DEF _U_ const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF _U_ const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC _U_ void plugin_register();

int proto_mc = -1;
int proto_mcje = -1;
int proto_mcbe = -1;

module_t *pref_mc = NULL;
gchar *pref_protocol_data_dir;
module_t *pref_mcje = NULL;
gchar *pref_ignore_packets_je = "";
gchar *pref_secret_key = "";
bool pref_do_nbt_decode = false;

module_t *pref_mcbe = NULL;

void proto_register() {
    proto_register_mcje();
    proto_register_mcbe();

    pref_protocol_data_dir = get_datafile_path("minecraft-protocol");

    // Preference ------------------------------------------------------------------------------------------------------
    proto_mc = proto_register_protocol("Minecraft", "Minecraft", "Minecraft");
    pref_mc = prefs_register_protocol(proto_mc, clear_storage);
    prefs_register_directory_preference(
            pref_mc, "protocol_data_dir", "Protocol Data Directory",
            "Directory for protocol data", (const char **) &pref_protocol_data_dir
    );
    pref_mcje = prefs_register_protocol_subtree("Minecraft", proto_mcje, NULL);
    prefs_register_string_preference(
            pref_mcje, "ignore_packets", "Ignore Packets",
            "Ignore packets with the given names", (const char **) &pref_ignore_packets_je
    );
    prefs_register_string_preference(
            pref_mcje, "secret_key", "Secret Key",
            "Secret key for decryption", (const char **) &pref_secret_key
    );
    prefs_register_bool_preference(
            pref_mcje, "do_nbt_decode", "NBT Decoding",
            "Decode NBT data", &pref_do_nbt_decode
    );

    pref_mcbe = prefs_register_protocol_subtree("Minecraft", proto_mcbe, NULL);
}

void proto_reg_handoff() {
    proto_reg_handoff_mcje();
    proto_reg_handoff_mcbe();
}

_U_ void plugin_register() {
    static proto_plugin plugin;
    if (proto_mcje == -1 || proto_mcbe == -1) {
        plugin.register_protoinfo = proto_register;
        plugin.register_handoff = proto_reg_handoff;
        proto_register_plugin(&plugin);
    }
}