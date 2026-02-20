//
// Created by Nickid2018 on 2023/7/12.
//
#include <ws_version.h>
#include <wsutil/plugins.h>
#include <wsutil/filesystem.h>

#include "mc_dissector.h"
#include "protocol_je/je_dissect.h"
#include "protocol_be/be_dissect.h"

WS_DLL_PUBLIC_DEF _U_ const gchar plugin_version[] = PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF _U_ const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF _U_ const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC _U_ void plugin_register();

WS_DLL_PUBLIC _U_ uint32_t plugin_describe();

int proto_mc = -1;
int proto_mcje = -1;
int proto_mcbe = -1;

module_t *pref_mc = NULL;
gchar *pref_protocol_data_dir;

module_t *pref_mcje = NULL;

module_t *pref_mcbe = NULL;

void reinit() {
    init_storage_je();
    init_storage_be();
}

void proto_register() {
    pref_protocol_data_dir = get_datafile_path("minecraft-protocol");

    // Preference ------------------------------------------------------------------------------------------------------
    proto_mc = proto_register_protocol("Minecraft", "Minecraft", "Minecraft");
    pref_mc = prefs_register_protocol(proto_mc, reinit);
    prefs_register_directory_preference(
        pref_mc, "protocol_data_dir", "Protocol Data Directory",
        "Directory for protocol data", (const char **) &pref_protocol_data_dir
    );

    proto_register_mcje();
    proto_register_mcbe();

    pref_mcje = prefs_register_protocol_subtree("Minecraft", proto_mcje, init_storage_je);
    pref_mcbe = prefs_register_protocol_subtree("Minecraft", proto_mcbe, init_storage_be);

    pref_register_mcje();
    pref_register_mcbe();
}

void proto_reg_handoff() {
    proto_reg_handoff_mcje();
    proto_reg_handoff_mcbe();
    reinit();
}

_U_ void plugin_register() {
    static proto_plugin plugin;
    if (proto_mcje == -1 || proto_mcbe == -1) {
        plugin.register_protoinfo = proto_register;
        plugin.register_handoff = proto_reg_handoff;
        proto_register_plugin(&plugin);
    }
}

uint32_t plugin_describe() {
    return WS_PLUGIN_DESC_DISSECTOR;
}
