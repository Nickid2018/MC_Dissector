//
// Created by Nickid2018 on 2023/7/12.
//
#include <ws_version.h>

#include "mc_dissector.h"
#include "protocol_data.h"
#include "protocol_je/je_dissect.h"
#include "protocol_be/be_dissect.h"

WS_DLL_PUBLIC_DEF _U_ const gchar plugin_version[] = "0.0.0";
WS_DLL_PUBLIC_DEF _U_ const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF _U_ const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC _U_ void plugin_register();

int proto_mcje = -1;
int proto_mcbe = -1;

_U_ void plugin_register() {
    if (proto_mcje == -1) {
        static proto_plugin plugMCJE;
        plugMCJE.register_protoinfo = proto_register_mcje;
        plugMCJE.register_handoff = proto_reg_handoff_mcje;
        proto_register_plugin(&plugMCJE);
    }
    if (proto_mcbe == -1) {
        static proto_plugin plugMCBE;
        plugMCBE.register_protoinfo = proto_register_mcbe;
        plugMCBE.register_handoff = proto_reg_handoff_mcbe;
        proto_register_plugin(&plugMCBE);
    }
    init_schema_data();
}