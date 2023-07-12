//
// Created by Nickid2018 on 2023/7/12.
//
#include <config.h>

#define WS_BUILD_DLL

#include "mc_dissector.h"
#include <epan/packet.h>

WS_DLL_PUBLIC_DEF const gchar plugin_version[] = "0.0.0";
WS_DLL_PUBLIC_DEF const int plugin_want_major = VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = VERSION_MINOR;
WS_DLL_PUBLIC void plugin_register(void);

int proto_mcje = -1;
int proto_mcbe = -1;

void proto_register_mcje() {
    if (proto_mcje == -1) {
        proto_mcje = proto_register_protocol(MCJE_NAME, MCJE_SHORT_NAME, MCJE_FILTER);
    }
}

void proto_register_mcbe() {
    if (proto_mcbe == -1) {
        proto_mcbe = proto_register_protocol(MCBE_NAME, MCBE_SHORT_NAME, MCBE_FILTER);
    }
}

static int dissect_mcje(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Test");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    return tvb_captured_length(tvb);
}

static int dissect_mcbe(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Test");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    return tvb_captured_length(tvb);
}

void proto_reg_handoff_mcje() {
    static dissector_handle_t mcje_handle;
    mcje_handle = create_dissector_handle(dissect_mcje, proto_mcje);
    dissector_add_uint("tcp.port", MCJE_PORT, mcje_handle);
}

void proto_reg_handoff_mcbe() {
    static dissector_handle_t mcbe_handle;
    mcbe_handle = create_dissector_handle(dissect_mcbe, proto_mcbe);
    dissector_add_uint("udp.port", MCBE_PORT, mcbe_handle);
}

void plugin_register(void) {
    static proto_plugin plugMCJE;

    plugMCJE.register_protoinfo = proto_register_mcje;
    plugMCJE.register_handoff = proto_reg_handoff_mcje;
    proto_register_plugin(&plugMCJE);

    static proto_plugin plugMCBE;

    plugMCBE.register_protoinfo = proto_register_mcbe;
    plugMCBE.register_handoff = proto_reg_handoff_mcbe;
    proto_register_plugin(&plugMCBE);
}