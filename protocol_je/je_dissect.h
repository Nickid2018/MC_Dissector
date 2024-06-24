//
// Created by Nickid2018 on 2023/7/13.
//

#ifndef MC_DISSECTOR_JE_DISSECT_H
#define MC_DISSECTOR_JE_DISSECT_H

#include <epan/packet.h>
#include "protocol/protocol_data.h"

extern dissector_handle_t mcje_handle;

extern int ett_mcje;
extern int ett_je_proto;
extern int ett_sub_je;

void proto_register_mcje();

void proto_reg_handoff_mcje();

void sub_dissect_je(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, mcje_protocol_context *ctx,
                    bool is_client, bool visited);

int dissect_je_core(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

int dissect_je_conv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_);

#endif //MC_DISSECTOR_JE_DISSECT_H
