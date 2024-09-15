//
// Created by Nickid2018 on 2023/7/13.
//

#ifndef MC_DISSECTOR_JE_DISSECT_H
#define MC_DISSECTOR_JE_DISSECT_H

#include <epan/packet.h>
#include "protocol/protocol_data.h"

extern dissector_handle_t mcje_handle;

extern int ett_mc;
extern int ett_proto;
extern int ett_sub;

void proto_register_mcje();

void proto_reg_handoff_mcje();

int dissect_je_conv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_);

#endif //MC_DISSECTOR_JE_DISSECT_H
