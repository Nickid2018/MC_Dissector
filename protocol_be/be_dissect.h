//
// Created by Nickid2018 on 2023/7/13.
//

#ifndef MC_DISSECTOR_BE_DISSECT_H
#define MC_DISSECTOR_BE_DISSECT_H

#include <epan/packet.h>

#define MSG_GAME 0xFE

extern dissector_handle_t mcbe_handle;

extern int ett_sub_be;

void proto_register_mcbe();

void proto_reg_handoff_mcbe();

void init_storage_be();

void pref_register_mcbe();

int dissect_be_conv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_);

bool dissect_be_core_heuristic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);

#endif //MC_DISSECTOR_BE_DISSECT_H
