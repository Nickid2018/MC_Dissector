//
// Created by Nickid2018 on 2023/7/13.
//

#ifndef MC_DISSECTOR_BE_DISSECT_H
#define MC_DISSECTOR_BE_DISSECT_H

#include <epan/packet.h>

extern dissector_handle_t mcbe_boot_handle, mcbe_handle, ignore_be_handle;

extern int ett_sub_be;
extern wmem_map_t *name_hf_map_be;
extern wmem_map_t *unknown_hf_map_be;

extern int hf_unknown_int_be;
extern int hf_unknown_uint_be;
extern int hf_unknown_int64_be;
extern int hf_unknown_uint64_be;
extern int hf_unknown_float_be;
extern int hf_unknown_double_be;
extern int hf_unknown_bytes_be;
extern int hf_unknown_string_be;
extern int hf_unknown_boolean_be;
extern int hf_unknown_uuid_be;

void proto_register_mcbe();

void proto_reg_handoff_mcbe();

int dissect_be_boot(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_);

int dissect_be_conv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_);

int dissect_be_ignore(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_);

#endif //MC_DISSECTOR_BE_DISSECT_H
