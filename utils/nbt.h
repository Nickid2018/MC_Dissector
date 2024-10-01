//
// Created by Nickid2018 on 2023/10/6.
//

#ifndef MC_DISSECTOR_NBT_H
#define MC_DISSECTOR_NBT_H

#include <epan/proto.h>

#define TAG_END        0
#define TAG_BYTE       1
#define TAG_SHORT      2
#define TAG_INT        3
#define TAG_LONG       4
#define TAG_FLOAT      5
#define TAG_DOUBLE     6
#define TAG_BYTE_ARRAY 7
#define TAG_STRING     8
#define TAG_LIST       9
#define TAG_COMPOUND   10
#define TAG_INT_ARRAY  11
#define TAG_LONG_ARRAY 12

int32_t do_nbt_tree(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int32_t offset, char *name, bool need_skip);

int32_t count_nbt_length_with_type(tvbuff_t *tvb, int32_t offset, uint32_t type);

int32_t count_nbt_length(tvbuff_t *tvb, int32_t offset);

#endif //MC_DISSECTOR_NBT_H
