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

gint do_nbt_tree(proto_tree *tree, tvbuff_t *tvb, gint offset, int hfindex, bool is_je, bool need_skip);

gint count_nbt_length_with_type(tvbuff_t *tvb, gint offset, guint type);

gint count_nbt_length(tvbuff_t *tvb, gint offset);

#endif //MC_DISSECTOR_NBT_H
