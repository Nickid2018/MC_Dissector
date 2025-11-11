//
// Created by Nickid2018 on 2023/10/6.
//

#include "nbt.h"
#include "protocol_je/je_dissect.h"

extern int hf_string;

#define is_primitive_type(type) (type != TAG_COMPOUND && type != TAG_LIST && type != TAG_END)

void parse_to_string(
    tvbuff_t *tvb, packet_info *pinfo, int32_t offset_g, uint32_t type, int32_t *length, char **text
) {
    switch (type) {
        case TAG_BYTE:
            *length = 1;
            *text = wmem_strdup_printf(pinfo->pool, "<b>: %d", tvb_get_int8(tvb, offset_g));
            break;
        case TAG_SHORT:
            *length = 2;
            *text = wmem_strdup_printf(pinfo->pool, "<s>: %d", tvb_get_int16(tvb, offset_g, ENC_BIG_ENDIAN));
            break;
        case TAG_INT:
            *length = 4;
            *text = wmem_strdup_printf(pinfo->pool, "<i>: %d", tvb_get_int32(tvb, offset_g, ENC_BIG_ENDIAN));
            break;
        case TAG_LONG:
            *length = 8;
            *text = wmem_strdup_printf(pinfo->pool, "<l>: %ld", tvb_get_int64(tvb, offset_g, ENC_BIG_ENDIAN));
            break;
        case TAG_FLOAT:
            *length = 4;
            *text = wmem_strdup_printf(pinfo->pool, "<f>: %f", tvb_get_ieee_float(tvb, offset_g, ENC_BIG_ENDIAN));
            break;
        case TAG_DOUBLE:
            *length = 8;
            *text = wmem_strdup_printf(pinfo->pool, "<d>: %lf", tvb_get_ieee_double(tvb, offset_g, ENC_BIG_ENDIAN));
            break;
        case TAG_BYTE_ARRAY:
        case TAG_INT_ARRAY:
        case TAG_LONG_ARRAY:
            *length = 4;
            int32_t array_length = tvb_get_int32(tvb, offset_g, ENC_BIG_ENDIAN);
            int32_t element_length = type == TAG_BYTE_ARRAY ? 1 : (type == TAG_INT_ARRAY ? 4 : 8);
            *length += array_length * element_length;

            int32_t record_length = array_length > 20 ? 20 : array_length;
            GPtrArray *array = g_ptr_array_new_with_free_func(g_free);
            for (int i = 0; i < record_length; i++) {
                if (type == TAG_BYTE_ARRAY)
                    g_ptr_array_add(
                        array,
                        g_strdup_printf("%d", tvb_get_int8(tvb, offset_g + 4 + i)
                        )
                    );
                else if (type == TAG_INT_ARRAY)
                    g_ptr_array_add(
                        array,
                        g_strdup_printf("%d", tvb_get_int32(tvb, offset_g + 4 + i * 4, ENC_BIG_ENDIAN)
                        )
                    );
                else
                    g_ptr_array_add(
                        array, g_strdup_printf(
                            "%ld",
                            tvb_get_int64(tvb, offset_g + 4 + i * 8, ENC_BIG_ENDIAN)
                        )
                    );
            }
            char *el_type = type == TAG_BYTE_ARRAY ? "<ba>" : type == TAG_INT_ARRAY ? "<ia>" : "<la>";
            g_ptr_array_add(array, NULL);
            char **built = (char **) g_ptr_array_steal(array, NULL);
            char *elements_text = g_strjoinv(", ", built);
            g_strfreev(built);
            *text = wmem_strdup_printf(
                pinfo->pool,
                record_length == array_length ? "%s: [%d] (%s)" : "%s: [%d] (%s, ...)",
                el_type, array_length, elements_text
            );
            g_free(elements_text);
            break;
        case TAG_STRING:
            *length = 2;
            int32_t string_length = tvb_get_uint16(tvb, offset_g, ENC_BIG_ENDIAN);
            *length += string_length;
            *text = wmem_strdup_printf(
                pinfo->pool, "<str>: %s",
                tvb_format_text(pinfo->pool, tvb, offset_g + 2, string_length)
            );
            break;
        default:
            *length = 0;
            *text = wmem_strdup_printf(pinfo->pool, "<NBT Error> Unknown type '%x'", type);
            break;
    }
}

int32_t add_primitive_type(
    proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
    int offset_global, uint32_t type, char *sup_name
) {
    int32_t length;
    char *text;
    parse_to_string(tvb, pinfo, offset_global, type, &length, &text);
    proto_item *item = proto_tree_add_item(tree, hf_string, tvb, offset_global, 0, ENC_NA);
    proto_item_set_text(item, "%s %s", sup_name, text);
    proto_item_set_len(item, length);
    return length;
}

int32_t add_list_type(
    proto_item *item, packet_info *pinfo, proto_tree *tree,
    tvbuff_t *tvb, int32_t ett, int32_t offset_global, char *sup_name
);

int32_t add_compound_type(
    proto_item *item, packet_info *pinfo, proto_tree *tree,
    tvbuff_t *tvb, int32_t ett, int32_t offset_global, char *sup_name
);

// NOLINTNEXTLINE
int32_t add_list_type(
    proto_item *item, packet_info *pinfo, proto_tree *tree,
    tvbuff_t *tvb, int32_t ett, int32_t offset_global, char *sup_name
) {
    int32_t length = 5;
    uint32_t sub_type = tvb_get_uint8(tvb, offset_global);
    uint32_t sub_length = tvb_get_uint32(tvb, offset_global + 1, ENC_BIG_ENDIAN);

    proto_tree *subtree;
    if (sup_name == NULL)
        subtree = tree;
    else {
        item = proto_tree_add_item(tree, hf_string, tvb, offset_global, 0, ENC_NA);
        subtree = proto_item_add_subtree(item, ett);
        proto_item_set_text(item, "%s", sup_name);
    }
    proto_item_append_text(item, " (%d entries)", sub_length);

    if (is_primitive_type(sub_type)) {
        for (uint32_t i = 0; i < sub_length; i++)
            length += add_primitive_type(
                subtree, pinfo, tvb,
                offset_global + length, sub_type,
                wmem_strdup_printf(pinfo->pool, "%s[%d]", sup_name, i)
            );
    } else if (sub_type == TAG_LIST) {
        for (uint32_t i = 0; i < sub_length; i++)
            length += add_list_type(
                NULL, pinfo, subtree, tvb, ett,
                offset_global + length,
                wmem_strdup_printf(pinfo->pool, "%s[%d]", sup_name, i)
            );
    } else if (sub_type == TAG_COMPOUND) {
        for (uint32_t i = 0; i < sub_length; i++)
            length += add_compound_type(
                NULL, pinfo, subtree, tvb, ett,
                offset_global + length,
                wmem_strdup_printf(pinfo->pool, "%s[%d]", sup_name, i)
            );
    }

    proto_item_set_len(item, length);
    return length;
}

// NOLINTNEXTLINE
int32_t add_compound_type(
    proto_item *item, packet_info *pinfo, proto_tree *tree,
    tvbuff_t *tvb, int32_t ett, int32_t offset_global, char *sup_name
) {
    int32_t length = 1;
    proto_tree *subtree;
    if (sup_name == NULL)
        subtree = tree;
    else {
        item = proto_tree_add_item(tree, hf_string, tvb, offset_global, 0, ENC_NA);
        subtree = proto_item_add_subtree(item, ett);
        proto_item_set_text(item, "%s", sup_name);
    }

    uint32_t sub_type;
    while ((sub_type = tvb_get_uint8(tvb, offset_global + length - 1)) != TAG_END) {
        int32_t name_length = tvb_get_uint16(tvb, offset_global + length, ENC_BIG_ENDIAN);
        char *name = tvb_format_text(pinfo->pool, tvb, offset_global + length + 2, name_length);
        length += 2 + name_length;
        if (is_primitive_type(sub_type)) {
            length += add_primitive_type(
                subtree, pinfo, tvb,
                offset_global + length, sub_type, name
            );
        } else if (sub_type == TAG_LIST) {
            length += add_list_type(
                NULL, pinfo, subtree, tvb, ett,
                offset_global + length, name
            );
        } else if (sub_type == TAG_COMPOUND) {
            length += add_compound_type(
                NULL, pinfo, subtree, tvb, ett,
                offset_global + length, name
            );
        }
        length += 1;
    }

    proto_item_set_len(item, length);
    return length;
}

int32_t do_nbt_tree(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int32_t offset, char *name, bool need_skip) {
    uint32_t type = tvb_get_uint8(tvb, offset);
    int32_t origin_offset = offset;
    if (need_skip)
        offset += 3 + tvb_get_uint16(tvb, offset + 1, ENC_BIG_ENDIAN);
    else
        offset += 1;

    if (is_primitive_type(type)) {
        offset += add_primitive_type(tree, pinfo, tvb, offset, type, name);
    } else {
        proto_item *item = proto_tree_add_item(tree, hf_string, tvb, offset, 0, ENC_NA);
        proto_item_set_text(item, "%s", name);
        proto_tree *subtree = proto_item_add_subtree(item, ett_sub);

        int32_t length = 0;
        if (type == TAG_LIST)
            length = add_list_type(item, pinfo, subtree, tvb, ett_sub, offset, NULL);
        else if (type == TAG_COMPOUND)
            length = add_compound_type(item, pinfo, subtree, tvb, ett_sub, offset, NULL);
        offset += length;

        proto_item_set_len(item, length);
    }
    return offset - origin_offset;
}

// NOLINTNEXTLINE
int32_t count_nbt_length_with_type(tvbuff_t *tvb, int32_t offset, uint32_t type) {
    if (type == TAG_END)
        return 0;
    if (type == TAG_BYTE)
        return 1;
    if (type == TAG_SHORT)
        return 2;
    if (type == TAG_INT || type == TAG_FLOAT)
        return 4;
    if (type == TAG_LONG || type == TAG_DOUBLE)
        return 8;
    if (type == TAG_BYTE_ARRAY)
        return 4 + tvb_get_int32(tvb, offset, ENC_BIG_ENDIAN);
    if (type == TAG_STRING)
        return 2 + tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
    if (type == TAG_LIST) {
        uint32_t sub_type = tvb_get_uint8(tvb, offset);
        if (sub_type == TAG_END)
            return 5;
        uint32_t length = tvb_get_uint32(tvb, offset + 1, ENC_BIG_ENDIAN);
        int32_t sub_length = 0;
        for (uint32_t i = 0; i < length; i++)
            sub_length += count_nbt_length_with_type(tvb, offset + 5 + sub_length, sub_type);
        return 5 + sub_length;
    }
    if (type == TAG_COMPOUND) {
        int32_t sub_length = 0;
        uint32_t sub_type;
        while ((sub_type = tvb_get_uint8(tvb, offset + sub_length)) != TAG_END) {
            int32_t name_length = tvb_get_uint16(tvb, offset + sub_length + 1, ENC_BIG_ENDIAN);
            sub_length += 3 + name_length;
            sub_length += count_nbt_length_with_type(tvb, offset + sub_length, sub_type);
        }
        return sub_length + 1;
    }
    if (type == TAG_INT_ARRAY)
        return 4 + tvb_get_int32(tvb, offset, ENC_BIG_ENDIAN) * 4;
    if (type == TAG_LONG_ARRAY)
        return 4 + tvb_get_int32(tvb, offset, ENC_BIG_ENDIAN) * 8;
    return 0;
}

int32_t count_nbt_length(tvbuff_t *tvb, int32_t offset) {
    uint8_t type = tvb_get_uint8(tvb, offset);
    int32_t skip = tvb_get_uint16(tvb, offset + 1, ENC_BIG_ENDIAN);
    return count_nbt_length_with_type(tvb, offset + 3 + skip, type) + 3 + skip;
}
