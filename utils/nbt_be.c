#include "nbt.h"
#include "protocol/protocol_data.h"

extern int hf_string_be;
extern int ett_sub_be;

void be_tag_parse_to_string(
    tvbuff_t *tvb, packet_info *pinfo, int32_t offset_g, uint32_t type, int32_t *length, char **text
) {
    switch (type) {
        case TAG_BYTE:
            *length = 1;
            *text = wmem_strdup_printf(pinfo->pool, "<b>: %d", tvb_get_int8(tvb, offset_g));
            break;
        case TAG_SHORT:
            *length = 2;
            *text = wmem_strdup_printf(pinfo->pool, "<s>: %d", tvb_get_int16(tvb, offset_g, ENC_LITTLE_ENDIAN));
            break;
        case TAG_INT:
            int32_t result_i;
            *length = read_var_int(tvb, offset_g, &result_i);
            *text = wmem_strdup_printf(pinfo->pool, "<i>: %d", result_i);
            break;
        case TAG_LONG:
            int64_t result_l;
            *length = read_var_long(tvb, offset_g, &result_l);
            *text = wmem_strdup_printf(pinfo->pool, "<l>: %ld", result_l);
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
            int32_t array_length;
            *length = read_var_int(tvb, offset_g, &array_length);

            int32_t record_length = array_length > 20 ? 20 : array_length;
            GPtrArray *array = g_ptr_array_new_with_free_func(g_free);
            for (int i = 0; i < array_length; i++) {
                if (type == TAG_BYTE_ARRAY) {
                    *length += 1;
                    if (i < record_length)
                        g_ptr_array_add(
                            array,
                            g_strdup_printf("%d", tvb_get_int8(tvb, offset_g + *length))
                        );
                } else {
                    int32_t data;
                    *length += read_var_int(tvb, offset_g + *length, &data);
                    if (i < record_length)
                        g_ptr_array_add(array,g_strdup_printf("%d", data));
                }
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
            int32_t string_length;
            *length = read_var_int(tvb, offset_g, &string_length);
            *text = wmem_strdup_printf(
                pinfo->pool, "<str>: %s",
                tvb_format_text(pinfo->pool, tvb, offset_g + *length, string_length)
            );
            *length += string_length;
            break;
        default:
            *length = 0;
            *text = wmem_strdup_printf(pinfo->pool, "<NBT Error> Unknown type '%x'", type);
            break;
    }
}

int32_t add_be_primitive_type(
    proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
    int offset_global, uint32_t type, char *sup_name
) {
    int32_t length;
    char *text;
    be_tag_parse_to_string(tvb, pinfo, offset_global, type, &length, &text);
    proto_item *item = proto_tree_add_item(tree, hf_string_be, tvb, offset_global, 0, ENC_NA);
    proto_item_set_text(item, "%s %s", sup_name, text);
    proto_item_set_len(item, length);
    return length;
}

int32_t add_be_list_type(
    proto_item *item, packet_info *pinfo, proto_tree *tree,
    tvbuff_t *tvb, int32_t ett, int32_t offset_global, char *sup_name
);

int32_t add_be_compound_type(
    proto_item *item, packet_info *pinfo, proto_tree *tree,
    tvbuff_t *tvb, int32_t ett, int32_t offset_global, char *sup_name
);

// NOLINTNEXTLINE
int32_t add_be_list_type(
    proto_item *item, packet_info *pinfo, proto_tree *tree,
    tvbuff_t *tvb, int32_t ett, int32_t offset_global, char *sup_name
) {
    int32_t length = 1;
    uint32_t sub_type = tvb_get_uint8(tvb, offset_global);
    int32_t sub_length;
    length += read_var_int(tvb, offset_global + 1, &sub_length);

    proto_tree *subtree;
    if (sup_name == NULL)
        subtree = tree;
    else {
        item = proto_tree_add_item(tree, hf_string_be, tvb, offset_global, 0, ENC_NA);
        subtree = proto_item_add_subtree(item, ett);
        proto_item_set_text(item, "%s", sup_name);
    }
    proto_item_append_text(item, " (%d entries)", sub_length);

    if (is_primitive_type(sub_type)) {
        for (uint32_t i = 0; i < sub_length; i++)
            length += add_be_primitive_type(
                subtree, pinfo, tvb,
                offset_global + length, sub_type,
                wmem_strdup_printf(pinfo->pool, "%s[%d]", sup_name, i)
            );
    } else if (sub_type == TAG_LIST) {
        for (uint32_t i = 0; i < sub_length; i++)
            length += add_be_list_type(
                NULL, pinfo, subtree, tvb, ett,
                offset_global + length,
                wmem_strdup_printf(pinfo->pool, "%s[%d]", sup_name, i)
            );
    } else if (sub_type == TAG_COMPOUND) {
        for (uint32_t i = 0; i < sub_length; i++)
            length += add_be_compound_type(
                NULL, pinfo, subtree, tvb, ett,
                offset_global + length,
                wmem_strdup_printf(pinfo->pool, "%s[%d]", sup_name, i)
            );
    }

    proto_item_set_len(item, length);
    return length;
}

// NOLINTNEXTLINE
int32_t add_be_compound_type(
    proto_item *item, packet_info *pinfo, proto_tree *tree,
    tvbuff_t *tvb, int32_t ett, int32_t offset_global, char *sup_name
) {
    int32_t length = 1;
    proto_tree *subtree;
    if (sup_name == NULL)
        subtree = tree;
    else {
        item = proto_tree_add_item(tree, hf_string_be, tvb, offset_global, 0, ENC_NA);
        subtree = proto_item_add_subtree(item, ett);
        proto_item_set_text(item, "%s", sup_name);
    }

    uint32_t sub_type;
    while ((sub_type = tvb_get_uint8(tvb, offset_global + length - 1)) != TAG_END) {
        int32_t name_length;
        int32_t name_len_len = read_var_int(tvb, offset_global + length, &name_length);
        char *name = tvb_format_text(pinfo->pool, tvb, offset_global + length + name_len_len, name_length);
        length += name_len_len + name_length;
        if (is_primitive_type(sub_type)) {
            length += add_be_primitive_type(
                subtree, pinfo, tvb,
                offset_global + length, sub_type, name
            );
        } else if (sub_type == TAG_LIST) {
            length += add_be_list_type(
                NULL, pinfo, subtree, tvb, ett,
                offset_global + length, name
            );
        } else if (sub_type == TAG_COMPOUND) {
            length += add_be_compound_type(
                NULL, pinfo, subtree, tvb, ett,
                offset_global + length, name
            );
        }
        length += 1;
    }

    proto_item_set_len(item, length);
    return length;
}

int32_t do_be_nbt_tree(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int32_t offset, char *name) {
    uint32_t type = tvb_get_uint8(tvb, offset);
    int32_t origin_offset = offset;
    int32_t name_len;
    offset += 1 + read_var_int(tvb, offset + 1, &name_len);
    offset += name_len;

    if (is_primitive_type(type)) {
        offset += add_be_primitive_type(tree, pinfo, tvb, offset, type, name);
    } else {
        proto_item *item = proto_tree_add_item(tree, hf_string_be, tvb, offset, 0, ENC_NA);
        proto_item_set_text(item, "%s", name);
        proto_tree *subtree = proto_item_add_subtree(item, ett_sub_be);

        int32_t length = 0;
        if (type == TAG_LIST)
            length = add_be_list_type(item, pinfo, subtree, tvb, ett_sub_be, offset, NULL);
        else if (type == TAG_COMPOUND)
            length = add_be_compound_type(item, pinfo, subtree, tvb, ett_sub_be, offset, NULL);
        offset += length;

        proto_item_set_len(item, length);
    }
    return offset - origin_offset;
}

int32_t count_be_nbt_length_with_type(tvbuff_t *tvb, int32_t offset, uint32_t type) {
    if (type == TAG_END)
        return 0;
    if (type == TAG_BYTE)
        return 1;
    if (type == TAG_SHORT)
        return 2;
    if (type == TAG_FLOAT)
        return 4;
    if (type == TAG_DOUBLE)
        return 8;
    if (type == TAG_INT) {
        int32_t uncare;
        int32_t length = read_var_int(tvb, offset, &uncare);
        return length;
    }
    if (type == TAG_LONG) {
        int64_t uncare;
        int32_t length = read_var_long(tvb, offset, &uncare);
        return length;
    }
    if (type == TAG_BYTE_ARRAY || type == TAG_STRING) {
        int32_t len;
        int32_t length = read_var_int(tvb, offset, &len);
        return length + len;
    }
    if (type == TAG_LIST) {
        uint32_t sub_type = tvb_get_uint8(tvb, offset);
        int32_t len;
        int32_t length = read_var_int(tvb, offset, &len);
        if (sub_type == TAG_END)
            return 1 + length;
        int32_t sub_length = 0;
        for (uint32_t i = 0; i < len; i++)
            sub_length += count_be_nbt_length_with_type(tvb, offset + 1 + length + sub_length, sub_type);
        return 1 + length + sub_length;
    }
    if (type == TAG_COMPOUND) {
        int32_t sub_length = 0;
        uint32_t sub_type;
        while ((sub_type = tvb_get_uint8(tvb, offset + sub_length)) != TAG_END) {
            int32_t name_length;
            int32_t length = read_var_int(tvb, offset, &name_length);
            sub_length += 1 + length + name_length;
            sub_length += count_be_nbt_length_with_type(tvb, offset + sub_length, sub_type);
        }
        return sub_length + 1;
    }
    if (type == TAG_INT_ARRAY) {
        int32_t len;
        int32_t length = read_var_int(tvb, offset, &len);
        for (uint32_t i = 0; i < len; i++) {
            int32_t uncare;
            length += read_var_int(tvb, offset + 1 + length, &uncare);
        }
        return 1 + length;
    }
    return 0;
}

int32_t count_be_nbt_length(tvbuff_t *tvb, int32_t offset) {
    uint8_t type = tvb_get_uint8(tvb, offset);
    int32_t name_length;
    int32_t length = read_var_int(tvb, offset, &name_length);
    return count_be_nbt_length_with_type(tvb, offset + 1 + length + name_length, type) + 1 + length + name_length;
}
