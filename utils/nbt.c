//
// Created by Nickid2018 on 2023/10/6.
//

#include "nbt.h"
#include "protocol_je/je_dissect.h"

extern int hf_string;

#define is_primitive_type(type) (type != TAG_COMPOUND && type != TAG_LIST && type != TAG_END)

void parse_to_string(tvbuff_t *tvb, packet_info *pinfo, int offset_global, guint type, gint *length, char **text) {
    switch (type) {
        case TAG_BYTE:
            *length = 1;
            *text = g_strdup_printf("<b>: %d", tvb_get_int8(tvb, offset_global));
            break;
        case TAG_SHORT:
            *length = 2;
            *text = g_strdup_printf("<s>: %d", tvb_get_int16(tvb, offset_global, ENC_BIG_ENDIAN));
            break;
        case TAG_INT:
            *length = 4;
            *text = g_strdup_printf("<i>: %d", tvb_get_int32(tvb, offset_global, ENC_BIG_ENDIAN));
            break;
        case TAG_LONG:
            *length = 8;
            *text = g_strdup_printf("<l>: %ld", tvb_get_int64(tvb, offset_global, ENC_BIG_ENDIAN));
            break;
        case TAG_FLOAT:
            *length = 4;
            *text = g_strdup_printf("<f>: %f", tvb_get_ntohieee_float(tvb, offset_global));
            break;
        case TAG_DOUBLE:
            *length = 8;
            *text = g_strdup_printf("<d>: %lf", tvb_get_ntohieee_double(tvb, offset_global));
            break;
        case TAG_BYTE_ARRAY:
        case TAG_INT_ARRAY:
        case TAG_LONG_ARRAY:
            *length = 4;
            gint array_length = tvb_get_int32(tvb, offset_global, ENC_BIG_ENDIAN);
            gint element_length = type == TAG_BYTE_ARRAY ? 1 : (type == TAG_INT_ARRAY ? 4 : 8);
            *length += array_length * element_length;

            gint record_length = array_length > 20 ? 20 : array_length;
            char **elements = g_new0(char *, record_length);
            for (int i = 0; i < record_length; i++) {
                if (type == TAG_BYTE_ARRAY)
                    elements[i] = g_strdup_printf("%d", tvb_get_int8(tvb, offset_global + 4 + i));
                else if (type == TAG_INT_ARRAY)
                    elements[i] = g_strdup_printf("%d", tvb_get_int32(tvb, offset_global + 4 + i * 4, ENC_BIG_ENDIAN));
                else
                    elements[i] = g_strdup_printf(
                            "%ld",
                            tvb_get_int64(tvb, offset_global + 4 + i * 8, ENC_BIG_ENDIAN));
            }
            char *el_type = type == TAG_BYTE_ARRAY ? "<ba>" : (type == TAG_INT_ARRAY ? "<ia>" : "<la>");
            char *elements_text = g_strjoinv(", ", elements);
            g_strfreev(elements);
            *text = g_strdup_printf(
                    record_length == array_length ? "%s: [%d] (%s)" : "%s: [%d] (%s, ...)",
                    el_type, array_length, elements_text
            );
            g_free(elements_text);
            break;
        case TAG_STRING:
            *length = 2;
            gint string_length = tvb_get_uint16(tvb, offset_global, ENC_BIG_ENDIAN);
            *length += string_length;
            *text = g_strdup_printf("<str>: %s", tvb_format_text(pinfo->pool, tvb, offset_global + 2, string_length));
            break;
        default:
            *length = 0;
            *text = g_strdup_printf("Unknown type '%x'", type);
            break;
    }
}

gint add_primitive_type(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                        int offset_global, guint type, gchar *sup_name) {
    gint length;
    char *text;
    parse_to_string(tvb, pinfo, offset_global, type, &length, &text);
    proto_item *item = proto_tree_add_item(tree, hf_string, tvb, offset_global, 0, ENC_NA);
    proto_item_set_text(item, "%s %s", sup_name, text);
    proto_item_set_len(item, length);
    return length;
}

gint add_list_type(proto_item *item, packet_info *pinfo, proto_tree *tree,
                   tvbuff_t *tvb, gint ett, int offset_global, gchar *sup_name);

gint add_compound_type(proto_item *item, packet_info *pinfo, proto_tree *tree,
                       tvbuff_t *tvb, gint ett, int offset_global, gchar *sup_name);

// NOLINTNEXTLINE
gint add_list_type(proto_item *item, packet_info *pinfo, proto_tree *tree,
                   tvbuff_t *tvb, gint ett, int offset_global, gchar *sup_name) {
    gint length = 5;
    guint sub_type = tvb_get_uint8(tvb, offset_global);
    guint sub_length = tvb_get_uint32(tvb, offset_global + 1, ENC_BIG_ENDIAN);

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
        for (guint i = 0; i < sub_length; i++)
            length += add_primitive_type(
                    subtree, pinfo, tvb,
                    offset_global + length, sub_type,
                    g_strdup_printf("%s[%d]", sup_name, i)
            );
    } else if (sub_type == TAG_LIST) {
        for (guint i = 0; i < sub_length; i++)
            length += add_list_type(
                    NULL, pinfo, subtree, tvb, ett,
                    offset_global + length,
                    g_strdup_printf("%s[%d]", sup_name, i)
            );
    } else if (sub_type == TAG_COMPOUND) {
        for (guint i = 0; i < sub_length; i++)
            length += add_compound_type(
                    NULL, pinfo, subtree, tvb, ett,
                    offset_global + length,
                    g_strdup_printf("%s[%d]", sup_name, i)
            );
    }

    proto_item_set_len(item, length);
    return length;
}

// NOLINTNEXTLINE
gint add_compound_type(proto_item *item, packet_info *pinfo, proto_tree *tree,
                       tvbuff_t *tvb, gint ett, int offset_global, gchar *sup_name) {
    gint length = 1;
    proto_tree *subtree;
    if (sup_name == NULL)
        subtree = tree;
    else {
        item = proto_tree_add_item(tree, hf_string, tvb, offset_global, 0, ENC_NA);
        subtree = proto_item_add_subtree(item, ett);
        proto_item_set_text(item, "%s", sup_name);
    }

    guint sub_type;
    while ((sub_type = tvb_get_uint8(tvb, offset_global + length - 1)) != TAG_END) {
        gint name_length = tvb_get_uint16(tvb, offset_global + length, ENC_BIG_ENDIAN);
        gchar *name = tvb_format_text(pinfo->pool, tvb, offset_global + length + 2, name_length);
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

gint do_nbt_tree(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, gint offset, gchar *name, bool need_skip) {
    guint8 type = tvb_get_uint8(tvb, offset);
    gint origin_offset = offset;
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

        gint length = 0;
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
gint count_nbt_length_with_type(tvbuff_t *tvb, gint offset, guint type) {
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
        guint sub_type = tvb_get_uint8(tvb, offset);
        if (sub_type == TAG_END)
            return 5;
        guint length = tvb_get_uint32(tvb, offset + 1, ENC_BIG_ENDIAN);
        gint sub_length = 0;
        for (guint i = 0; i < length; i++)
            sub_length += count_nbt_length_with_type(tvb, offset + 5 + sub_length, sub_type);
        return 5 + sub_length;
    }
    if (type == TAG_COMPOUND) {
        gint sub_length = 0;
        guint sub_type;
        while ((sub_type = tvb_get_uint8(tvb, offset + sub_length)) != TAG_END) {
            gint name_length = tvb_get_uint16(tvb, offset + sub_length + 1, ENC_BIG_ENDIAN);
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

gint count_nbt_length(tvbuff_t *tvb, gint offset) {
    guint8 type = tvb_get_uint8(tvb, offset);
    gint skip = tvb_get_uint16(tvb, offset + 1, ENC_BIG_ENDIAN);
    return count_nbt_length_with_type(tvb, offset + 3 + skip, type) + 3 + skip;
}