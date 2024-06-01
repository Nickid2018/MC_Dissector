//
// Created by Nickid2018 on 2023/10/6.
//

#include "nbt.h"
#include "protocol_je/je_dissect.h"
#include "protocol_be/be_dissect.h"
#include "strings_je.h"

#define is_primitive_type(type) (type != TAG_COMPOUND && type != TAG_LIST && type != TAG_END)

void parse_to_string(tvbuff_t *tvb, int offset_global, guint type, gint *length, char **text) {
    switch (type) {
        case TAG_BYTE:
            *length = 1;
            *text = g_strdup_printf("%d", tvb_get_gint8(tvb, offset_global));
            break;
        case TAG_SHORT:
            *length = 2;
            *text = g_strdup_printf("%d", tvb_get_gint16(tvb, offset_global, ENC_BIG_ENDIAN));
            break;
        case TAG_INT:
            *length = 4;
            *text = g_strdup_printf("%d", tvb_get_gint32(tvb, offset_global, ENC_BIG_ENDIAN));
            break;
        case TAG_LONG:
            *length = 8;
            *text = g_strdup_printf("%ld", tvb_get_gint64(tvb, offset_global, ENC_BIG_ENDIAN));
            break;
        case TAG_FLOAT:
            *length = 4;
            *text = g_strdup_printf("%f", tvb_get_ntohieee_float(tvb, offset_global));
            break;
        case TAG_DOUBLE:
            *length = 8;
            *text = g_strdup_printf("%lf", tvb_get_ntohieee_double(tvb, offset_global));
            break;
        case TAG_BYTE_ARRAY:
        case TAG_INT_ARRAY:
        case TAG_LONG_ARRAY:
            *length = 4;
            gint array_length = tvb_get_gint32(tvb, offset_global, ENC_BIG_ENDIAN);
            gint element_length = type == TAG_BYTE_ARRAY ? 1 : (type == TAG_INT_ARRAY ? 4 : 8);
            *length += array_length * element_length;
            gint record_length = array_length > 20 ? 20 : array_length;
            char **elements = g_new0(char *, record_length);
            for (int i = 0; i < record_length; i++) {
                if (type == TAG_BYTE_ARRAY)
                    elements[i] = g_strdup_printf("%d", tvb_get_gint8(tvb, offset_global + 4 + i));
                else if (type == TAG_INT_ARRAY)
                    elements[i] = g_strdup_printf("%d", tvb_get_gint32(tvb, offset_global + 4 + i * 4, ENC_BIG_ENDIAN));
                else
                    elements[i] = g_strdup_printf("%ld", tvb_get_gint64(tvb, offset_global + 4 + i * 8, ENC_BIG_ENDIAN));
            }
            char *elements_text = g_strjoinv(", ", elements);
            g_strfreev(elements);
            *text = g_strdup_printf(record_length == array_length ? "[%d] (%s)" : "[%d] (%s, ...)",
                                    array_length, elements_text);
            break;
        case TAG_STRING:
            *length = 2;
            gint string_length = tvb_get_guint16(tvb, offset_global, ENC_BIG_ENDIAN);
            *length += string_length;
            *text = tvb_bytes_to_str(wmem_packet_scope(), tvb, offset_global + 2, string_length);
            break;
        default:
            *length = 0;
            *text = g_strdup_printf("Unknown type '%x'", type);
            break;
    }
}

gint add_primitive_type_hf(proto_tree *tree, tvbuff_t *tvb, int offset_global, guint type, int hfindex) {
    gint length;
    char *text;
    parse_to_string(tvb, offset_global, type, &length, &text);
    proto_item *item = proto_tree_add_item(tree, hfindex, tvb, offset_global, 1, ENC_NA);
    proto_item_append_text(item, " - <%s>", text);
    proto_item_set_len(item, length);
    return length;
}

gint add_primitive_type(proto_tree *tree, tvbuff_t *tvb, gint hf_text, int offset_global, guint type, gchar *sup_name) {
    gint length;
    char *text;
    parse_to_string(tvb, offset_global, type, &length, &text);
    proto_item *item = proto_tree_add_item(tree, hf_text, tvb, offset_global, 0, ENC_NA);
    proto_item_set_text(item, "%s: %s", sup_name, text);
    proto_item_set_len(item, length);
    return length;
}

gint add_list_type(proto_item *item, proto_tree *tree, tvbuff_t *tvb, gint ett, gint hf_text, int offset_global, gchar *sup_name);

gint add_compound_type(proto_item *item, proto_tree *tree, tvbuff_t *tvb, gint ett, gint hf_text, int offset_global, gchar *sup_name);

gint add_list_type(proto_item *item, proto_tree *tree, tvbuff_t *tvb, gint ett, gint hf_text, int offset_global, gchar *sup_name) {
    gint length = 5;
    guint sub_type = tvb_get_guint8(tvb, offset_global);
    guint sub_length = tvb_get_guint32(tvb, offset_global + 1, ENC_BIG_ENDIAN);

    proto_tree *subtree;
    if (sup_name == NULL)
        subtree = tree;
    else {
        item = proto_tree_add_item(tree, hf_text, tvb, offset_global, 0, ENC_NA);
        subtree = proto_item_add_subtree(item, ett);
        proto_item_set_text(item, "%s", sup_name);
    }
    proto_item_append_text(item, " (%d entries)", sub_length);

    if (is_primitive_type(sub_type)) {
        for (guint i = 0; i < sub_length; i++)
            length += add_primitive_type(
                    subtree, tvb, hf_text,
                    offset_global + length, sub_type,
                    g_strdup_printf("[%d]", i)
            );
    } else if (sub_type == TAG_LIST) {
        for (guint i = 0; i < sub_length; i++)
            length += add_list_type(
                    NULL, subtree, tvb, ett, hf_text,
                    offset_global + length,
                    g_strdup_printf("[%d]", i)
            );
    } else if (sub_type == TAG_COMPOUND) {
        for (guint i = 0; i < sub_length; i++)
            length += add_compound_type(
                    NULL, subtree, tvb, ett, hf_text,
                    offset_global + length,
                    g_strdup_printf("[%d]", i)
            );
    }

    proto_item_set_len(item, length);
    return length;
}

gint add_compound_type(proto_item *item, proto_tree *tree, tvbuff_t *tvb, gint ett, gint hf_text, int offset_global, gchar *sup_name) {
    gint length = 1;
    proto_tree *subtree;
    if (sup_name == NULL)
        subtree = tree;
    else {
        item = proto_tree_add_item(tree, hf_text, tvb, offset_global, 0, ENC_NA);
        subtree = proto_item_add_subtree(item, ett);
        proto_item_set_text(item, "%s", sup_name);
    }

    guint sub_type;
    while ((sub_type = tvb_get_guint8(tvb, length - 1)) != TAG_END) {
        gint name_length = tvb_get_guint16(tvb, length, ENC_BIG_ENDIAN);
        gchar *name = tvb_bytes_to_str(wmem_packet_scope(), tvb, length + 2, name_length);
        length += 2 + name_length;
        if (is_primitive_type(sub_type)) {
            length += add_primitive_type(
                    subtree, tvb, hf_text,
                    offset_global + length, sub_type, name
            );
        } else if (sub_type == TAG_LIST) {
            length += add_list_type(
                    NULL, subtree, tvb, ett, hf_text,
                    offset_global + length, name
            );
        } else if (sub_type == TAG_COMPOUND) {
            length += add_compound_type(
                    NULL, subtree, tvb, ett, hf_text,
                    offset_global + length, name
            );
        }
        length += 1;
    }

    proto_item_set_len(item, length);
    return length;
}

guint do_nbt_tree(proto_tree *tree, tvbuff_t *tvb, gint offset, int hfindex, bool is_je, bool need_skip) {
    guint8 type = tvb_get_guint8(tvb, offset);
    guint origin_offset = offset;
    if (need_skip)
        offset += 3 + tvb_get_guint16(tvb, offset + 1, ENC_BIG_ENDIAN);
    else
        offset += 1;

    if (is_primitive_type(type)) {
        offset += add_primitive_type_hf(tree, tvb, offset, type, hfindex);
    } else {
        int ett = is_je ? ett_sub_je : ett_sub_be;
        int hf_text = is_je ? get_string_je("text_je", "bytes") : hf_text_be;
        proto_item *item = proto_tree_add_item(tree, hfindex, tvb, offset, 1, ENC_NA);
        proto_tree *subtree = proto_item_add_subtree(item, ett);

        gint length = 0;
        if (type == TAG_LIST)
            length = add_list_type(item, subtree, tvb, ett, hf_text, offset, NULL);
        else if (type == TAG_COMPOUND)
            length = add_compound_type(item, subtree, tvb, ett, hf_text, offset, NULL);
        offset += length;

        proto_item_set_len(item, length);
    }
    return offset - origin_offset;
}

guint count_nbt_length_with_type(const guint8 *data, guint type) {
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
        return 4 + ((((gint) data[0] & 0xff) << 24) | ((data[1] & 0xff) << 16) |
                    ((data[2] & 0xff) << 8) | (data[3] & 0xff));
    if (type == TAG_STRING)
        return 2 + ((((gint) data[0] & 0xff) << 8) | (data[1] & 0xff));
    if (type == TAG_LIST) {
        guint sub_type = data[0];
        if (sub_type == TAG_END)
            return 5;
        guint length = ((((gint) data[1] & 0xff) << 24) | ((data[2] & 0xff) << 16) |
                        ((data[3] & 0xff) << 8) | (data[4] & 0xff));
        guint sub_length = 0;
        for (guint i = 0; i < length; i++)
            sub_length += count_nbt_length_with_type(data + 5 + sub_length, sub_type);
        return 5 + sub_length;
    }
    if (type == TAG_COMPOUND) {
        guint sub_length = 0;
        guint sub_type;
        while ((sub_type = data[sub_length]) != TAG_END) {
            gint name_length = ((((gint) data[sub_length + 1] & 0xff) << 8) | (data[sub_length + 2] & 0xff));
            sub_length += 3 + name_length;
            sub_length += count_nbt_length_with_type(data + sub_length, sub_type);
        }
        return sub_length + 1;
    }
    if (type == TAG_INT_ARRAY)
        return 4 + ((((gint) data[0] & 0xff) << 24) | ((data[1] & 0xff) << 16) |
                    ((data[2] & 0xff) << 8) | (data[3] & 0xff)) * 4;
    if (type == TAG_LONG_ARRAY)
        return 4 + ((((gint) data[0] & 0xff) << 24) | ((data[1] & 0xff) << 16) |
                    ((data[2] & 0xff) << 8) | (data[3] & 0xff)) * 8;
    return 0;
}

guint count_nbt_length(const guint8 *data) {
    guint8 type = data[0];
    gint skip = ((((gint) data[1] & 0xff) << 8) | (data[2] & 0xff));
    guint length = count_nbt_length_with_type(data + 3 + skip, type);
    return length + 3 + skip;
}