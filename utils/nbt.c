//
// Created by Nickid2018 on 2023/10/6.
//

#include "nbt.h"
#include "protocol_je/je_dissect.h"
#include "protocol_be/be_dissect.h"

#define is_primitive_type(type) (type != TAG_COMPOUND && type != TAG_LIST && type != TAG_END)

void parse_to_string(tvbuff_t *tvb, const guint8 *data, int offset_global, guint type, guint *length, char **text) {
    switch (type) {
        case TAG_BYTE:
            *length = 1;
            *text = g_strdup_printf("%d", data[0]);
            break;
        case TAG_SHORT:
            *length = 2;
            *text = g_strdup_printf("%d", (((gint) data[0] & 0xff) << 8) | (data[1] & 0xff));
            break;
        case TAG_INT:
            *length = 4;
            *text = g_strdup_printf("%d", ((((gint) data[0] & 0xff) << 24) | ((data[1] & 0xff) << 16) |
                                           ((data[2] & 0xff) << 8) | (data[3] & 0xff)));
            break;
        case TAG_LONG:
            *length = 8;
            *text = g_strdup_printf("%lld", ((((gint64) data[0] & 0xff) << 56) | ((gint64) (data[1] & 0xff) << 48) |
                                             ((gint64) (data[2] & 0xff) << 40) | ((gint64) (data[3] & 0xff) << 32) |
                                             ((gint64) (data[4] & 0xff) << 24) | ((gint64) (data[5] & 0xff) << 16) |
                                             ((gint64) (data[6] & 0xff) << 8) | ((gint64) (data[7] & 0xff))));
            break;
        case TAG_FLOAT:
            *length = 4;
            *text = g_strdup_printf("%f", tvb_get_ntohieee_float(tvb, offset_global));
            break;
        case TAG_DOUBLE:
            *length = 8;
            *text = g_strdup_printf("%llf", tvb_get_ntohieee_double(tvb, offset_global));
            break;
        case TAG_BYTE_ARRAY:
        case TAG_INT_ARRAY:
        case TAG_LONG_ARRAY:
            *length = 4;
            gint array_length = ((((gint) data[0] & 0xff) << 24) | ((data[1] & 0xff) << 16) |
                                 ((data[2] & 0xff) << 8) | (data[3] & 0xff));
            gint element_length = type == TAG_BYTE_ARRAY ? 1 : (type == TAG_INT_ARRAY ? 4 : 8);
            *length += array_length * element_length;
            gint record_length = array_length > 20 ? 20 : array_length;
            char **elements = g_new0(char *, record_length);
            for (int i = 0; i < record_length; i++) {
                if (type == TAG_BYTE_ARRAY)
                    elements[i] = g_strdup_printf("%d", data[4 + i]);
                else if (type == TAG_INT_ARRAY)
                    elements[i] = g_strdup_printf("%d", ((((gint) data[4 + i * 4] & 0xff) << 24) |
                                                         ((data[4 + i * 4 + 1] & 0xff) << 16) |
                                                         ((data[4 + i * 4 + 2] & 0xff) << 8) |
                                                         (data[4 + i * 4 + 3] & 0xff)));
                else
                    elements[i] = g_strdup_printf("%lld", ((((gint64) data[4 + i * 8] & 0xff) << 56) |
                                                           ((gint64) (data[4 + i * 8 + 1] & 0xff) << 48) |
                                                           ((gint64) (data[4 + i * 8 + 2] & 0xff) << 40) |
                                                           ((gint64) (data[4 + i * 8 + 3] & 0xff) << 32) |
                                                           ((gint64) (data[4 + i * 8 + 4] & 0xff) << 24) |
                                                           ((gint64) (data[4 + i * 8 + 5] & 0xff) << 16) |
                                                           ((gint64) (data[4 + i * 8 + 6] & 0xff) << 8) |
                                                           ((gint64) (data[4 + i * 8 + 7] & 0xff))));
            }
            char *elements_text = g_strjoinv(", ", elements);
            g_strfreev(elements);
            *text = g_strdup_printf(record_length == array_length ? "[%d] (%s)" : "[%d] (%s, ...)",
                                    array_length, elements_text);
            break;
        default:
            *length = 0;
            *text = g_strdup_printf("Unknown type '%x'", type);
            break;
    }
}

guint add_primitive_type_hf(const proto_tree *tree, tvbuff_t *tvb,
                            const guint8 *data, int offset_global, guint type, int hfindex) {
    guint length;
    char *text;
    parse_to_string(tvb, data, offset_global, type, &length, &text);
    proto_item *item = proto_tree_add_item(tree, hfindex, tvb, offset_global, length, ENC_NA);
    proto_item_append_text(item, " %s", text);
    return length;
}

guint add_primitive_type(const proto_tree *tree, tvbuff_t *tvb, gint hf_text,
                         const guint8 *data, int offset_global, guint type, gchar *sup_name) {
    guint length;
    char *text;
    parse_to_string(tvb, data, offset_global, type, &length, &text);
    proto_item *item = proto_tree_add_item(tree, hf_text, tvb, offset_global, length, ENC_NA);
    proto_item_set_text(item, "%s: %s", sup_name, text);
    return length;
}

guint add_list_type(proto_item *item, const proto_tree *tree, tvbuff_t *tvb, gint ett, gint hf_text,
                    const guint8 *data, int offset_global, gchar *sup_name);

guint add_compound_type(proto_item *item, const proto_tree *tree, tvbuff_t *tvb, gint ett, gint hf_text,
                        const guint8 *data, int offset_global, gchar *sup_name);

guint add_list_type(proto_item *item, const proto_tree *tree, tvbuff_t *tvb, gint ett, gint hf_text,
                    const guint8 *data, int offset_global, gchar *sup_name) {
    guint length = 5;
    guint sub_type = data[0];
    guint sub_length = ((((gint) data[1] & 0xff) << 24) | ((data[2] & 0xff) << 16) |
                        ((data[3] & 0xff) << 8) | (data[4] & 0xff));
    const proto_tree *subtree;
    if (sup_name == NULL)
        subtree = tree;
    else {
        item = proto_tree_add_item(tree, hf_text, tvb, offset_global, length, ENC_NA);
        subtree = proto_item_add_subtree(item, ett);
        proto_item_set_text(item, "%s", sup_name);
    }
    proto_item_append_text(item, " (%d entries)", sub_length);
    if (is_primitive_type(sub_type)) {
        for (guint i = 0; i < sub_length; i++)
            length += add_primitive_type(subtree, tvb, hf_text, data + length,
                                         offset_global + length, sub_type,
                                         g_strdup_printf("[%d]", i));
    } else if (sub_type == TAG_LIST) {
        for (guint i = 0; i < sub_length; i++)
            length += add_list_type(NULL, subtree, tvb, ett, hf_text, data + length,
                                    offset_global + length,
                                    g_strdup_printf("[%d]", i));
    } else if (sub_type == TAG_COMPOUND) {
        for (guint i = 0; i < sub_length; i++)
            length += add_compound_type(NULL, subtree, tvb, ett, hf_text, data + length,
                                        offset_global + length,
                                        g_strdup_printf("[%d]", i));
    }
    proto_item_set_len(item, length);
    return length;
}

guint add_compound_type(proto_item *item, const proto_tree *tree, tvbuff_t *tvb, gint ett, gint hf_text,
                        const guint8 *data, int offset_global, gchar *sup_name) {
    guint length = 1;
    const proto_tree *subtree;
    if (sup_name == NULL)
        subtree = tree;
    else {
        item = proto_tree_add_item(tree, hf_text, tvb, offset_global, length, ENC_NA);
        subtree = proto_item_add_subtree(item, ett);
        proto_item_set_text(item, "%s", sup_name);
    }
    while (data[length - 1] != TAG_END) {
        guint sub_type = data[length - 1];
        gint name_length = ((((gint) data[length] & 0xff) << 8) | (data[length + 1] & 0xff));
        gchar *name = g_strndup((gchar *) data + length + 2, name_length);
        length += 2 + name_length;
        if (is_primitive_type(sub_type)) {
                length += add_primitive_type(subtree, tvb, hf_text, data + length,
                                             offset_global + length, sub_type,name);
        } else if (sub_type == TAG_LIST) {
                length += add_list_type(NULL, subtree, tvb, ett, hf_text, data + length,
                                        offset_global + length,name);
        } else if (sub_type == TAG_COMPOUND) {
                length += add_compound_type(NULL, subtree, tvb, ett, hf_text, data + length,
                                            offset_global + length, name);
        }
        length += 1;
    }
    proto_item_set_len(item, length);
    return length;
}

guint do_nbt_tree(proto_tree *tree, tvbuff_t *tvb, const guint8 *data,
                  guint offset, guint remaining, int hfindex, bool is_je, bool need_skip) {
    guint8 type = data[0];
    guint origin_offset = offset;
    if (need_skip) {
        gint skip = ((((gint) data[1] & 0xff) << 8) | (data[2] & 0xff));
        offset += 3 + skip;
    } else
        offset += 1;
    if (is_primitive_type(type)) {
        offset += add_primitive_type_hf(tree, tvb, data + offset, offset, type, hfindex);
    } else {
        int ett = is_je ? ett_sub_je : ett_sub_be;
        int hf_text = is_je ? hf_text_je : hf_text_be;
        proto_item *item = proto_tree_add_item(tree, hfindex, tvb, offset, remaining, ENC_NA);
        proto_tree *subtree = proto_item_add_subtree(item, ett);
        guint length = 0;
        if (type == TAG_LIST)
            length = add_list_type(item, subtree, tvb, ett, hf_text, data + offset, offset, NULL);
        else if (type == TAG_COMPOUND)
            length = add_compound_type(item, subtree, tvb, ett, hf_text, data + offset, offset, NULL);
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