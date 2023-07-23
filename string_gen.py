import json
import sys

data_source_file = sys.argv[1]
code_gen_file = sys.argv[2]
code_gen_header = sys.argv[3]
edition = sys.argv[4]
print(f'code_gen_file: {code_gen_file}, edition: {edition}, data_source_file: {data_source_file}')

hf_defines = []
value_string_lines = []
bitmask_collection_defines = []

hf_lines = []
complex_hf = {}
add_hf_lines = []
bitmask_collection_lines = []
cp_lines = []

mapping = {
    'i32': 'INT32',
    'i64': 'INT64',
    'u32': 'UINT32',
    'u64': 'UINT64',
    'f32': 'FLOAT',
    'f64': 'DOUBLE',
    'bool': 'BOOLEAN',
    'string': 'STRING',
    'bytes': 'BYTES',
    'uuid': 'GUID',
    'i8': 'INT8',
    'u8': 'UINT8',
    'i16': 'INT16',
    'u16': 'UINT16'
}

mapping_display = {
    'i32': 'DEC',
    'i64': 'DEC',
    'u32': 'DEC',
    'u64': 'DEC',
    'f32': 'DEC',
    'f64': 'DEC',
    'bool': 'NONE',
    'string': 'NONE',
    'bytes': 'NONE',
    'uuid': 'NONE',
    'i8': 'DEC',
    'u8': 'DEC',
    'i16': 'DEC',
    'u16': 'DEC'
}


def add_default_fields():
    hf_defines.append(f'hf_unknown_int_{edition}')
    hf_lines.append(
        f'\t\tDEFINE_HF(hf_unknown_int_{edition}, "Unresolved Integer", "mc{edition}.unknown_int", INT32, DEC)')
    hf_defines.append(f'hf_unknown_uint_{edition}')
    hf_lines.append(
        f'\t\tDEFINE_HF(hf_unknown_uint_{edition}, "Unresolved Unsigned Integer", "mc{edition}.unknown_uint", '
        f'UINT32, DEC)')
    hf_defines.append(f'hf_unknown_int64_{edition}')
    hf_lines.append(
        f'\t\tDEFINE_HF(hf_unknown_int64_{edition}, "Unresolved Long Integer", "mc{edition}.unknown_int64", '
        f'INT64, DEC)')
    hf_defines.append(f'hf_unknown_uint64_{edition}')
    hf_lines.append(f'\t\tDEFINE_HF(hf_unknown_uint64_{edition}, "Unresolved Unsigned Long Integer", '
                    f'"mc{edition}.unknown_uint64", UINT64, DEC)')
    hf_defines.append(f'hf_unknown_float_{edition}')
    hf_lines.append(
        f'\t\tDEFINE_HF(hf_unknown_float_{edition}, "Unresolved Float", "mc{edition}.unknown_float", FLOAT, '
        f'DEC)')
    hf_defines.append(f'hf_unknown_double_{edition}')
    hf_lines.append(f'\t\tDEFINE_HF(hf_unknown_double_{edition}, "Unresolved Double", "mc{edition}.unknown_double", '
                    f'DOUBLE, DEC)')
    hf_defines.append(f'hf_unknown_bytes_{edition}')
    hf_lines.append(
        f'\t\tDEFINE_HF(hf_unknown_bytes_{edition}, "Unresolved Bytes", "mc{edition}.unknown_bytes", BYTES, '
        f'NONE)')
    hf_defines.append(f'hf_unknown_string_{edition}')
    hf_lines.append(f'\t\tDEFINE_HF(hf_unknown_string_{edition}, "Unresolved String", "mc{edition}.unknown_string", '
                    f'STRING, NONE)')
    hf_defines.append(f'hf_unknown_boolean_{edition}')
    hf_lines.append(f'\t\tDEFINE_HF(hf_unknown_boolean_{edition}, "Unresolved Boolean", "mc{edition}.unknown_boolean", '
                    f'BOOLEAN, NONE)')
    hf_defines.append(f'hf_unknown_uuid_{edition}')
    hf_lines.append(
        f'\t\tDEFINE_HF(hf_unknown_uuid_{edition}, "Unresolved UUID", "mc{edition}.unknown_uuid", GUID, NONE)')
    hf_defines.append(f'hf_array_length_{edition}')
    hf_lines.append(
        f'\t\tDEFINE_HF(hf_array_length_{edition}, "Array Length", "mc{edition}.array_length", UINT32, DEC)')


def make_simple_hf(key, value, type_name):
    display = value['display'] if 'display' in value else mapping_display[type_name]
    type_str = mapping[type_name]
    if 'bitmask' in value:
        hf_defines.append(f'hf_{key}')
        if 'value_mapping' in value:
            hf_lines.append(f'\t\tDEFINE_HF_BITMASK_VAL(hf_{key}, "{value["name"]}", "mc{edition}.{key}", '
                            f'{type_str}, {display}, 0x{value["bitmask"]}, '
                            f'{value["value_mapping"]})')
        elif value['type'] == 'bool':
            hf_lines.append(f'\t\tDEFINE_HF_BITMASK_TF(hf_{key}, "{value["name"]}" , "mc{edition}.{key}", '
                            f'0x{value["bitmask"]})')
        else:
            hf_lines.append(f'\t\tDEFINE_HF_BITMASK(hf_{key}, "{value["name"]}" , "mc{edition}.{key}", '
                            f'{type_str}, {display}, 0x{value["bitmask"]})')
    else:
        hf_defines.append(f'hf_{key}')
        if 'value_mapping' in value:
            hf_lines.append(f'\t\tDEFINE_HF_VAL(hf_{key}, "{value["name"]}", "mc{edition}.{key}", '
                            f'{type_str}, {display}, {value["value_mapping"]})')
        else:
            hf_lines.append(f'\t\tDEFINE_HF(hf_{key}, "{value["name"]}", "mc{edition}.{key}", '
                            f'{type_str}, {display})')


def read_data():
    add_default_fields()
    with open(data_source_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

        hf_defines_json = data['hf_defines']
        for key, value in hf_defines_json.items():
            if isinstance(value['type'], list):
                for type_name in value['type']:
                    make_simple_hf(f'{key}_{type_name}', value, type_name)
                complex_hf[key] = value['type']
            else:
                make_simple_hf(key, value, value['type'])

        hf_mappings_json = data['mappings']
        for key, value in hf_mappings_json.items():
            if value in complex_hf:
                add_hf_lines.append(f'\tADD_COMPLEX_HF("{key}", "{value}")')
            else:
                add_hf_lines.append(f'\tADD_HF("{key}", hf_{value})')

        bitmask_collection_json = data['bitmask_collection']
        bitmask_count = 0
        for key, value in bitmask_collection_json.items():
            links = []
            for link in value:
                if link is None:
                    links.append('NULL')
                else:
                    links.append(f'&hf_{link}')
            bitmask_collection_defines.append(f'int *bitmask_{bitmask_count}[] = {{ {", ".join(links)} }};')
            bitmask_collection_lines.append(f'\tADD_BITMASK("{key}", bitmask_{bitmask_count})')
            bitmask_count += 1

        value_string_json = data['value_mappings']
        for key, value in value_string_json.items():
            values = []
            for k, v in value.items():
                values.append(f'{{ {k}, "{v}" }}')
            values.append('{ 0, NULL }')
            values_str = '\n\t' + ',\n\t'.join(values) + '\n'
            value_string_lines.append(f'value_string {key}[] = {{{values_str}}};')

        cp_lines_json = data['component_names']
        for key, value in cp_lines_json.items():
            cp_lines.append(f'\tADD_CP("{key}", "{value}")')


def write_data():
    with open(code_gen_header, 'w', encoding='utf-8') as f:
        f.write('#pragma once\n')
        f.write(f'void register_string_{edition}();')
    with open(code_gen_file, 'w', encoding='utf-8') as f:
        f.writelines('\n'.join([
            '#include "mc_dissector.h"',
            '#include <epan/packet.h>',
            f'int ett_mc{edition} = -1;',
            f'int ett_{edition}_proto = -1;',
            f'int ett_sub_{edition} = -1;',
            f'wmem_map_t *name_hf_map_{edition} = NULL;',
            f'wmem_map_t *complex_name_map_{edition} = NULL;',
            f'wmem_map_t *complex_hf_map_{edition} = NULL;',
            f'wmem_map_t *unknown_hf_map_{edition} = NULL;',
            f'wmem_map_t *bitmask_hf_map_{edition} = NULL;',
            f'wmem_map_t *component_map_{edition} = NULL;',
            f'#define ADD_HF(name, hf_index) wmem_map_insert(name_hf_map_{edition}, name, GINT_TO_POINTER(hf_index));',
            f'#define ADD_COMPLEX_HF(name, map) wmem_map_insert(complex_name_map_{edition}, name, map);',
            f'#define ADD_CP(name, display_name) wmem_map_insert(component_map_{edition}, name, display_name);',
            f'#define ADD_BITMASK(name, link) wmem_map_insert(bitmask_hf_map_{edition}, name, link);',
            'true_false_string tf_string[] = {{ "true", "false" }};',
            ''
        ]))
        # write hf defines
        for hf_define in hf_defines:
            f.write(f'int {hf_define} = -1;\n')
        # write bitmask collection
        f.writelines('\n'.join(bitmask_collection_defines))
        f.write('\n')
        # write value string
        f.writelines('\n'.join(value_string_lines))
        f.write('\n')
        # main
        f.writelines('\n'.join([
            f'void register_string_{edition}() {{',
            f'\tname_hf_map_{edition} = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);',
            f'\tcomplex_name_map_{edition} = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);',
            f'\tcomplex_hf_map_{edition} = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);',
            f'\tunknown_hf_map_{edition} = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);',
            f'\tbitmask_hf_map_{edition} = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);',
            f'\tcomponent_map_{edition} = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);',
            f'\tstatic gint *ett_{edition}[] = {{&ett_mc{edition}, &ett_{edition}_proto, &ett_sub_{edition}}};',
            f'\tstatic hf_register_info hf_je[] = {{',
            ''
        ]))
        # hf lines
        f.writelines('\n'.join(hf_lines))
        f.write('\n')
        f.writelines('\n'.join([
            f'\t}};',
            f'\tproto_register_field_array(proto_mc{edition}, hf_{edition}, array_length(hf_{edition}));',
            f'\tproto_register_subtree_array(ett_{edition}, array_length(ett_{edition}));',
            f'\twmem_map_insert(unknown_hf_map_{edition}, "int", GINT_TO_POINTER(hf_unknown_int_{edition}));',
            f'\twmem_map_insert(unknown_hf_map_{edition}, "uint", GINT_TO_POINTER(hf_unknown_uint_{edition}));',
            f'\twmem_map_insert(unknown_hf_map_{edition}, "int64", GINT_TO_POINTER(hf_unknown_int64_{edition}));',
            f'\twmem_map_insert(unknown_hf_map_{edition}, "uint64", GINT_TO_POINTER(hf_unknown_uint64_{edition}));',
            f'\twmem_map_insert(unknown_hf_map_{edition}, "float", GINT_TO_POINTER(hf_unknown_float_{edition}));',
            f'\twmem_map_insert(unknown_hf_map_{edition}, "double", GINT_TO_POINTER(hf_unknown_double_{edition}));',
            f'\twmem_map_insert(unknown_hf_map_{edition}, "bytes", GINT_TO_POINTER(hf_unknown_bytes_{edition}));',
            f'\twmem_map_insert(unknown_hf_map_{edition}, "string", GINT_TO_POINTER(hf_unknown_string_{edition}));',
            f'\twmem_map_insert(unknown_hf_map_{edition}, "boolean", GINT_TO_POINTER(hf_unknown_boolean_{edition}));',
            f'\twmem_map_insert(unknown_hf_map_{edition}, "uuid", GINT_TO_POINTER(hf_unknown_uuid_{edition}));',
            ''
        ]))
        # add hf
        f.writelines('\n'.join(add_hf_lines))
        f.write('\n')
        # add complex hf
        cpx_count = 0
        for key in complex_hf:
            f.write(f'\twmem_map_t *complex_{cpx_count} = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);\n')
            for v in complex_hf[key]:
                f.write(f'\twmem_map_insert(complex_{cpx_count}, "{v}", GINT_TO_POINTER(hf_{key}_{v}));\n')
            f.write(f'\twmem_map_insert(complex_hf_map_{edition}, "{key}", complex_{cpx_count});\n')
            cpx_count += 1
        # bitmask collection
        f.writelines('\n'.join(bitmask_collection_lines))
        f.write('\n')
        # add cp
        f.writelines('\n'.join(cp_lines))
        f.write('\n}\n')


read_data()
write_data()
