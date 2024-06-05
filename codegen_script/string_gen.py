import json
import sys

data_source_file = sys.argv[1]
code_gen_file = sys.argv[2]
code_gen_header = sys.argv[3]
edition = sys.argv[4]

packet_client_lines = []
packet_server_lines = []

def read_data():
    with open(data_source_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
        packet_name_json = data['packet_names']
        for key, value in packet_name_json['toClient'].items():
            packet_client_lines.append(f'\tDEFINE_NAME_CLIENT({key}, {value})')
        for key, value in packet_name_json['toServer'].items():
            packet_server_lines.append(f'\tDEFINE_NAME_SERVER({key}, {value})')


def write_data():
    with open(code_gen_header, 'w', encoding='utf-8') as f:
        f.write('\n'.join([
            '// Auto generate codes, DO NOT MODIFY THIS FILE',
            '#pragma once',
            '#include "mc_dissector.h"',
            '#include <epan/packet.h>',
            f'void register_string_{edition}();',
            f'extern wmem_map_t *protocol_name_map_client_{edition};',
            f'extern wmem_map_t *protocol_name_map_server_{edition};',
            ''
        ]))
    with open(code_gen_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join([
            '// Auto generate codes, DO NOT MODIFY THIS FILE',
            f'#include "strings_{edition}.h"',
            f'wmem_map_t *protocol_name_map_client_{edition} = NULL;',
            f'wmem_map_t *protocol_name_map_server_{edition} = NULL;',
            f'#define DEFINE_NAME_CLIENT(name, desc) wmem_map_insert(protocol_name_map_client_{edition}, #name, #desc);',
            f'#define DEFINE_NAME_SERVER(name, desc) wmem_map_insert(protocol_name_map_server_{edition}, #name, #desc);',
            ''
        ]))
        # main
        f.write('\n'.join([
            f'void register_string_{edition}() {{',
            f'\tprotocol_name_map_client_{edition} = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);',
            f'\tprotocol_name_map_server_{edition} = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);',
        ]))
        # add packet names
        f.write('\n'.join(packet_client_lines))
        f.write('\n')
        f.write('\n'.join(packet_server_lines))
        f.write('\n}\n\n')


read_data()
write_data()
print(f'Generate {len(packet_client_lines)} packet client lines.')
print(f'Generate {len(packet_server_lines)} packet server lines.')
