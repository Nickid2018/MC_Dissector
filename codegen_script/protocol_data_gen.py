import json
import os
import sys

data_dir = sys.argv[1]
code_gen_dir = sys.argv[2]


def get_file_list(path):
    for root, dirs, files in os.walk(path):
        return dirs
    return []


def get_data(root):
    with open(root + '/protocolVersions.json', 'r') as file:
        data_json = json.load(file)
        protocol_version_data = json.dumps(data_json).replace('"', '\\"')

    available_versions = get_file_list(root)
    versions_data = {}
    for v in available_versions:
        with open(f'{root}/{v}/protocol.json', 'r') as file:
            data_json = json.load(file)
            versions_data[v] = json.dumps(data_json).replace('"', '\\"')

    return protocol_version_data, versions_data


je_protocol_version_data, je_versions_data = get_data(data_dir + '/java')
be_protocol_version_data, be_versions_data = get_data(data_dir + '/bedrock')

with open(code_gen_dir + '/protocolVersions.h', 'w') as f:
    f.write("""// Auto generate codes, DO NOT MODIFY THIS FILE
#pragma once
extern const char* PROTOCOL_VERSIONS_JE;
extern const char* PROTOCOL_VERSIONS_BE;
""")

with open(code_gen_dir + '/protocolVersions.c', 'w') as f:
    f.write("""// Auto generate codes, DO NOT MODIFY THIS FILE
#include "protocolVersions.h"
""")
    f.write(f'const char* PROTOCOL_VERSIONS_JE = "{je_protocol_version_data}";\n')
    f.write(f'const char* PROTOCOL_VERSIONS_BE = "{be_protocol_version_data}";\n')

with open(code_gen_dir + '/protocolSchemas.h', 'w') as f:
    f.write("""// Auto generate codes, DO NOT MODIFY THIS FILE
#pragma once
extern const int JE_PROTOCOL_SIZE;
extern const char *JE_PROTOCOLS[];
extern const int BE_PROTOCOL_SIZE;
extern const char *BE_PROTOCOLS[];
""")

with open(code_gen_dir + '/protocolSchemas.c', 'w') as f:
    f.write("""// Auto generate codes, DO NOT MODIFY THIS FILE
#include "protocolSchemas.h"
""")

    f.write(f'const int JE_PROTOCOL_SIZE = {len(je_versions_data)};\n')
    f.write('const char *JE_PROTOCOLS[] = {\n')
    for version in je_versions_data:
        f.write(f'    "{version}", "{je_versions_data[version]}",\n')
    f.write('};\n')

    f.write(f'const int BE_PROTOCOL_SIZE = {len(be_versions_data)};\n')
    f.write('const char *BE_PROTOCOLS[] = {\n')
    for version in be_versions_data:
        f.write(f'    "{version}", "{be_versions_data[version]}",\n')
    f.write('};\n')

print(f'Java version count: {len(je_versions_data)}')
print(f'Bedrock version count: {len(be_versions_data)}')
