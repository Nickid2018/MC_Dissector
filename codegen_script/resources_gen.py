import os
import sys

data_dir = sys.argv[1]
code_gen_dir = sys.argv[2]


def get_file_list(path):
    for root, dirs, files in os.walk(path):
        return files


def get_data(file):
    with open(file, 'rb') as fi:
        read_data = fi.read()
        converted_data = ''.join([f'\\x{byte:02x}' for byte in read_data])
        return converted_data


file_list = get_file_list(data_dir)
with open(code_gen_dir + '/resources.h', 'w') as f:
    f.write('\n'.join([
        '// Auto generate codes, DO NOT MODIFY THIS FILE',
        '#pragma once',
        '#ifdef MC_DISSECTOR_FUNCTION_FEATURE',
        ''
    ]))
    f.write('\n'.join([f'extern const char* RESOURCE_{file[:file.rindex(".")].upper()};' for file in file_list]))
    f.write('\n')
    f.write('#endif // MC_DISSECTOR_FUNCTION_FEATURE\n')

with open(code_gen_dir + '/resources.c', 'w') as f:
    f.write('\n'.join([
        '// Auto generate codes, DO NOT MODIFY THIS FILE',
        '#ifdef MC_DISSECTOR_FUNCTION_FEATURE',
        '#include "resources.h"',
        ''
    ]))
    f.write('\n'.join(
        [f'const char* RESOURCE_{file[:file.rindex(".")].upper()} = "{get_data(data_dir + "/" + file)}";' for file in
         file_list]))
    f.write('\n')
    f.write('#endif // MC_DISSECTOR_FUNCTION_FEATURE\n')

print(f'Generate {len(file_list)} resources.')
