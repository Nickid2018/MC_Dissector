import os
import sys

data_1_dir = sys.argv[1]
data_2_dir = sys.argv[2]
code_gen_dir = sys.argv[3]


def get_file_list(path):
    for root, dirs, files in os.walk(path):
        return files
    return []


def get_data(file):
    with open(file, 'rb') as fi:
        read_data = fi.read()
        converted_data = ''.join([f'\\x{byte:02x}' for byte in read_data])
        converted_data = converted_data.replace('\\x0d\\x0a', '\\x0a')  # Replace CRLF with LF
        return converted_data


file_1_list = get_file_list(data_1_dir)
file_2_list = get_file_list(data_2_dir)
with open(code_gen_dir + '/resources.h', 'w') as f:
    f.write('\n'.join([
        '// Auto generate codes, DO NOT MODIFY THIS FILE',
        '#pragma once',
        '#ifdef MC_DISSECTOR_FUNCTION_FEATURE',
        ''
    ]))
    f.write('\n'.join([f'extern const char* RESOURCE_{file[:file.rindex(".")].upper()};' for file in file_1_list]))
    f.write('\n')
    f.write('\n'.join([f'extern const char* RESOURCE_{file[:file.rindex(".")].upper()};' for file in file_2_list]))
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
        [f'const char* RESOURCE_{file[:file.rindex(".")].upper()} = "{get_data(data_1_dir + "/" + file)}";' for file in
         file_1_list]))
    f.write('\n')
    f.write('\n'.join(
        [f'const char* RESOURCE_{file[:file.rindex(".")].upper()} = "{get_data(data_2_dir + "/" + file)}";' for file in
         file_2_list]))
    f.write('\n')
    f.write('#endif // MC_DISSECTOR_FUNCTION_FEATURE\n')

print(f'Generate {len(file_1_list)} resources in {data_1_dir}.')
print(f'Generate {len(file_2_list)} resources in {data_2_dir}.')
