import sys
import os
import json

data_dir = sys.argv[1]
code_gen_dir = sys.argv[2]


def get_file_list(path):
    for root, dirs, files in os.walk(path):
        return dirs
    return []


version_list = get_file_list(data_dir)

# make data version map
data_version_map = {}
with open(data_dir + '/protocolVersions.json', 'r') as file:
    data_json = json.load(file)
    for v in data_json:
        if v['usesNetty'] and 'dataVersion' in v:
            data_version_map[v['minecraftVersion']] = v['dataVersion']

entity_to_desc_id = {}
data_id_map = {}
data_list = []
entity_name_list = []
for v in version_list:
    if v not in data_version_map or data_version_map[v] < data_version_map['1.14.4']:
        continue
    if os.path.exists(f'{data_dir}/{v}/entities.json'):
        index_map = {}
        entity_list = []
        max_id = 0
        with open(f'{data_dir}/{v}/entities.json', 'r') as file:
            data_json = json.load(file)
            for e in data_json:
                entity_name = e['name']
                if entity_name not in entity_to_desc_id:
                    entity_to_desc_id[entity_name] = len(entity_to_desc_id)
                    entity_name_list.append(entity_name)
                entity_id_name = entity_to_desc_id[entity_name]
                entity_list.append(entity_id_name)
                index_map[entity_id_name] = e['id']
                max_id = max(max_id, e['id'])
        if len(entity_list) != max_id + 1:
            print(f'Warning: entity id not continuous: {v}, {len(entity_list)}, {max_id}')
            continue
        entity_list.sort(key=lambda x: index_map[x])
        data_id_map[data_version_map[v]] = entity_list
        data_list.append(data_version_map[v])

data_list.sort()
sorted_data_ids = [data_id_map[v] for v in data_list]
entity_name_list.sort(key=lambda x: entity_to_desc_id[x])

with open(code_gen_dir + '/entity_id.txt', 'w') as f:
    f.write(f'{len(entity_to_desc_id)}\n')
    f.write(' '.join(entity_name_list))
    f.write('\n')
    f.write(f'{len(sorted_data_ids)}\n')
    for i in range(len(sorted_data_ids)):
        f.write(f'{data_list[i]} {len(sorted_data_ids[i])}\n')
        f.write(' '.join([str(data) for data in sorted_data_ids[i]]))
        f.write('\n')
