//
// Created by Nickid2018 on 2023/7/13.
//

#ifndef MC_DISSECTOR_PROTOCOL_SCHEMA_H
#define MC_DISSECTOR_PROTOCOL_SCHEMA_H

#include <epan/proto.h>
#include "../cJSON/cJSON.h"

struct _protocol_set;
typedef struct _protocol_set *protocol_set;
struct _protocol_entry;
typedef struct _protocol_entry *protocol_entry;

protocol_set create_protocol_set(cJSON *types, cJSON *data);

#endif //MC_DISSECTOR_PROTOCOL_SCHEMA_H
