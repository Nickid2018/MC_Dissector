//
// Created by nickid2018 on 24-9-14.
//

#ifndef MC_DISSECTOR_SCHEMA_H
#define MC_DISSECTOR_SCHEMA_H

#include <epan/proto.h>
#include <cJSON.h>

typedef struct protocol_dissector_struct protocol_dissector;
typedef struct protocol_dissector_set_struct protocol_dissector_set;

protocol_dissector_set *create_protocol(uint32_t protocol_version);

void destroy_protocol(protocol_dissector_set *dissector_set);

#endif //MC_DISSECTOR_SCHEMA_H
