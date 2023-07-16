//
// Created by Nickid2018 on 2023/7/16.
//

#ifndef MC_DISSECTOR_JE_PROTOCOL_CONSTANTS_H
#define MC_DISSECTOR_JE_PROTOCOL_CONSTANTS_H

#include <epan/proto.h>

extern wmem_map_t *protocol_name_map_client_je;
extern wmem_map_t *protocol_name_map_server_je;

void init_je_constants();

#endif //MC_DISSECTOR_JE_PROTOCOL_CONSTANTS_H
