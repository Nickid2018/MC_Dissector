//
// Created by Nickid2018 on 2023/7/12.
//

#ifndef MC_DISSECTOR_MC_DISSECTOR_H
#define MC_DISSECTOR_MC_DISSECTOR_H

#include <epan/tfs.h>

#define MCJE_PORT 25565
#define MCBE_PORT 19132
#define MCJE_NAME "Minecraft Java Edition"
#define MCBE_NAME "Minecraft Bedrock Edition"
#define MCJE_SHORT_NAME "MCJE"
#define MCBE_SHORT_NAME "MCBE"
#define MCJE_FILTER "mcje"
#define MCBE_FILTER "mcbe"

#define DEFINE_HF(name, desc, key, type, dis) {&name, {desc, key, FT_##type, BASE_##dis, NULL, 0x0, NULL, HFILL}},
#define DEFINE_HF_VAL(name, desc, key, type, dis, val) {&name, {desc, key, FT_##type, BASE_##dis, VALS(val), 0x0, NULL, HFILL}},
#define DEFINE_HF_BITMASK(name, desc, key, type, dis, bitmask) {&name, {desc, key, FT_##type, BASE_##dis, NULL, bitmask, NULL, HFILL}},
#define DEFINE_HF_BITMASK_VAL(name, desc, key, type, dis, bitmask, val) {&name, {desc, key, FT_##type, BASE_##dis, VALS(val), bitmask, NULL, HFILL}},
#define DEFINE_HF_BITMASK_TF(name, desc, key, bitmask) {&name, {desc, key, FT_BOOLEAN, 8, TFS(tf_string), bitmask, NULL, HFILL}},

#if defined(DEBUG)
#define WS_LOG(format, ...) ws_log("", LOG_LEVEL_CRITICAL, format, ##__VA_ARGS__)
#else
#define WS_LOG(format, ...)
#endif

extern int proto_mcje;
extern int proto_mcbe;

#endif //MC_DISSECTOR_MC_DISSECTOR_H
