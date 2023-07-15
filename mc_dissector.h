//
// Created by Nickid2018 on 2023/7/12.
//

#ifndef MC_DISSECTOR_MC_DISSECTOR_H
#define MC_DISSECTOR_MC_DISSECTOR_H

#define MCJE_PORT 25565
#define MCBE_PORT 19132
#define MCJE_NAME "Minecraft Java Edition"
#define MCBE_NAME "Minecraft Bedrock Edition"
#define MCJE_SHORT_NAME "MCJE"
#define MCBE_SHORT_NAME "MCBE"
#define MCJE_FILTER "mcje"
#define MCBE_FILTER "mcbe"

#define DEFINE_HF(name, desc, key, type, dis) {&name, {desc, key, FT_##type, BASE_##dis, NULL, 0x0, NULL, HFILL}}

extern int proto_mcje;
extern int proto_mcbe;

#endif //MC_DISSECTOR_MC_DISSECTOR_H
