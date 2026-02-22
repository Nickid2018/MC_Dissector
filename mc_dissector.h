//
// Created by Nickid2018 on 2023/7/12.
//

#ifndef MC_DISSECTOR_MC_DISSECTOR_H
#define MC_DISSECTOR_MC_DISSECTOR_H

#include <epan/prefs.h>

#define MCJE_PORT "25565"
#define MCBE_PORT 19132
#define MCJE_NAME "Minecraft Java Edition"
#define MCBE_NAME "Minecraft Bedrock Edition"
#define MCJE_SHORT_NAME "MCJE"
#define MCBE_SHORT_NAME "MCBE"
#define MCJE_FILTER "mcje"
#define MCBE_FILTER "mcbe"

#define PLUGIN_VERSION "1.4.3"
#define PROTOCOL_DATA_VERSION "2.4"

#if defined(DEBUG)
#define WS_LOG(format, ...) ws_log("", LOG_LEVEL_CRITICAL, format, ##__VA_ARGS__)
#else
#define WS_LOG(format, ...)
#endif

extern int proto_mcje;
extern int proto_mcbe;

extern module_t *pref_mcje;
extern gchar *pref_ignore_packets_je;
extern gchar *pref_secret_key_je;
extern gchar *pref_key_log_filepath_je;
extern bool pref_do_nbt_decode_je;

extern module_t *pref_mcbe;
extern bool pref_do_nbt_decode_be;
extern gchar *pref_secret_key_be;

#endif //MC_DISSECTOR_MC_DISSECTOR_H
