//
// Created by Nickid2018 on 2023/7/16.
//

#include <epan/packet.h>
#include "mc_dissector.h"
#include "strings_je.h"
#include "je_protocol.h"
#include "je_protocol_constants.h"

module_t *pref_mcje = NULL;
gchar *pref_ignore_packets_je = "c:map_chunk";
gchar *pref_secret_key = "";

void proto_register_mcje() {
    proto_mcje = proto_register_protocol(MCJE_NAME, MCJE_SHORT_NAME, MCJE_FILTER);

    // Preference ------------------------------------------------------------------------------------------------------
    pref_mcje = prefs_register_protocol(proto_mcje, NULL);
    prefs_register_string_preference(pref_mcje, "ignore_packets", "Ignore Packets",
                                     "Ignore packets with the given names", (const char **) &pref_ignore_packets_je);
    prefs_register_string_preference(pref_mcje, "secret_key", "Secret Key",
                                     "Secret key for decryption", (const char **) &pref_secret_key);

    register_string_je();
    init_je();
    init_je_constants();
}