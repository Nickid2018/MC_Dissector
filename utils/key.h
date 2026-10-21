//
// Created by nickid2018 on 2026/10/21.
//

#ifndef MC_DISSECTOR_KEY_H
#define MC_DISSECTOR_KEY_H
#include <glib/gtypes.h>
#include <wsutil/wmem/wmem_core.h>

gchar *match_secret_key(const gchar *challenge, const gchar *content);

const gchar *find_encryption_key(gchar *challenge_str);

uint8_t *make_key(const gchar *encryption_key);

char *bytes_to_hex(wmem_allocator_t *allocator, const uint8_t *bytes, uint32_t len, bool uppercase);

#endif //MC_DISSECTOR_KEY_H
