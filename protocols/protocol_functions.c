//
// Created by Nickid2018 on 2023/8/27.
//

#ifdef MC_DISSECTOR_FUNCTION_FEATURE

#include "protocol_functions.h"

void init_protocol_functions() {

}

FIELD_MAKE_TREE(record_entity_id) {
    if (!extra->allow_write)
        return 0;
    char *id_path[] = {"entityId", NULL};
    gchar *id = record_query(recorder, id_path);
    char *type_path[] = {"type", NULL};
    gchar *type = record_query(recorder, type_path);
    return 0;
}

FIELD_MAKE_TREE(sync_entity_data) {
    return 0;
}

#endif //MC_DISSECTOR_FUNCTION_FEATURE