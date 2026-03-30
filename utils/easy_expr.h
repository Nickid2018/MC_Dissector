//
// Created by nickid2018 on 2026/3/30.
//

#ifndef MC_DISSECTOR_EASY_EXPR_H
#define MC_DISSECTOR_EASY_EXPR_H
#include <wsutil/wmem/wmem_core.h>

typedef struct operand_struct {
    int64_t value;
} operand_t;

char *calculate_expr(
    char **expr_list, wmem_allocator_t *allocator,
    char *(*value_fetcher)(char *name, void *user_data, int64_t *value), void *user_data,
    int64_t *result
);

#endif //MC_DISSECTOR_EASY_EXPR_H
