//
// Created by nickid2018 on 2026/3/30.
//

#include "easy_expr.h"

#include <wsutil/wmem/wmem_stack.h>

operand_t *create_operand(int64_t value, wmem_allocator_t *allocator) {
    operand_t *operand = wmem_alloc(allocator, sizeof(operand_t));
    operand->value = value;
    return operand;
}

char *calculate_expr(
    char **expr_list, wmem_allocator_t *allocator,
    char *(*value_fetcher)(char *name, void *user_data, int64_t *value), void *user_data,
    int64_t *result
) {
    wmem_stack_t *stack = wmem_stack_new(allocator);
    for (int i = 0; expr_list[i] != NULL; i++) {
        char *op = expr_list[i];

        if (strcmp(op, "+") == 0) {
            if (wmem_stack_count(stack) < 2)
                return "Invalid expression: Not enough operands for +";
            int64_t op1 = ((operand_t *) wmem_stack_pop(stack))->value;
            int64_t op2 = ((operand_t *) wmem_stack_pop(stack))->value;
            wmem_stack_push(stack, create_operand(op1 + op2, allocator));
            continue;
        }

        if (strcmp(op, "-") == 0) {
            if (wmem_stack_count(stack) < 2)
                return "Invalid expression: Not enough operands for -";
            int64_t op1 = ((operand_t *) wmem_stack_pop(stack))->value;
            int64_t op2 = ((operand_t *) wmem_stack_pop(stack))->value;
            wmem_stack_push(stack, create_operand(op1 - op2, allocator));
            continue;
        }

        if (strcmp(op, "*") == 0) {
            if (wmem_stack_count(stack) < 2)
                return "Invalid expression: Not enough operands for *";
            int64_t op1 = ((operand_t *) wmem_stack_pop(stack))->value;
            int64_t op2 = ((operand_t *) wmem_stack_pop(stack))->value;
            wmem_stack_push(stack, create_operand(op1 * op2, allocator));
            continue;
        }

        if (strcmp(op, "/") == 0) {
            if (wmem_stack_count(stack) < 2)
                return "Invalid expression: Not enough operands for /";
            int64_t op1 = ((operand_t *) wmem_stack_pop(stack))->value;
            int64_t op2 = ((operand_t *) wmem_stack_pop(stack))->value;
            wmem_stack_push(stack, create_operand(op1 / op2, allocator));
            continue;
        }

        int64_t operand;
        char *error_message = value_fetcher(op, user_data, &operand);
        if (error_message) return error_message;
        wmem_stack_push(stack, create_operand(operand, allocator));
    }

    if (wmem_stack_count(stack) != 1) return "Invalid expression: Too many operands";
    *result = ((operand_t *) wmem_stack_pop(stack))->value;
    return NULL;
}
