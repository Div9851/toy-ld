#include "vec.h"

Vec *new_vec() {
    Vec *vec = calloc(1, sizeof(Vec));
    vec->array = calloc(INITIAL_CAPACITY, sizeof(void *));
    vec->capacity = INITIAL_CAPACITY;
    vec->len = 0;
    return vec;
}

void vec_push_back(Vec *vec, void *elem) {
    if (vec->len + 1 > vec->capacity) {
        vec->array = realloc(vec->array, sizeof(void *) * (vec->capacity * 2));
        vec->capacity *= 2;
    }
    vec->array[vec->len++] = elem;
}

void vec_concat(Vec *vec1, Vec *vec2) {
    for (int i = 0; i < vec2->len; ++i) {
        vec_push_back(vec1, vec2->array[i]);
    }
}
