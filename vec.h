#pragma once
#include <stdlib.h>

#define INITIAL_CAPACITY 16

typedef struct {
    void **array;
    int capacity;
    int len;
} Vec;

Vec *new_vec();

void vec_push_back(Vec *vec, void *elem);
void vec_concat(Vec *vec1, Vec *vec2);
