#pragma once

#include <stdbool.h>
#include <stdint.h>

#define HASH_SIZE 10

typedef struct {
    char *key;
    void *val;
} HashMapItem;

typedef struct {
    HashMapItem *array[1 << HASH_SIZE];
} HashMap;

HashMap *new_hashmap();
void hashmap_insert(HashMap *hmap, char *key, void *val);
HashMapItem *hashmap_find(HashMap *hmap, char *key);
