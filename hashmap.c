#include "hashmap.h"
#include <stdlib.h>
#include <string.h>

#define FNV_PRIME 16777619U
#define OFFSET_BASIS 2166136261U

// FNV-1a algorithm
// ref: http://www.isthe.com/chongo/tech/comp/fnv/#FNV-1a
uint32_t hash(char *key) {
    uint32_t hash = OFFSET_BASIS;
    while ((*key) != '\0') {
        hash = hash ^ (*key);
        hash *= FNV_PRIME;
        ++key;
    }
    return ((hash >> HASH_SIZE) ^ hash) & ((1 << HASH_SIZE) - 1);
}

HashMap *new_hashmap() {
    HashMap *hmap = calloc(1, sizeof(HashMap));
    return hmap;
}

void hashmap_insert(HashMap *hmap, char *key, uint64_t val) {
    uint32_t idx = hash(key);
    while (hmap->array[idx] != NULL &&
           strcmp(hmap->array[idx]->key, key) != 0) {
        idx = (idx + 1) & ((1 << HASH_SIZE) - 1);
    }
    HashMapItem *item = calloc(1, sizeof(HashMapItem));
    item->key = key;
    item->val = val;
    hmap->array[idx] = item;
}

HashMapItem *hashmap_find(HashMap *hmap, char *key) {
    uint32_t idx = hash(key);
    while (hmap->array[idx] != NULL) {
        if (strcmp(hmap->array[idx]->key, key) == 0) {
            return hmap->array[idx];
        }
        idx = (idx + 1) & ((1 << HASH_SIZE) - 1);
    }
    return NULL;
}
