#define _XOPEN_SOURCE 500

#include <string.h>
#include <glib.h>
#include <stdlib.h>
#include <assert.h>


GHashTable *ht_create() {
  return g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);
}

void ht_free(GHashTable *ht) {
  g_hash_table_destroy(ht);
}

void *ht_lookup_or_insert(GHashTable *ht, char *key, void *value) {
  void *retval = g_hash_table_lookup(ht, key);
  if (retval != NULL) return retval;
  key = strdup(key);
  g_hash_table_insert(ht, key, value);
  return retval;
}

void ht_update(GHashTable *ht, char *key, void *value) {
  if (value == NULL) {
    g_hash_table_remove(ht, key);
  } else {
    key = strdup(key);
    g_hash_table_insert(ht, key, value);
  }
}

void ht_remove(GHashTable *ht, char *key) {
  g_hash_table_remove(ht, key);
}

void *ht_lookup(GHashTable *ht, char *key) {
  return g_hash_table_lookup(ht, key);
}
