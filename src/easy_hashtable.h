typedef struct _GHashTable GHashTable;

GHashTable *ht_create();
void ht_free(GHashTable *);

// Gives value ownership if retval is NULL.
void *ht_lookup_or_insert(GHashTable *, char *key, void *value);

void ht_update(GHashTable *, char *key, void *value);

void ht_remove(GHashTable *, char *key);

void *ht_lookup(GHashTable *, char *key);
