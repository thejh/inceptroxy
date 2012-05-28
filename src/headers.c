#include <string.h>
#include <stdlib.h>

#include "headers.h"
#include "memory.h"

void free_headers(struct http_header **header) {
  struct http_header *h = *header;
  struct http_header *next;
  while (h != NULL) {
    next = h->next;
    free(h->key);
    free(h->value);
    free(h);
    h = next;
  }
  *header = NULL;
}

#define header (*header_ptr)

void headers_append_key(struct http_header **header_ptr, const char *buf, size_t len) {
  if (header == NULL || header->value != NULL) {
    // likely case: new key
    struct http_header *new_header = safe_malloc(sizeof(struct http_header));
    new_header->key = safe_malloc(len+1);
    memcpy(new_header->key, buf, len);
    new_header->key[len] = '\0';
    new_header->value = NULL;
    new_header->next = header;
    header = new_header; // this is why we need a double-pointer
  } else {
    // Oh, we're completing an existing header? well, in this unlikely case, we
    // can use strlen() and stuff without feeling too bad.
    size_t old_len = strlen(header->key);
    header->key = safe_realloc(header->key, old_len + len + 1);
    memcpy(header->key + old_len, buf, len);
    header->key[old_len + len] = '\0';
  }
}

void headers_append_value(struct http_header **header_ptr, const char *buf, size_t len) {
  size_t old_len;
  if (header->value == NULL) {
    old_len = 0;
  } else {
    old_len = strlen(header->value);
  }
  header->value = safe_realloc(header->value, old_len + len + 1);
  memcpy(header->value + old_len, buf, len);
  header->value[old_len + len] = '\0';
}

#undef header
