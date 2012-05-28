#include "memory.h"
#include <stdlib.h>
#include <assert.h>

void *safe_malloc(size_t size) {
  void *result = malloc(size);
  assert(size == 0 || result != NULL);
  return result;
}

void *safe_realloc(void *buf, size_t size) {
  void *result = realloc(buf, size);
  assert(size == 0 || result != NULL);
  return result;
}
