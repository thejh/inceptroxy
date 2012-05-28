#include <sys/types.h>

struct http_header {
  char *key;
  char *value;
  struct http_header *next;
};

void free_headers(struct http_header **header);

void headers_append_key(struct http_header **header_ptr, const char *buf, size_t len);
void headers_append_value(struct http_header **header_ptr, const char *buf, size_t len);
