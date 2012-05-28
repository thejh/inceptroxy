#ifndef outstream_h
#define outstream_h

#include <libev/ev.h>

#define OUTSTREAM_HIGH 1024 * 1024
#define OUTSTREAM_LOW 256 * 1024

struct buffer {
  char *buf;
  char *free_ptr;
  size_t len;
  struct buffer *next;
};

struct outstream {
  struct ev_io watcher;
  struct ev_io *input_watcher;
  
  struct buffer *first_buf;
  struct buffer *last_buf;
  int pressure;
  
  /// responsible for cleaning this up after a fatal error has occured
  void (*error_cb)(struct outstream *);
};


void outstream_init(struct outstream *s, int fd, void (*error_cb)(struct outstream *));

// Use this to add/remove backpressure.
void outstream_input_set(struct outstream *s, struct ev_io *input_watcher);

// Takes responsibility for free()'ing buf.
void outstream_send(struct outstream *s, char *buf, size_t len);

void outstream_nuke(struct outstream *s);

#endif
