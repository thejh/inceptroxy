#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

#include "outstream.h"
#include "memory.h"
#include "ev_helpers.h"
#include "helpers.h"

static void outstream_writable_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
  struct outstream *s = CASTUP(watcher, struct outstream, watcher);
  assert(s->first_buf != NULL);
  struct buffer *next;
  while (s->first_buf != NULL) {
    ssize_t written = write(watcher->fd, s->first_buf->buf, s->first_buf->len);
    if (written == -1 && errno == EAGAIN)
      return;
    if (written == -1 || written == 0) {
      s->error_cb(s); return;
    }
    // if we reach this point, stuff has actually been written
    s->pressure -= written;
    if (written < s->first_buf->len) {
      s->first_buf->buf += written;
      s->first_buf->len -= written;
      return;
    }
    assert(written == s->first_buf->len);
    next = s->first_buf->next;
    free(s->first_buf->free_ptr);
    free(s->first_buf);
    s->first_buf = next;
  }
  // buffer flushed!
  assert(s->pressure == 0);
  ev_io_stop(ev_default_loop(0), watcher);
}

void outstream_init(struct outstream *s, int fd, void (*error_cb)(struct outstream *)) {
  ev_io_init(&s->watcher, outstream_writable_cb, fd, EV_WRITE);
  // ev_io_start(ev_default_loop(0), &s->watcher);
  s->input_watcher = NULL;
  s->first_buf = NULL;
  s->last_buf = NULL;
  s->pressure = 0;
  s->error_cb = error_cb;
}

void outstream_input_set(struct outstream *s, struct ev_io *w) {
  // remove pressure on old path
  if (s->input_watcher && (s->input_watcher->events & EV_READ) == 0)
    alter_ev_io_events(s->input_watcher, 1, EV_READ);
  
  s->input_watcher = w;
  if (w == NULL) return;
  assert(w->events & EV_READ);
  
  // maybe add pressure on new path
  if (s->pressure > OUTSTREAM_HIGH)
    alter_ev_io_events(s->input_watcher, 0, EV_READ);
}

void outstream_nuke(struct outstream *s) {
  struct buffer *buf = s->first_buf;
  struct buffer *next_buf;
  while (buf != NULL) {
    next_buf = buf->next;
    free(buf->free_ptr);
    free(buf);
    buf = next_buf;
  }
  
  outstream_input_set(s, NULL);
  ev_io_stop(ev_default_loop(0), &s->watcher);
}

void outstream_send(struct outstream *s, char *buf, size_t len) {
  char *free_ptr = buf;
  if (s->first_buf == NULL) {
    ssize_t written = write(s->watcher.fd, buf, len);
    if (written == -1 && errno != EAGAIN) {
      s->error_cb(s); return;
    } else if (written == 0) {
      s->error_cb(s); return;
    }
    if (written == len) { free(buf); return; } // yaaay, no buffer magic needed!
    
    // unlikely: empty->filled transition
    if (written == -1) written = 0;
    buf += written;
    len -= written;
  }
  
  struct buffer *buffer = malloc(sizeof(struct buffer));
  buffer->buf = buf;
  buffer->free_ptr = free_ptr;
  buffer->len = len;
  buffer->next = NULL;
  if (s->last_buf == NULL) {
    s->first_buf = buffer;
    ev_io_start(ev_default_loop(0), &s->watcher);
  } else {
    s->last_buf->next = buffer;
  }
  s->last_buf = buffer;
  s->pressure += len;
  if (s->pressure >= OUTSTREAM_HIGH && s->pressure - len < OUTSTREAM_HIGH && s->input_watcher != NULL) {
    alter_ev_io_events(s->input_watcher, 0, EV_READ);
  }
}
