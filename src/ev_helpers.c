#include "ev_helpers.h"

void alter_ev_io_events(struct ev_io *w, int add, int events_change) {
  struct ev_loop *loop = ev_default_loop(0);
  ev_io_stop(loop, w);
  int events = w->events;
  if (add) {
    events |= events_change;
  } else {
    events &= ~events_change;
  }
  ev_io_set(w, w->fd, events);
  ev_io_start(loop, w);
}
