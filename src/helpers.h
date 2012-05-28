#ifndef helpers_h
#define helpers_h

#include <stddef.h>

#define BUF_APPEND(buf, data, len) { memcpy(buf, data, len); buf += len; }
#define BUF_APPEND_STR(buf, str) BUF_APPEND(buf, str, strlen(str))

// Looks complicated, but should actually be even faster than the `void *user_data` method.
// Should compile to a fixed-size decrement.
#define CASTUP(pointer, supertype, member) (                       \
          (supertype *) (((char *) pointer) - offsetof(supertype, member))    \
        )

#define YADA assert(0/* XXX NOT IMPLEMENTED YET XXX */);

int unblock_fd(int fd);

#endif
