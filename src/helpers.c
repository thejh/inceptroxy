#include <unistd.h>
#include <fcntl.h>

int unblock_fd(int fd) {
  return fcntl(fd, F_SETFL, O_NONBLOCK);
}
