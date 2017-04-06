/*
 * Copyright 2017, Victor van der Veen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _UTIL_SAFEIO_H
#define _UTIL_SAFEIO_H

#include "util_def.h"

#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <dirent.h>

#define _UTIL_SAFEIO_MIN_FD  1000

/*
 * Safe file descriptor opening functions.
 * XXX: Most daemon processes will close file descriptors 0, 1 and 2.
 * This can lead to the unfortunate case where a new file
 * descriptor will unwillingly take the place of one of these.
 * For example, if a socket is given fd 2, then any message printed
 * to STDERR (from libc, for example) will be sent across that socket.
 */
static inline int util_safeio_get_fd_min(int fd, int min_fd, int force_new)
{
    int flags, new_fd;
    /*
     * fd < 0  -> error
     * fd >= min_fd -> valid and safe fd
     */
    if (fd < 0 || (fd >= min_fd && !force_new))
        return fd;

    flags = fcntl(fd, F_GETFD);
    if (flags < 0)
        return -1;

    /* Duplicate fd to a value >= min_fd and close orignal fd. */
    if (flags & FD_CLOEXEC)
        new_fd = fcntl(fd, F_DUPFD_CLOEXEC, min_fd);
    else
        new_fd = fcntl(fd, F_DUPFD, min_fd);

    if (new_fd < 0)
        return -1;

    if (close(fd) < 0)
        return -1;

    /*
     * XXX: Due to a weird mechanism in the kernel, successive
     * dup() calls will detect a race condition if the file
     * descriptor is left closed. Redirect it to /dev/null.
     */
    open("/dev/null", O_RDWR);
    return new_fd;
}

static inline int util_safeio_get_fd(int fd)
{
    return util_safeio_get_fd_min(fd, _UTIL_SAFEIO_MIN_FD, 0);
}

static inline int util_safeio_open(const char *pathname, int flags, ...)
{
    if (flags & O_CREAT) {
        mode_t mode;
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
        return util_safeio_get_fd(open(pathname, flags, mode));
    } else
        return util_safeio_get_fd(open(pathname, flags));
}

static inline int util_safeio_creat(const char *pathname, mode_t mode)
{
    return util_safeio_get_fd(creat(pathname, mode));
}

static inline int util_safeio_socket(int domain, int type, int protocol)
{
    return util_safeio_get_fd(socket(domain, type, protocol));
}

static inline int util_safeio_socketpair(int domain, int type, int protocol,
    int sv[2])
{
    if (socketpair(domain, type, protocol, sv) < 0)
        return -1;

    sv[0] = util_safeio_get_fd(sv[0]);
    sv[1] = util_safeio_get_fd(sv[1]);
    return 0;
}

static inline int util_safeio_accept(int sockfd, struct sockaddr *addr,
    socklen_t *addrlen)
{
    return util_safeio_get_fd(accept(sockfd, addr, addrlen));
}

static inline int util_safeio_accept4(int sockfd, struct sockaddr *addr,
    socklen_t *addrlen, int flags)
{
    return util_safeio_get_fd(accept4(sockfd, addr, addrlen, flags));
}

static inline int util_safeio_fdwalk(int (*cb)(void *cb_args, int fd),
    void *cb_args)
{
  int open_max;
  int fd;
  int res = 0;
  struct rlimit rl;
  DIR *d;

  if ((d = opendir("/proc/self/fd"))) {
      struct dirent *de;

      while ((de = readdir(d))) {
          long l;
          char *e = NULL;

          if (de->d_name[0] == '.')
              continue;

          errno = 0;
          l = strtol(de->d_name, &e, 10);
          if (errno != 0 || !e || *e)
              continue;

          fd = (int) l;

          if ((long) fd != l)
              continue;

          if (fd == dirfd(d))
              continue;

          if ((res = cb (cb_args, fd)) != 0)
              break;
        }

      closedir(d);
      return res;
  }

  /* If /proc is not mounted or not accessible we fall back to the old
   * rlimit trick */

  if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_max != RLIM_INFINITY)
      open_max = rl.rlim_max;
  else
      open_max = sysconf (_SC_OPEN_MAX);

  for (fd = 0; fd < open_max; fd++)
      if ((res = cb (cb_args, fd)) != 0)
          break;

  return res;
}

#endif /* _UTIL_SAFEIO_H */

