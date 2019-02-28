/* This common_user.h is used by userspace programs */
#ifndef __COMMON_USER_H
#define __COMMON_USER_H

/* Exit return codes */
#define EXIT_OK		0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL		1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION	2
#define EXIT_FAIL_XDP		3

void usage(const char *prog_name, const char *doc,
           const struct option *long_options);

#endif /* __COMMON_USER_H */
