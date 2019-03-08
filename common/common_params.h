/* This common_user.h is used by userspace programs */
#ifndef __COMMON_PARAMS_H
#define __COMMON_PARAMS_H

#include "common_defines.h"

void usage(const char *prog_name, const char *doc,
           const struct option *long_options, bool full);

void parse_cmdline_args(int argc, char **argv,
			const struct option *long_options,
                        struct config *cfg, const char *doc);

#endif /* __COMMON_PARAMS_H */
