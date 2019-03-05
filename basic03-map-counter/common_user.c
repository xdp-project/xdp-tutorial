#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <errno.h>

#include <net/if.h>
#include <linux/if_link.h> /* XDP_FLAGS_* depend on kernel-headers installed */

#include "common_user.h"

int verbose = 1;

void usage(const char *prog_name, const char *doc,
           const struct option *long_options)
{
	int i;

	printf("\nDOCUMENTATION:\n %s\n", doc);
	printf(" Usage: %s (options-see-below)\n", prog_name);
	printf(" Listing options:\n");
	for (i = 0; long_options[i].name != 0; i++) {
		printf(" --%-12s", long_options[i].name);
		if (long_options[i].flag != NULL)
			printf(" flag (internal value:%d)",
			       long_options[i].flag);
		else {
			if (long_options[i].val > 64) /* ord('A') = 65 */
				printf(" short-option: -%c",
				       long_options[i].val);
		}
		printf("\n");
	}
	printf("\n");
}

void parse_cmdline_args(int argc, char **argv,
			const struct option *long_options,
                        struct config *cfg, const char *doc)
{
	int longindex = 0;
	char *dest;
	int opt;

	/* Parse commands line args */
	while ((opt = getopt_long(argc, argv, "hd:SNFUq",
				  long_options, &longindex)) != -1) {
		switch (opt) {
		case 'd':
			if (strlen(optarg) >= IF_NAMESIZE) {
				fprintf(stderr, "ERR: --dev name too long\n");
				goto error;
			}
			cfg->ifname = (char *)&cfg->ifname_buf;
			strncpy(cfg->ifname, optarg, IF_NAMESIZE);
			cfg->ifindex = if_nametoindex(cfg->ifname);
			if (cfg->ifindex == 0) {
				fprintf(stderr,
					"ERR: --dev name unknown err(%d):%s\n",
					errno, strerror(errno));
				goto error;
			}
			break;
		case 'A':
			cfg->xdp_flags &= ~XDP_FLAGS_DRV_MODE; /* Clear flag */
			cfg->xdp_flags &= ~XDP_FLAGS_SKB_MODE; /* Clear flag */
			break;
		case 'S':
			cfg->xdp_flags &= ~XDP_FLAGS_DRV_MODE; /* Clear flag */
			cfg->xdp_flags |= XDP_FLAGS_SKB_MODE;  /* Set   flag */
			break;
		case 'N':
			cfg->xdp_flags &= ~XDP_FLAGS_SKB_MODE; /* Clear flag */
			cfg->xdp_flags |= XDP_FLAGS_DRV_MODE;  /* Set   flag */
			break;
		case 'F':
			cfg->xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
			break;
		case 'U':
			cfg->do_unload = true;
			break;
		case 'q':
			verbose = false;
			break;
		case 1: /* --filename */
			dest  = (char *)&cfg->filename;
			strncpy(dest, optarg, sizeof(cfg->filename));
			break;
		case 2: /* --progsec */
			dest  = (char *)&cfg->progsec;
			strncpy(dest, optarg, sizeof(cfg->progsec));
			break;
		case 'h':
		error:
		default:
			usage(argv[0], doc, long_options);
			exit(EXIT_FAIL_OPTION);
		}
	}
}
