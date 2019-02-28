#include <stddef.h>
#include <stdio.h>
#include <getopt.h>

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
				*long_options[i].flag);
		else
			printf(" short-option: -%c",
				long_options[i].val);
		printf("\n");
	}
	printf("\n");
}
