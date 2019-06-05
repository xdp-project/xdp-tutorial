/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../common/common_defines.h"
#include <netinet/ether.h>

#define TRACEFS_PIPE "/sys/kernel/debug/tracing/trace_pipe"

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

static void print_ether_addr(const char *type, char *str)
{
	__u64 addr;

	if (1 != sscanf(str, "%llu", &addr))
		return;

	printf("%s: %s ", type, ether_ntoa((struct ether_addr *) &addr));
}

int main(int argc, char **argv)
{
	FILE *stream;
	char *line = NULL;
	size_t len = 0;
	ssize_t nread;

	stream = fopen(TRACEFS_PIPE, "r");
	if (stream == NULL) {
		perror("fopen");
		exit(EXIT_FAILURE);
	}


	while ((nread = getline(&line, &len, stream)) != -1) {
		char *tok, *saveptr;
		unsigned int proto;

		tok = strtok_r(line, " ", &saveptr);

		while (tok) {
			if (!strncmp(tok, "src:", 4)) {
				tok = strtok_r(NULL, " ", &saveptr);
				print_ether_addr("src", tok);
			}

			if (!strncmp(tok, "dst:", 4)) {
				tok = strtok_r(NULL, " ", &saveptr);
				print_ether_addr("dst", tok);
			}

			if (!strncmp(tok, "proto:", 5)) {
				tok = strtok_r(NULL, " ", &saveptr);
				if (1 == sscanf(tok, "%u", &proto))
					printf("proto: %u", proto);
			}
			tok = strtok_r(NULL, " ", &saveptr);
		}

		printf("\n");
	}

	free(line);
	fclose(stream);
	return EXIT_OK;
}
