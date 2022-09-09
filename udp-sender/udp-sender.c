/*
 * udp sender for bandwidth test
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>

#define BUF_SIZE 14400
#define REP_COUNT 10000

int main(int argc, char *argv[])
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sfd, s, j;
	size_t len;
	ssize_t nread;
	char buf[BUF_SIZE];
	struct timeval start, end ;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s host port\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	/* Obtain address(es) matching host/port */

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
	hints.ai_flags = 0;
	hints.ai_protocol = 0;          /* Any protocol */

	s = getaddrinfo(argv[1], argv[2], &hints, &result);
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}

	/* getaddrinfo() returns a list of address structures.
	Try each address until we successfully connect(2).
	If socket(2) (or connect(2)) fails, we (close the socket
	and) try the next address. */

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1)
			continue;

		if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
			break;                  /* Success */

		close(sfd);
	}

	if (rp == NULL) {               /* No address succeeded */
		fprintf(stderr, "Could not connect\n");
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(result);           /* No longer needed */

	memset(buf,0,BUF_SIZE) ;
	gettimeofday(&start,NULL) ;
	for(j=0; j<REP_COUNT; j += 1) {
	    write(sfd, buf, BUF_SIZE) ;
	}
	gettimeofday(&end, NULL);
	double duration=(end.tv_sec-start.tv_sec) + (end.tv_usec-start.tv_usec)*1e-6;
	unsigned long bytes=(unsigned long)BUF_SIZE*REP_COUNT;
	double bitrate=(bytes*8)/duration;
	printf("%lu bytes in %f seconds, rate=%f Gbit/sec\n", bytes, duration, bitrate*1e-9);

	close(sfd) ;

}
