#include <sys/time.h>

#define SEC 		1000000

struct timeval timestamp() {
	struct timeval tv;
	struct timezone tz;
	memset(&tv, 0, sizeof(tv));
	memset(&tz, 0, sizeof(tz));
	if (gettimeofday(&tv, &tz) < 0) {
		perror("time:");
	}
	return tv;
}

int timedif(const struct timeval &start, const struct timeval &end) {
	return SEC * ( end.tv_sec - start.tv_sec ) + ( end.tv_usec - start.tv_usec );
}

double timedif_sec(struct timeval *start, struct timeval *end) {
	return (double)( end->tv_sec - start->tv_sec ) + (double)( end->tv_usec - start->tv_usec ) / (double)SEC;
}
