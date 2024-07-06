#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <limits.h>
#include <sys/user.h>

#include "utils.h"
#define MIN(a, b) ((a) < (b) ? (a) : (b))

static int do_read(int fd, void *buf, size_t count)
{
	int rv;
	size_t off = 0;

	while (off < count) {
		rv = read(fd, (char *)buf + off, count - off);
		if (rv == 0)
			return -1;
		if (rv == -1 && errno == EINTR)
			continue;
		if (rv == -1)
			return -1;
		off += rv;
	}
	return 0;
}

static int do_write(int fd, void *buf, size_t count)
{
	int rv, off = 0;

 retry:
	rv = write(fd, (char *)buf + off, count);
	if (rv == -1 && errno == EINTR)
		goto retry;
	if (rv < 0) {
		perror("write");
		return rv;
	}

	if (rv != count) {
		count -= rv;
		off += rv;
		goto retry;
	}
	return 0;
}

static int do_connect(const char *sock_path)
{
	struct sockaddr_un sun;
	socklen_t addrlen;
	int rv, fd;

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		goto out;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strcpy(&sun.sun_path[1], sock_path);
	addrlen = sizeof(sa_family_t) + strlen(sun.sun_path+1) + 1;

	rv = connect(fd, (struct sockaddr *) &sun, addrlen);
	if (rv < 0) {
		close(fd);
		fd = rv;
	}
out:
	return fd;
}

int csdo_query_request(void *cmd, size_t len)
{
	struct csdo_request_header rqh = {};
	struct csdo_respond_header rph = {};
	int fd, rv;
	char sock_path[PATH_MAX] = {};
	char data[PAGE_SIZE];

	csdo_query_init_header(&rqh.bh);
	rqh.length = len;

	snprintf(sock_path, sizeof(sock_path), "%s", CSDO_QUERY_QUERY_SOCK_PATH);
	fd = do_connect(sock_path);
	if (fd < 0) {
		rv = fd;
		goto out;
	}

	rv = do_write(fd, &rqh, sizeof(rqh));
	if (rv < 0)
		goto out_close;

	if (len) {
		rv = do_write(fd, cmd, len);
		if (rv < 0)
			goto out_close;
	}

	do {
		rv = do_read(fd, &rph, sizeof(rph));
		if (rv < 0)
			goto out_close;

		len = rph.length;
		if (len == 0) {
			rv = rph.result;
			break;
		}

		if (len > 0) {
			while (len) {
				int todo = MIN(len, PAGE_SIZE);
				rv = do_read(fd, data, todo);
				if (rv < 0)
					goto out_close;
				len -= todo;
				do_write(rph.std_fileno, data, todo);
			}
		}
	} while (1);
	fflush(stdout);
	fflush(stderr);

out_close:
	close(fd);
out:
	return rv;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		printf("Usage: %s <cmd> <...>\n", argv[0]);
		return -1;
	}
	uint32_t size = 0;
	struct cmd_arg_list list = {};
	list.argc = argc - 1;
	memcpy(list.argv, argv + 1, sizeof(char *) * (argc - 1));
	cmd_encode(&list, NULL, &size);
	char *data = malloc(size);
	cmd_encode(&list, data, &size);

	int res = csdo_query_request(data, size);
	free(data);
	return res;
}
