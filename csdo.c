/*
 * Copyright(c) 2024-2025 vgfree omstor
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <limits.h>
#include <sys/user.h>
#include <syslog.h>
#include <pwd.h>
#include <grp.h>

#include "utils.h"
#define MIN(a, b) ((a) < (b) ? (a) : (b))

static int do_read(int fd, void *buf, size_t count)
{
	int rv;
	size_t off = 0;

	if (!buf) {
		syslog(LOG_ERR, "do_read: null buffer");
		return -1;
	}

	while (off < count) {
		rv = read(fd, (char *)buf + off, count - off);
		if (rv == 0) {
			syslog(LOG_ERR, "do_read: connection closed");
			return -1;
		}
		if (rv == -1 && errno == EINTR)
			continue;
		if (rv == -1) {
			syslog(LOG_ERR, "do_read: %s", strerror(errno));
			return -1;
		}
		off += rv;
	}
	return 0;
}

static int do_write(int fd, void *buf, size_t count)
{
	int rv, off = 0;

	if (!buf) {
		syslog(LOG_ERR, "do_write: null buffer");
		return -1;
	}

retry:
	rv = write(fd, (char *)buf + off, count);
	if (rv == -1 && errno == EINTR)
		goto retry;
	if (rv < 0) {
		syslog(LOG_ERR, "do_write: %s", strerror(errno));
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
	if (fd < 0) {
		syslog(LOG_ERR, "do_connect: socket: %s", strerror(errno));
		return fd;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, sock_path, sizeof(sun.sun_path) - 1);
	addrlen = sizeof(sun);

	rv = connect(fd, (struct sockaddr *)&sun, addrlen);
	if (rv < 0) {
		if (errno != EPERM)
			syslog(LOG_ERR, "do_connect: connect: %s", strerror(errno));
		close(fd);
		return rv;
	}
	return fd;
}

int csdo_query_request(void *cmd, size_t len, uid_t uid)
{
	struct csdo_request_header rqh = {};
	struct csdo_respond_header rph = {};
	int fd, rv;
	char data[PAGE_SIZE];

	csdo_query_init_header(&rqh.bh);
	rqh.length = len;
	rqh.uid = uid; /* Set UID for csdod */

	fd = do_connect(CSDO_SOCKET_PATH);
	if (fd < 0) {
		rv = fd;
		if (rv == -EPERM)
			fprintf(stderr, "Permission denied: cannot connect to /var/run/csdod.sock\n");
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

		if (rph.bh.magic != CSDO_QUERY_MAGIC) {
			syslog(LOG_ERR, "csdo_query_request: invalid response magic: %u", rph.bh.magic);
			rv = -1;
			goto out_close;
		}

		uint64_t len = rph.length;
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
				if (rph.std_fileno == STDOUT_FILENO || rph.std_fileno == STDERR_FILENO) {
					rv = do_write(rph.std_fileno, data, todo);
					if (rv < 0)
						goto out_close;
				}
				len -= todo;
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

static int is_user_in_sudo_or_wheel_group(void)
{
	uid_t uid = getuid();
	struct passwd *pw = getpwuid(uid);
	if (!pw) {
		syslog(LOG_ERR, "main: getpwuid failed for uid %u: %s", uid, strerror(errno));
		return -1;
	}

	const char *groups[] = {"sudo", "wheel"};
	for (int i = 0; i < 2; i++) {
		struct group *grp = getgrnam(groups[i]);
		if (!grp) {
			syslog(LOG_ERR, "main: getgrnam failed for group '%s': %s", groups[i], strerror(errno));
			continue;
		}
		for (char **member = grp->gr_mem; *member; member++) {
			if (strcmp(*member, pw->pw_name) == 0)
				return 0;
		}
	}
	syslog(LOG_ERR, "main: user '%s' not in sudo or wheel group", pw->pw_name);
	fprintf(stderr, "Permission denied: user not in sudo or wheel group\n");
	return -EPERM;
}

int main(int argc, char **argv)
{
	openlog("csdo", LOG_PID | LOG_CONS, LOG_DAEMON);

	if (argc < 2) {
		fprintf(stderr, "Usage: %s [-u username] <cmd> <...>\n", argv[0]);
		closelog();
		return -EINVAL;
	}

	if (getuid() && is_user_in_sudo_or_wheel_group()) {
		closelog();
		return -EPERM;
	}

	struct cmd_arg_list list = {};
	list.argc = 0;
	uid_t target_uid = 0; /* Default to root */

	int optind = 1;
	if (argc >= 3 && strcmp(argv[1], "-u") == 0) {
		struct passwd *pw = getpwnam(argv[2]);
		if (!pw) {
			fprintf(stderr, "Invalid user: %s\n", argv[2]);
			syslog(LOG_ERR, "main: invalid user '%s'", argv[2]);
			closelog();
			return -EINVAL;
		}
		target_uid = pw->pw_uid;
		optind = 3;
	}

	if (optind >= argc) {
		fprintf(stderr, "Usage: %s [-u username] <cmd> <...>\n", argv[0]);
		closelog();
		return -EINVAL;
	}

	list.argc = argc - optind;
	memcpy(list.argv, argv + optind, sizeof(char *) * list.argc);

	uint32_t size = 0;
	if (cmd_encode(&list, NULL, &size)) {
		syslog(LOG_ERR, "main: cmd_encode failed for command '%s'", argv[optind]);
		closelog();
		return -EINVAL;
	}
	if (size == 0) {
		syslog(LOG_ERR, "main: cmd_encode returned zero size for command '%s'", argv[optind]);
		closelog();
		return -EINVAL;
	}
	char *data = malloc(size);
	if (!data) {
		syslog(LOG_ERR, "main: malloc failed for %u bytes", size);
		closelog();
		return -ENOMEM;
	}
	if (cmd_encode(&list, data, &size)) {
		syslog(LOG_ERR, "main: cmd_encode failed for command '%s'", argv[optind]);
		free(data);
		closelog();
		return -EINVAL;
	}
	syslog(LOG_DEBUG, "main: encoded command '%s', size=%u", argv[optind], size);

	int res = csdo_query_request(data, size, target_uid);
	free(data);
	closelog();
	return res;
}
