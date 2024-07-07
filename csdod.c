/*
* Copyright(c) 2012-2021 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
*/
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

#include <stdbool.h>
#include <assert.h>
#include <syslog.h>
#include <signal.h>
#include <poll.h>
#include <sys/wait.h>
#include <pthread.h>

#include "utils.h"
/*
 * timeout 毫秒
 */
static int poll_wait(int efds[], int nums, int timeout)
{
	int             max = nums;
	struct pollfd   pfds[max];

	for (int i = 0; i < max; i++) {
		pfds[i].fd = efds[i];
		pfds[i].events = POLLIN;
	}

	do {
		int have = poll(pfds, max, timeout);

		if (have < 0) {
			if ((errno == EINTR) || (errno == EAGAIN)) {
				continue;
			}

			assert(0);
		} else if (have == 0) {
			/*timeout*/
			return 0;
		} else {
			int done = 0;

			/* An event on one of the fds has occurred. */
			for (int i = 0; i < max; i++) {
				int ev = pfds[i].revents;

				if (ev & (POLLERR | POLLNVAL)) {
					assert(0);
				}

				/*写端关闭,会触发POLLHUP*/
				if (ev & (POLLIN | POLLHUP)) {
					efds[done] = pfds[i].fd;

					done++;

					if (done == have) {
						break;
					}
				}
			}

			return have;
		}
	} while (1);
}

static void set_non_blocking(int fd) {
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		perror("fcntl");
		exit(EXIT_FAILURE);
	}
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) == -1) {
		perror("fcntl");
		exit(EXIT_FAILURE);
	}
}

typedef void (*sshsig_t)(int);
sshsig_t ssh_signal(int signum, sshsig_t handler)
{
	struct sigaction sa, osa;

	/* mask all other signals while in handler */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handler;
	sigfillset(&sa.sa_mask);
#if defined(SA_RESTART) && !defined(NO_SA_RESTART)
	if (signum != SIGALRM)
		sa.sa_flags = SA_RESTART;
#endif
	if (sigaction(signum, &sa, &osa) == -1) {
		syslog(LOG_WARNING, "sigaction(%s): %s", strsignal(signum), strerror(errno));
		return SIG_ERR;
	}
	return osa.sa_handler;
}

typedef void (*CSDO_GOT_CB)(void *private, void *data, uint64_t size, int std_fileno);

int do_local_cmd(char **arglist, CSDO_GOT_CB got_cb, void *private)
{
	int c_out, c_err;
	int p_out, p_err;
	int out[2], err[2];
#ifdef USE_PIPES
	if ((pipe(out) == -1) || (pipe(err) == -1)) {
		syslog(LOG_CRIT, "pipe: %s", strerror(errno));
		abort();
	}
	p_out = out[0];
	p_err = err[0];
	c_out = out[1];
	c_err = err[1];
#else
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, out) == -1) {
		syslog(LOG_CRIT, "socketpair: %s", strerror(errno));
		abort();
	}
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, err) == -1) {
		syslog(LOG_CRIT, "socketpair: %s", strerror(errno));
		abort();
	}
	p_out = out[0];
	p_err = err[0];
	c_out = out[1];
	c_err = err[1];
#endif

	/* Fork a child to execute the command on the remote host using ssh. */
	pid_t pid = fork();
	switch (pid) {
		case -1:
			syslog(LOG_CRIT, "fork: %s", strerror(errno));
			abort();
		case 0:
			/* Child. */
			if ((dup2(c_out, STDOUT_FILENO) == -1) ||
					(dup2(c_err, STDERR_FILENO) == -1)) {
				fprintf(stderr, "dup2: %s\n", strerror(errno));
				_exit(EXIT_FAILURE);
			}
			close(p_out);
			close(p_err);
			close(c_out);
			close(c_err);

			/*
			 * The underlying ssh is in the same process group, so we must
			 * ignore SIGINT if we want to gracefully abort commands,
			 * otherwise the signal will make it to the ssh process and
			 * kill it too.  Contrawise, since sftp sends SIGTERMs to the
			 * underlying ssh, it must *not* ignore that signal.
			 */
			ssh_signal(SIGINT, SIG_IGN);
			ssh_signal(SIGTERM, SIG_DFL);
			execvp(arglist[0], arglist);
			perror(arglist[0]);
			_exit(EXIT_FAILURE);
		default:
			/* Parent.  Close the other side, and return the local side. */
			close(c_out);
			close(c_err);

			set_non_blocking(p_out);
			set_non_blocking(p_err);

			char data[PAGE_SIZE];
			bool out_finish = false;
			bool err_finish = false;
			int efds[2] = {};
			int idxs = 0;
			int i;
			do {
				if (out_finish && err_finish)
					break;
				idxs = 0;
				if (!out_finish)
					efds[idxs++] = p_out;
				if (!err_finish)
					efds[idxs++] = p_err;
				idxs = poll_wait(efds, idxs, -1);

				for (i = 0; i < idxs; i ++) {
					do {
						int bytes = read(efds[i], data, sizeof(data));
						if (bytes > 0) {
							got_cb(private, data, bytes, (efds[i] == p_out) ? STDOUT_FILENO : STDERR_FILENO);
						} else if (bytes == 0) {
							// 管道被关闭
							if (efds[i] == p_out)
								out_finish = true;
							else
								err_finish = true;
							break;
						} else if (bytes == -1 && errno == EAGAIN) {
							// 非阻塞模式下，暂时没有数据可读
							break;
						} else {
							if (efds[i] == p_out)
								out_finish = true;
							else
								err_finish = true;
							syslog(LOG_CRIT, "do_local_cmd: read: %s", strerror(errno));
							abort();
							break;
						}
					} while (1);
				}
			} while (1);


			close(p_out);
			close(p_err);

			int status;
			while (waitpid(pid, &status, 0) == -1) {
				if (errno != EINTR) {
					syslog(LOG_CRIT, "do_local_cmd: waitpid: %s", strerror(errno));
					abort();
				}
			}

			if (WIFEXITED(status)) {
				// 子进程正常退出
				int exit_code = WEXITSTATUS(status);
				return exit_code;
			} else {
				if (WIFSIGNALED(status)) {
					// 子进程被信号终止
					syslog(LOG_WARNING, "Child killed by signal %d\n", WTERMSIG(status));
				}
				return EXIT_FAILURE;
			}
	}
}

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
		syslog(LOG_ERR, "write errno %d", errno);
		return rv;
	}

	if (rv != count) {
		count -= rv;
		off += rv;
		goto retry;
	}
	return 0;
}


static int setup_listener(const char *sock_path)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int rv, sd;

	/* we listen for new client connections on socket sd */

	sd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (sd < 0) {
		syslog(LOG_ERR, "socket error %d %d", sd, errno);
		return sd;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	strcpy(&addr.sun_path[1], sock_path);
	addrlen = sizeof(sa_family_t) + strlen(addr.sun_path+1) + 1;

	rv = bind(sd, (struct sockaddr *) &addr, addrlen);
	if (rv < 0) {
		syslog(LOG_ERR, "bind error %d %d", rv, errno);
		close(sd);
		return rv;
	}

	rv = listen(sd, 5);
	if (rv < 0) {
		syslog(LOG_ERR, "listen error %d %d", rv, errno);
		close(sd);
		return rv;
	}
	return sd;
}

static void csdo_got_cb(void *private, void *data, uint64_t size, int std_fileno)
{
	int fd = *(int *)private;
	struct csdo_respond_header rph = {};
	csdo_query_init_header(&rph.bh);
	rph.length = size;
	rph.std_fileno = std_fileno;
	int rv = do_write(fd, &rph, sizeof(rph));
	if (rv < 0)
		return;

	do_write(fd, data, size);
}

static void do_query_work(int fd, char *cmd, uint64_t len)
{
	struct cmd_arg_list list = {};
	cmd_decode(&list, cmd, len);
	for (int i = 0; i < list.argc; i ++) {
		syslog(LOG_DEBUG, "arg %d,%s\n", i, list.argv[i]);
	}

	int result = do_local_cmd(list.argv, csdo_got_cb, (void *)&fd);

	struct csdo_respond_header rph = {};
	csdo_query_init_header(&rph.bh);
	rph.length = 0;
	rph.result = result;
	do_write(fd, &rph, sizeof(rph));
}

static void *csdo_query_handle(void *arg)
{
        int fd = (int)(uintptr_t)arg;
	struct csdo_request_header rqh;
	char *extra = NULL;

	int rv = do_read(fd, &rqh, sizeof(rqh));
	if (rv < 0) {
		goto out;
	}

	if (rqh.bh.magic != CSDO_QUERY_MAGIC) {
		goto out;
	}

	if ((rqh.bh.version & 0xFFFF0000) != (CSDO_QUERY_VERSION & 0xFFFF0000)) {
		goto out;
	}

	if (rqh.length > 0) {
		extra = malloc(rqh.length);
		if (!extra) {
			syslog(LOG_ERR, "process_connection no mem %lu", rqh.length);
			goto out;
		}
		memset(extra, 0, rqh.length);

		rv = do_read(fd, extra, rqh.length);
		if (rv < 0) {
			syslog(LOG_DEBUG, "connection %d extra read error %d", fd, rv);
			goto out;
		}
	}

	do_query_work(fd, extra, rqh.length);

out:
	close(fd);
	if (extra) {
		free(extra);
	}

	pthread_exit(0);
}

static void *csdo_query_process(void)
{
	int sd, fd, rv;
	pthread_t thread;
	char sock_path[PATH_MAX] = {};

	snprintf(sock_path, sizeof(sock_path), "%s", CSDO_QUERY_QUERY_SOCK_PATH);
	sd = setup_listener(sock_path);
	if (sd < 0)
		return NULL;

	for (;;) {
		fd = accept(sd, NULL, NULL);
		if (fd < 0)
			return NULL;

		rv = pthread_create(&thread, NULL, csdo_query_handle, (void *)(uintptr_t)fd);
		if (rv < 0) {
			syslog(LOG_CRIT, "pthread_create failed!");
			close(fd);
		}
	}
	return NULL;
}

int main(int argc, char **argv)
{
	daemon(0, 0);
	csdo_query_process();
	return 0;
}
