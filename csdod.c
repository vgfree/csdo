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
#include <stdbool.h>
#include <assert.h>
#include <syslog.h>
#include <signal.h>
#include <poll.h>
#include <sys/wait.h>
#include <pthread.h>
#include <grp.h>
#include <pwd.h>

#include "utils.h"


/*
 * timeout 毫秒
 */
static int poll_wait(int efds[], int nums, int timeout)
{
	int     max = nums;
	struct pollfd pfds[max];

	for (int i = 0; i < max; i++) {
		pfds[i].fd = efds[i];
		pfds[i].events = POLLIN;
	}

	while (1) {
		int have = poll(pfds, max, timeout);

		if (have < 0) {
			if ((errno == EINTR) || (errno == EAGAIN)) {
				continue;
			}
			syslog(LOG_ERR, "poll_wait: error %d: %s", errno, strerror(errno));
			return -1;
		} else if (have == 0) {
			/* timeout */
			return 0;
		} else {
			int done = 0;

			/* An event on one of the fds has occurred. */
			for (int i = 0; i < max; i++) {
				int ev = pfds[i].revents;

				if (ev & (POLLERR | POLLNVAL)) {
					syslog(LOG_ERR, "poll_wait: invalid event on fd %d", pfds[i].fd);
					return -1;
				}

				/* 写端关闭,会触发POLLHUP */
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
	}
}

static void set_non_blocking(int fd) {
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		syslog(LOG_ERR, "fcntl F_GETFL: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) == -1) {
		syslog(LOG_ERR, "fcntl F_SETFL: %s", strerror(errno));
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

int do_local_cmd(char **arglist, CSDO_GOT_CB got_cb, void *private, uid_t uid)
{
	int c_out, c_err;
	int p_out, p_err;
	int out[2], err[2];

	/* 验证 arglist 和 got_cb */
	if (!arglist || !arglist[0] || !got_cb) {
		syslog(LOG_ERR, "do_local_cmd: invalid arglist=%p or got_cb=%p", arglist, got_cb);
		return -1;
	}

#ifdef USE_PIPES
	if ((pipe(out) == -1) || (pipe(err) == -1)) {
		syslog(LOG_CRIT, "pipe: %s", strerror(errno));
		return -1;
	}
	p_out = out[0];
	p_err = err[0];
	c_out = out[1];
	c_err = err[1];
#else
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, out) == -1) {
		syslog(LOG_CRIT, "socketpair stdout: %s", strerror(errno));
		return -1;
	}
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, err) == -1) {
		syslog(LOG_CRIT, "socketpair stderr: %s", strerror(errno));
		close(out[0]);
		close(out[1]);
		return -1;
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
			close(p_out);
			close(p_err);
			close(c_out);
			close(c_err);
			return -1;
		case 0:
			/* Child. */
			do {
				if (getpwuid(uid) == NULL) {
					syslog(LOG_ERR, "do_local_cmd: invalid uid %u for command '%s'", uid, arglist[0]);
					fprintf(stderr, "Invalid user with UID %u for command '%s'\n", uid, arglist[0]);
					break;
				}
				if (setuid(uid) < 0) {
					syslog(LOG_ERR, "do_local_cmd: setuid %u for command '%s': %s", uid, arglist[0], strerror(errno));
					fprintf(stderr, "Failed to switch to user with UID %u for command '%s'\n", uid, arglist[0]);
					break;
				}

				if ((dup2(c_out, STDOUT_FILENO) == -1) ||
						(dup2(c_err, STDERR_FILENO) == -1)) {
					syslog(LOG_ERR, "dup2: %s", strerror(errno));
					break;
				}
				close(p_out);
				close(p_err);
				close(c_out);
				close(c_err);

				/*
				 * The underlying ssh is in the same process group, so we must
				 * ignore SIGINT if we want to gracefully abort commands,
				 * otherwise the signal will make it to the ssh process and
				 * kill it too. Contrawise, since sftp sends SIGTERMs to the
				 * underlying ssh, it must *not* ignore that signal.
				 */
				ssh_signal(SIGINT, SIG_IGN);
				ssh_signal(SIGTERM, SIG_DFL);
				execvp(arglist[0], arglist);
				syslog(LOG_ERR, "execvp %s: %s", arglist[0], strerror(errno));
				_exit(EXIT_FAILURE);
			} while (0);

			close(p_out);
			close(p_err);
			close(c_out);
			close(c_err);
			_exit(EXIT_FAILURE);
		default:
			/* Parent. Close the other side, and return the local side. */
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

				if (idxs < 0) {
					close(p_out);
					close(p_err);
					return -1;
				}

				for (i = 0; i < idxs; i++) {
					do {
						int bytes = read(efds[i], data, sizeof(data));
						if (bytes > 0) {
							got_cb(private, data, bytes, (efds[i] == p_out) ? STDOUT_FILENO : STDERR_FILENO);
						} else if (bytes == 0) {
							/* 管道被关闭 */
							if (efds[i] == p_out)
								out_finish = true;
							else
								err_finish = true;
							break;
						} else if (bytes == -1 && errno == EAGAIN) {
							/* 非阻塞模式下，暂时没有数据可读 */
							break;
						} else {
							if (efds[i] == p_out)
								out_finish = true;
							else
								err_finish = true;
							syslog(LOG_CRIT, "do_local_cmd: read: %s", strerror(errno));
							close(p_out);
							close(p_err);
							return -1;
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
					return -1;
				}
			}

			if (WIFEXITED(status)) {
				/* 子进程正常退出 */
				int exit_code = WEXITSTATUS(status);
				return exit_code;
			} else {
				if (WIFSIGNALED(status)) {
					/* 子进程被信号终止 */
					syslog(LOG_WARNING, "Child killed by signal %d", WTERMSIG(status));
				}
				return EXIT_FAILURE;
			}
	}
}

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
		if (rv == 0)
			return -1;
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

static int setup_listener(const char *sock_path)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int rv, sd;

	/* we listen for new client connections on socket sd */
	sd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (sd < 0) {
		syslog(LOG_ERR, "socket: error %d: %s", sd, strerror(errno));
		return sd;
	}

	unlink(sock_path); /* Remove stale socket file */
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
	addrlen = sizeof(addr);

	rv = bind(sd, (struct sockaddr *)&addr, addrlen);
	if (rv < 0) {
		syslog(LOG_ERR, "bind: error %d: %s", rv, strerror(errno));
		close(sd);
		return rv;
	}

	rv = listen(sd, 5);
	if (rv < 0) {
		syslog(LOG_ERR, "listen: error %d: %s", rv, strerror(errno));
		close(sd);
		return rv;
	}

	/* Set socket file permissions for group access */
	rv = chmod(sock_path, 0660);
	if (rv < 0) {
		syslog(LOG_ERR, "chmod: error %d: %s", rv, strerror(errno));
		close(sd);
		return rv;
	}

	/* Try to find an appropriate group: sudo or wheel */
	struct group *grp = NULL;
	const char *group_name = NULL;
	if ((grp = getgrnam("sudo")) != NULL) {
		group_name = "sudo";
	} else if ((grp = getgrnam("wheel")) != NULL) {
		group_name = "wheel";
	}

	if (!grp) {
		syslog(LOG_ERR, "chown: no suitable group found (tried sudo, wheel)");
		close(sd);
		return -1;
	}

	syslog(LOG_INFO, "Using group '%s' (gid %d) for socket permissions", group_name, grp->gr_gid);
	rv = chown(sock_path, 0, grp->gr_gid);
	if (rv < 0) {
		syslog(LOG_ERR, "chown: error %d: %s", rv, strerror(errno));
		close(sd);
		return rv;
	}

	return sd;
}

static void csdo_got_cb(void *private, void *data, uint64_t size, int std_fileno)
{
	int *fd_ptr = (int *)private;
	if (!fd_ptr) {
		syslog(LOG_ERR, "csdo_got_cb: null private pointer");
		return;
	}
	int fd = *fd_ptr;
	if (fd < 0) {
		syslog(LOG_ERR, "csdo_got_cb: invalid fd %d", fd);
		return;
	}

	struct csdo_respond_header rph = {};
	csdo_query_init_header(&rph.bh);
	rph.length = size;
	rph.std_fileno = std_fileno;
	int rv = do_write(fd, &rph, sizeof(rph));
	if (rv < 0) {
		syslog(LOG_ERR, "csdo_got_cb: write header failed: %s", strerror(errno));
		return;
	}
	rv = do_write(fd, data, size);
	if (rv < 0) {
		syslog(LOG_ERR, "csdo_got_cb: write data failed: %s", strerror(errno));
	}
}

static void do_query_work(int fd, char *cmd, uint64_t len, uid_t uid)
{
	struct cmd_arg_list list = {};

	if (len > 0 && !cmd) {
		syslog(LOG_ERR, "do_query_work: null cmd with non-zero len=%lu", len);
		return;
	}

	if (cmd_decode(&list, cmd, len) < 0) {
		syslog(LOG_ERR, "do_query_work: cmd_decode failed");
		return;
	}

	for (int i = 0; i < list.argc; i++) {
		syslog(LOG_DEBUG, "arg %d: %s", i, list.argv[i] ? list.argv[i] : "(null)");
	}

	int result = do_local_cmd(list.argv, csdo_got_cb, (void *)&fd, uid);

	struct csdo_respond_header rph = {};
	csdo_query_init_header(&rph.bh);
	rph.length = 0;
	rph.result = result;
	do_write(fd, &rph, sizeof(rph));
	/* Note: list.argv points to cmd buffer, freed by caller */
}

static void *csdo_query_handle(void *arg)
{
	int fd = (int)(uintptr_t)arg;
	struct csdo_request_header rqh;
	char *extra = NULL;

	if (fd < 0) {
		syslog(LOG_ERR, "csdo_query_handle: invalid fd %d", fd);
		pthread_exit(0);
	}

	int rv = do_read(fd, &rqh, sizeof(rqh));
	if (rv < 0) {
		goto out;
	}

	if (rqh.bh.magic != CSDO_QUERY_MAGIC) {
		syslog(LOG_ERR, "Invalid magic number: %u", rqh.bh.magic);
		goto out;
	}

	if ((rqh.bh.version & 0xFFFF0000) != (CSDO_QUERY_VERSION & 0xFFFF0000)) {
		syslog(LOG_ERR, "Invalid version: %u", rqh.bh.version);
		goto out;
	}

	if (rqh.length > 0) {
		extra = malloc(rqh.length);
		if (!extra) {
			syslog(LOG_ERR, "csdo_query_handle: no memory for %lu bytes", rqh.length);
			goto out;
		}
		memset(extra, 0, rqh.length);

		rv = do_read(fd, extra, rqh.length);
		if (rv < 0) {
			syslog(LOG_DEBUG, "connection %d: extra read error %d", fd, rv);
			goto out;
		}
	}

	do_query_work(fd, extra, rqh.length, rqh.uid);

out:
	if (extra) {
		free(extra);
	}
	close(fd);
	pthread_exit(0);
}

static void *csdo_query_process(void)
{
	int sd, fd, rv;
	pthread_t thread;

	/* Check if running as root */
	if (geteuid() != 0) {
		syslog(LOG_CRIT, "csdod must run as root");
		return NULL;
	}

	sd = setup_listener(CSDO_SOCKET_PATH);
	if (sd < 0)
		return NULL;

	for (;;) {
		fd = accept(sd, NULL, NULL);
		if (fd < 0) {
			syslog(LOG_ERR, "accept: %s", strerror(errno));
			continue;
		}

		rv = pthread_create(&thread, NULL, csdo_query_handle, (void *)(uintptr_t)fd);
		if (rv < 0) {
			syslog(LOG_CRIT, "pthread_create failed: %s", strerror(errno));
			close(fd);
		} else {
			pthread_detach(thread); /* Detach thread to avoid resource leak */
		}
	}
	close(sd);
	return NULL;
}

int main(int argc, char **argv)
{
	openlog("csdod", LOG_PID | LOG_CONS, LOG_DAEMON);
	daemon(0, 0);
	csdo_query_process();
	closelog();
	return 0;
}
