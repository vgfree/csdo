/*
 * Copyright(c) 2024-2025 vgfree omstor
 */
#define _GNU_SOURCE
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
#include <sys/epoll.h>
#include <pthread.h>
#include <grp.h>
#include <pwd.h>
#include <pty.h>
#include <utmp.h>
#include <time.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/file.h>

#include "utils.h"

enum exit_steps_code {
	exit_steps_success = 0,
	exit_steps_server_error,
	exit_steps_client_error,
	exit_steps_child_error,
};

// 资源结构体，用于管理文件描述符
typedef struct relay_session {
	int client_fd;        // 客户端文件描述符
	int master_fd;        // PTY 主文件描述符
	int slave_fd;         // PTY 从文件描述符
	int pipe_stdin[2];    // 标准输入管道
	int pipe_stdout[2];   // 标准输出管道
	int pipe_stderr[2];   // 标准错误管道
	int epoll_fd;         // epoll 文件描述符
	int no_pty;
	struct winsize ws;
	struct termios term;
} relay_session_t;

// 初始化资源结构体
void init_relay_session(relay_session_t *rs) {
	rs->client_fd = -1;
	rs->master_fd = -1;
	rs->slave_fd = -1;
	rs->pipe_stdin[0] = rs->pipe_stdin[1] = -1;
	rs->pipe_stdout[0] = rs->pipe_stdout[1] = -1;
	rs->pipe_stderr[0] = rs->pipe_stderr[1] = -1;
	rs->epoll_fd = -1;
	memset(&rs->ws, 0, sizeof(rs->ws));
}

// 清理资源，关闭所有打开的文件描述符
void cleanup_relay_session(relay_session_t *rs) {
	if (rs->master_fd != -1) {
		close(rs->master_fd);
		x_printf(LOG_INFO, "Closed master_fd=%d", rs->master_fd);
	}
	if (rs->slave_fd != -1) {
		close(rs->slave_fd);
		x_printf(LOG_INFO, "Closed slave_fd=%d", rs->slave_fd);
	}
	if (rs->pipe_stdin[0] != -1) {
		close(rs->pipe_stdin[0]);
		x_printf(LOG_INFO, "Closed pipe_stdin[0]=%d", rs->pipe_stdin[0]);
	}
	if (rs->pipe_stdin[1] != -1) {
		close(rs->pipe_stdin[1]);
		x_printf(LOG_INFO, "Closed pipe_stdin[1]=%d", rs->pipe_stdin[1]);
	}
	if (rs->pipe_stdout[0] != -1) {
		close(rs->pipe_stdout[0]);
		x_printf(LOG_INFO, "Closed pipe_stdout[0]=%d", rs->pipe_stdout[0]);
	}
	if (rs->pipe_stdout[1] != -1) {
		close(rs->pipe_stdout[1]);
		x_printf(LOG_INFO, "Closed pipe_stdout[1]=%d", rs->pipe_stdout[1]);
	}
	if (rs->pipe_stderr[0] != -1) {
		close(rs->pipe_stderr[0]);
		x_printf(LOG_INFO, "Closed pipe_stderr[0]=%d", rs->pipe_stderr[0]);
	}
	if (rs->pipe_stderr[1] != -1) {
		close(rs->pipe_stderr[1]);
		x_printf(LOG_INFO, "Closed pipe_stderr[1]=%d", rs->pipe_stderr[1]);
	}
	if (rs->epoll_fd != -1) {
		close(rs->epoll_fd);
		x_printf(LOG_INFO, "Closed epoll_fd=%d", rs->epoll_fd);
	}
}

int create_norm_bridge(relay_session_t *rs)
{
#ifdef USE_PIPES
	if (pipe(rs->pipe_stdin) == -1) {
		x_printf(LOG_ERR, "Failed to create stdin pipe: %s", strerror(errno));
		return -1;
	}
	fcntl(rs->pipe_stdin[1], F_SETFD, FD_CLOEXEC); // 设置 stdin 写端在 exec 时关闭，保证epoll_wait能收到事件处理EOF
	x_printf(LOG_INFO, "Created stdin pipe: read=%d, write=%d", rs->pipe_stdin[0], rs->pipe_stdin[1]);

	if (pipe(rs->pipe_stdout) == -1) {
		x_printf(LOG_ERR, "Failed to create stdout pipe: %s", strerror(errno));
		return -1;
	}
	fcntl(rs->pipe_stdout[1], F_SETFD, FD_CLOEXEC); // 设置 stdout 写端在 exec 时关闭，保证epoll_wait能收到事件处理EOF
	x_printf(LOG_INFO, "Created stdout pipe: read=%d, write=%d", rs->pipe_stdout[0], rs->pipe_stdout[1]);

	if (pipe(rs->pipe_stderr) == -1) {
		x_printf(LOG_ERR, "Failed to create stderr pipe: %s", strerror(errno));
		return -1;
	}
	fcntl(rs->pipe_stderr[1], F_SETFD, FD_CLOEXEC); // 设置 stderr 写端在 exec 时关闭，保证epoll_wait能收到事件处理EOF
	x_printf(LOG_INFO, "Created stderr pipe: read=%d, write=%d", rs->pipe_stderr[0], rs->pipe_stderr[1]);
#else
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, rs->pipe_stdin) == -1) {
		x_printf(LOG_ERR, "Failed to create stdin socketpair: %s", strerror(errno));
		return -1;
	}
	fcntl(rs->pipe_stdin[1], F_SETFD, FD_CLOEXEC); // 设置 stdin 写端在 exec 时关闭，保证epoll_wait能收到事件处理EOF
	x_printf(LOG_INFO, "Created stdin pipe: read=%d, write=%d", rs->pipe_stdin[0], rs->pipe_stdin[1]);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, rs->pipe_stdout) == -1) {
		x_printf(LOG_ERR, "Failed to create stdout socketpair: %s", strerror(errno));
		return -1;
	}
	fcntl(rs->pipe_stdout[1], F_SETFD, FD_CLOEXEC); // 设置 stdout 写端在 exec 时关闭，保证epoll_wait能收到事件处理EOF
	x_printf(LOG_INFO, "Created stdout pipe: read=%d, write=%d", rs->pipe_stdout[0], rs->pipe_stdout[1]);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, rs->pipe_stderr) == -1) {
		x_printf(LOG_ERR, "Failed to create stderr socketpair: %s", strerror(errno));
		return -1;
	}
	fcntl(rs->pipe_stderr[1], F_SETFD, FD_CLOEXEC); // 设置 stderr 写端在 exec 时关闭，保证epoll_wait能收到事件处理EOF
	x_printf(LOG_INFO, "Created stderr pipe: read=%d, write=%d", rs->pipe_stderr[0], rs->pipe_stderr[1]);
#endif
	return 0;
}

int create_pty_bridge(relay_session_t *rs)
{
	char slave_name[128];

	/* 使用客户端提供的窗口大小 */
	struct winsize default_ws = { .ws_row = 24, .ws_col = 80 };
	if (rs->ws.ws_row == 0 || rs->ws.ws_col == 0) {
		rs->ws = default_ws;
		x_printf(LOG_WARNING, "do_local_cmd: no window size provided, using default rows=%d, cols=%d", rs->ws.ws_row, rs->ws.ws_col);
	} else {
		x_printf(LOG_DEBUG, "do_local_cmd: window size rows=%d, cols=%d", rs->ws.ws_row, rs->ws.ws_col);
	}

	/* 创建 PTY 并应用终端设置 */
	if (openpty(&rs->master_fd, &rs->slave_fd, slave_name, &rs->term, &rs->ws) == -1) {
		x_printf(LOG_ERR, "Failed to create PTY: %s", strerror(errno));
		return -1;
	}
	fcntl(rs->master_fd, F_SETFD, FD_CLOEXEC); // 设置 master 在 exec 时关闭，保证epoll_wait能收到事件处理EOF
	fcntl(rs->slave_fd, F_SETFD, FD_CLOEXEC); // 设置 slave 在 exec 时关闭，保证epoll_wait能收到事件处理EOF
	x_printf(LOG_INFO, "Created PTY %s: master_fd=%d, slave_fd=%d", slave_name, rs->master_fd, rs->slave_fd);
	return 0;
}

// 注册文件描述符到 epoll
int register_epoll(int epfd, int fd, const char *name) {
	struct epoll_event ev = { .events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP, .data.fd = fd };
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
		x_printf(LOG_ERR, "Failed to register %s=%d with epoll: %s", name, fd, strerror(errno));
		return -1;
	}
	x_printf(LOG_INFO, "Registered %s=%d with epoll", name, fd);
	return 0;
}

typedef void (*sshsig_t)(int);

/*
 * Installs a signal handler for the specified signal.
 * Returns the old handler or SIG_ERR on error.
 */
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
		x_printf(LOG_WARNING, "sigaction(%s): %s", strsignal(signum), strerror(errno));
		return SIG_ERR;
	}
	return osa.sa_handler;
}

typedef void (*CSDO_GOT_CB)(void *private, void *data, uint64_t size, int std_fileno);

void child_process(relay_session_t *rs)
{
	// 忽略 SIGHUP 和 SIGPIPE 信号
	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	x_printf(LOG_INFO, "Child: Ignored SIGHUP and SIGPIPE signals");

	// 关闭子进程不需要的文件描述符
	close(rs->client_fd);
	x_printf(LOG_INFO, "Child: Closed client_fd=%d", rs->client_fd);
	if (!rs->no_pty) {
		close(rs->master_fd);
		x_printf(LOG_INFO, "Child: Closed master_fd=%d", rs->master_fd);
	} else {
		close(rs->pipe_stdin[1]);
		x_printf(LOG_INFO, "Child: Closed pipe_stdin[1]=%d", rs->pipe_stdin[1]);
		close(rs->pipe_stdout[0]);
		x_printf(LOG_INFO, "Child: Closed pipe_stdout[0]=%d", rs->pipe_stdout[0]);
		close(rs->pipe_stderr[0]);
		x_printf(LOG_INFO, "Child: Closed pipe_stderr[0]=%d", rs->pipe_stderr[0]);
	}

	if (!rs->no_pty) {
		// 设置 slave_fd 为控制终端
		if (login_tty(rs->slave_fd) == -1) {
			x_printf(LOG_ERR, "Child: login_tty failed on slave_fd=%d: %s", rs->slave_fd, strerror(errno));
			exit(EXIT_FAILURE);
		}
		x_printf(LOG_INFO, "Child: login_tty succeeded on slave_fd=%d", rs->slave_fd);
		close(rs->slave_fd);
		x_printf(LOG_INFO, "Child: Closed slave_fd=%d", rs->slave_fd);
	} else {
		// 重定向标准输入
		if (dup2(rs->pipe_stdin[0], STDIN_FILENO) == -1) {
			x_printf(LOG_ERR, "Child: dup2 stdin failed: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}
		close(rs->pipe_stdin[0]);
		x_printf(LOG_INFO, "Child: Closed pipe_stdin[0]=%d", rs->pipe_stdin[0]);

		// 重定向标准输出
		if (dup2(rs->pipe_stdout[1], STDOUT_FILENO) == -1) {
			x_printf(LOG_ERR, "Child: dup2 stdout failed: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}
		close(rs->pipe_stdout[1]);
		x_printf(LOG_INFO, "Child: Closed pipe_stdout[1]=%d", rs->pipe_stdout[1]);

		// 重定向标准错误
		if (dup2(rs->pipe_stderr[1], STDERR_FILENO) == -1) {
			x_printf(LOG_ERR, "Child: dup2 stderr failed: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}
		close(rs->pipe_stderr[1]);
		x_printf(LOG_INFO, "Child: Closed pipe_stderr[1]=%d", rs->pipe_stderr[1]);
	}
}

int do_client_event(relay_session_t *rs)
{
	char data[PAGE_SIZE] = {};
	int fd = rs->client_fd;
	struct csdo_request_header rqh = {};
	int rv = do_read(fd, &rqh, sizeof(rqh));
	if (rv < 0) {
		x_printf(LOG_INFO, "do_local_cmd: client disconnected: %s", strerror(errno));
		return exit_steps_client_error; /* 客户端断开，直接清理 */
	}
	if (rqh.bh.magic != CSDO_QUERY_MAGIC) {
		x_printf(LOG_ERR, "do_local_cmd: invalid request magic: %u", rqh.bh.magic);
		return exit_steps_client_error;
	}
	if (rqh.type == CSDO_MSG_WINSIZE) {
		/* 处理窗口大小更新 */
		if (!rs->no_pty) {
			if (ioctl(rs->master_fd, TIOCSWINSZ, &rqh.ws) == -1) {
				x_printf(LOG_ERR, "do_local_cmd: ioctl TIOCSWINSZ failed: %s", strerror(errno));
			} else {
				rs->ws = rqh.ws; // 更新 relay_session_t 中的窗口大小
				x_printf(LOG_DEBUG, "do_local_cmd: updated window size rows=%d, cols=%d", rqh.ws.ws_row, rqh.ws.ws_col);
			}
		}
		return exit_steps_success;
	}
	if (rqh.type != CSDO_MSG_OPERATE) {
		x_printf(LOG_ERR, "do_local_cmd: invalid request type %d", rqh.type);
		return exit_steps_client_error;
	}
	if (rqh.std_fileno != STDIN_FILENO) {
		x_printf(LOG_ERR, "do_local_cmd: invalid std_fileno %d", rqh.std_fileno);
		return exit_steps_client_error;
	}
	if (rqh.length == 0) {
		x_printf(LOG_INFO, "do_local_cmd: client tell input over");
		if (!rs->no_pty) {
			// 关闭控制终端以触发 EOF
			close(rs->master_fd);
			x_printf(LOG_INFO, "Parent: Closed master_fd=%d to trigger EOF", rs->master_fd);
			rs->master_fd = -1;
		} else {
			// 关闭标准输入管道写端以触发 EOF
			close(rs->pipe_stdin[1]);
			x_printf(LOG_INFO, "Parent: Closed pipe_stdin[1]=%d to trigger EOF", rs->pipe_stdin[1]);
			rs->pipe_stdin[1] = -1;
		}
		return exit_steps_success;
	}
	uint64_t len = rqh.length;
	while (len) {
		int todo = MIN(len, PAGE_SIZE);
		rv = do_read(fd, data, todo);
		if (rv < 0) {
			x_printf(LOG_INFO, "do_local_cmd: read client data failed: %s", strerror(errno));
			return exit_steps_client_error;
		}
		if (!rs->no_pty) {
			rv = do_write(rs->master_fd, data, todo);
		} else {
			rv = do_write(rs->pipe_stdin[1], data, todo);
		}
		if (rv < 0) {
			x_printf(LOG_ERR, "do_local_cmd: write child: %s", strerror(errno));
			return exit_steps_child_error;
		}
		len -= todo;
	}
	return exit_steps_success;
}

// 处理 epoll 事件
int handle_epoll_events(int epfd, relay_session_t *rs, CSDO_GOT_CB got_cb, void *private)
{
	int max = 3;
	struct epoll_event events[max];
	bool stdout_done = false, stderr_done = false;

	while (!(stdout_done && stderr_done)) {
		x_printf(LOG_DEBUG, "epoll_wait stdout_done=%d, stderr_done=%d", stdout_done, stderr_done);
		int num = epoll_wait(epfd, events, max, -1);
		x_printf(LOG_INFO, "epoll_wait returned %d", num);

		if (num == -1) {
			x_printf(LOG_ERR, "epoll_wait failed: %s", strerror(errno));
			return exit_steps_server_error;
		}

		for (int i = 0; i < num; i++) {
			int fd = events[i].data.fd;
			const char *source = (fd == rs->pipe_stdout[0]) ? "stdout" :
				(fd == rs->pipe_stderr[0]) ? "stderr" :
				(fd == rs->master_fd) ? "master_fd" : "client_fd";

			if (events[i].events & EPOLLIN) {
				if (fd == rs->client_fd) {
					int ret = do_client_event(rs);
					if (ret != exit_steps_success) {
						return ret;
					}
				} else {
					char data[PAGE_SIZE] = {};
					while (1) {
						ssize_t bytes = read(fd, data, sizeof(data));
						if (bytes > 0) {
							if (fd == rs->pipe_stdout[0] || fd == rs->pipe_stderr[0])
								got_cb(private, data, bytes, (fd == rs->pipe_stdout[0]) ? STDOUT_FILENO : STDERR_FILENO);
							else
								got_cb(private, data, bytes, STDOUT_FILENO);
							x_printf(LOG_DEBUG, "Received from %s: %s", source, data);
						} else if (bytes == 0) {
							/* 写端已关闭，管道无数据 */
							x_printf(LOG_INFO, "Detected EOF on %s", source);
							epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);

							if (fd == rs->pipe_stdout[0])
								stdout_done = true;
							else if (fd == rs->pipe_stderr[0])
								stderr_done = true;
							else {
								stdout_done = true;
								stderr_done = true;
							}
							break;
						} else if (bytes == -1 && errno == EINTR) {
							continue;
						} else if (bytes == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
							/* 非阻塞模式下，暂时没有数据可读 */
							break;
						} else {
							x_printf(LOG_ERR, "Read error on %s: %s", source, strerror(errno));
							epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);

							/* 错误处理：PTY 在 EOF 时返回 EIO */
							if (fd == rs->pipe_stdout[0])
								stdout_done = true;
							else if (fd == rs->pipe_stderr[0])
								stderr_done = true;
							else {
								stdout_done = true;
								stderr_done = true;
							}
							break;
						}
					}
				}
			}

			if (events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
				if (events[i].events & EPOLLERR)
					x_printf(LOG_INFO, "EPOLLERR detected on %s", source);
				if (events[i].events & EPOLLHUP)
					x_printf(LOG_INFO, "EPOLLHUP detected on %s", source);
				if (events[i].events & EPOLLRDHUP)
					x_printf(LOG_INFO, "EPOLLRDHUP detected on %s", source);

				epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);

				if (fd == rs->pipe_stdout[0])
					stdout_done = true;
				else if (fd == rs->pipe_stderr[0])
					stderr_done = true;
				else if (fd == rs->master_fd) {
					stdout_done = true;
					stderr_done = true;
				} else
					return exit_steps_client_error;
				continue;
			}
		}
	}
	return exit_steps_success;
}

/*
 * Executes a command locally, optionally with a PTY.
 * arglist: Null-terminated array of command arguments.
 * got_cb: Callback to handle output data.
 * private: Pointer passed to got_cb.
 * uid: User ID to run the command as.
 * no_pty: If non-zero, use pipes/socketpairs instead of PTY.
 * client_fd: Client socket for communication.
 * cwd: Working directory to set for the command.
 * ws: Window size to set for PTY.
 * term: Terminal settings to apply to PTY.
 * Returns the command's exit status or -1 on error.
 */
int do_local_cmd(char **arglist, CSDO_GOT_CB got_cb, void *private, uid_t uid, int no_pty, int client_fd, const char *cwd, struct winsize ws, struct termios term)
{
	int status;
	relay_session_t rs;

	/* 验证 arglist 和 got_cb */
	if (!arglist || !arglist[0] || !got_cb) {
		x_printf(LOG_ERR, "do_local_cmd: invalid arglist=%p or got_cb=%p", arglist, got_cb);
		return -1;
	}

	init_relay_session(&rs);
	rs.client_fd = client_fd;
	rs.no_pty = no_pty;
	rs.ws = ws;
	rs.term = term;

	if (!no_pty) {
		if (create_pty_bridge(&rs) == -1) {
			cleanup_relay_session(&rs);
			return -1;
		}
	} else {
		if (create_norm_bridge(&rs) == -1) {
			cleanup_relay_session(&rs);
			return -1;
		}
	}

	// 创建子进程
	pid_t pid = fork();

	switch (pid) {
		case -1:
			x_printf(LOG_CRIT, "Fork failed: %s", strerror(errno));
			cleanup_relay_session(&rs);
			return -1;
		case 0:
			/* Child. */
			child_process(&rs);

			x_printf(LOG_DEBUG, "do_local_cmd: child cmd=%s", arglist[0]);
			if (getpwuid(uid) == NULL) {
				x_printf(LOG_ERR, "do_local_cmd: invalid uid %u for command '%s'", uid, arglist[0]);
				fprintf(stderr, "Invalid user with UID %u for command '%s'\n", uid, arglist[0]);
				exit(EXIT_FAILURE);
			}
			if (setuid(uid) < 0) {
				x_printf(LOG_ERR, "do_local_cmd: setuid %u for command '%s': %s", uid, arglist[0], strerror(errno));
				fprintf(stderr, "Failed to switch to user with UID %u for command '%s'\n", uid, arglist[0]);
				exit(EXIT_FAILURE);
			}

			/* 设置工作目录 */
			if (cwd && *cwd) {
				if (chdir(cwd) < 0) {
					x_printf(LOG_ERR, "do_local_cmd: chdir to '%s' failed: %s", cwd, strerror(errno));
					fprintf(stderr, "Failed to change to directory '%s': %s\n", cwd, strerror(errno));
					exit(EXIT_FAILURE);
				}
				x_printf(LOG_DEBUG, "do_local_cmd: changed to cwd='%s'", cwd);
			}

			/* 设置 TERM 环境变量 */
			char *term = getenv("TERM");
			if (term) {
				setenv("TERM", term, 1);
				x_printf(LOG_DEBUG, "do_local_cmd: set TERM=%s", term);
			} else {
				setenv("TERM", "xterm-256color", 1); /* 使用更现代的终端类型 */
				x_printf(LOG_DEBUG, "do_local_cmd: set default TERM=xterm-256color");
			}

			/* 设置 COLUMNS 和 LINES */
			char cols[16], rows[16];
			snprintf(cols, sizeof(cols), "%d", rs.ws.ws_col);
			snprintf(rows, sizeof(rows), "%d", rs.ws.ws_row);
			setenv("COLUMNS", cols, 1);
			setenv("LINES", rows, 1);
			x_printf(LOG_DEBUG, "do_local_cmd: set COLUMNS=%s, LINES=%s", cols, rows);

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
			int exit_code = errno;
			fprintf(stderr, "execvp %s: %s\n", arglist[0], strerror(exit_code));
			x_printf(LOG_ERR, "execvp %s: %s", arglist[0], strerror(exit_code));
			close(STDIN_FILENO);
			close(STDOUT_FILENO);
			close(STDERR_FILENO);
			_exit(exit_code);
		default:
			/* Parent. Close the other side, and return the local side. */
			if (!rs.no_pty) {
				close(rs.slave_fd);
				x_printf(LOG_INFO, "Parent: Closed slave_fd=%d", rs.slave_fd);
				rs.slave_fd = -1;
			} else {
				close(rs.pipe_stdin[0]);
				x_printf(LOG_INFO, "Parent: Closed pipe_stdin[0]=%d", rs.pipe_stdin[0]);
				rs.pipe_stdin[0] = -1;
				close(rs.pipe_stdout[1]);
				x_printf(LOG_INFO, "Parent: Closed pipe_stdout[1]=%d", rs.pipe_stdout[1]);
				rs.pipe_stdout[1] = -1;
				close(rs.pipe_stderr[1]);
				x_printf(LOG_INFO, "Parent: Closed pipe_stderr[1]=%d", rs.pipe_stderr[1]);
				rs.pipe_stderr[1] = -1;
			}

			// 设置文件描述符为非阻塞
			if (set_nonblocking(rs.client_fd, "client_fd") == -1) {
				cleanup_relay_session(&rs);
				return -1;
			}
			if (!rs.no_pty) {
				if (set_nonblocking(rs.master_fd, "master_fd") == -1) {
					cleanup_relay_session(&rs);
					return -1;
				}
			} else {
				if (set_nonblocking(rs.pipe_stdout[0], "pipe_stdout[0]") == -1 ||
						set_nonblocking(rs.pipe_stderr[0], "pipe_stderr[0]") == -1) {
					cleanup_relay_session(&rs);
					return -1;
				}
			}

			// 创建 epoll 实例
			rs.epoll_fd = epoll_create1(0);
			if (rs.epoll_fd == -1) {
				x_printf(LOG_ERR, "epoll_create1 failed: %s", strerror(errno));
				cleanup_relay_session(&rs);
				return -1;
			}
			x_printf(LOG_INFO, "Parent: Created epoll instance, epoll_fd=%d", rs.epoll_fd);

			// 注册文件描述符到 epoll
			if (register_epoll(rs.epoll_fd, rs.client_fd, "client_fd") == -1) {
				cleanup_relay_session(&rs);
				return -1;
			}
			if (!rs.no_pty) {
				if (register_epoll(rs.epoll_fd, rs.master_fd, "master_fd") == -1) {
					cleanup_relay_session(&rs);
					return -1;
				}
			} else {
				if (register_epoll(rs.epoll_fd, rs.pipe_stdout[0], "pipe_stdout[0]") == -1 ||
						register_epoll(rs.epoll_fd, rs.pipe_stderr[0], "pipe_stderr[0]") == -1) {
					cleanup_relay_session(&rs);
					return -1;
				}
			}

			x_printf(LOG_DEBUG, "do_local_cmd: parent cmd=%s", arglist[0]);
			// 处理 epoll 事件
			int exit_steps = handle_epoll_events(rs.epoll_fd, &rs, got_cb, private);

			// 清理资源
			cleanup_relay_session(&rs);

			switch (exit_steps) {
				case exit_steps_server_error:
					return -1;
				case exit_steps_client_error:
					x_printf(LOG_INFO, "do_local_cmd: terminating child pid %d due to client disconnect", pid);
					kill(pid, SIGTERM);
					struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
					nanosleep(&ts, NULL);
					/* 检查子进程状态 */
					int ret = waitpid(pid, &status, WNOHANG);
					if (ret == pid) {
						/* 子进程状态已变化 */
					} else if (ret == 0) {
						/* 子进程尚未退出 */
						x_printf(LOG_WARNING, "do_local_cmd: child pid %d did not terminate, sending SIGKILL", pid);
						kill(pid, SIGKILL);
						while (waitpid(pid, &status, 0) == -1) {
							if (errno != EINTR) {
								x_printf(LOG_CRIT, "do_local_cmd: waitpid: %s", strerror(errno));
								return -1;
							}
						}
					} else {
						/* waitpid 出错 */
						if (errno == ECHILD) {
							x_printf(LOG_ERR, "do_local_cmd: waitpid: No child process (pid %d), possibly already reaped", pid);
						} else {
							x_printf(LOG_ERR, "do_local_cmd: waitpid error for pid %d: %s", pid, strerror(errno));
						}
						return -1;
					}
					break;
				case exit_steps_child_error:
				default:
					while (waitpid(pid, &status, 0) == -1) {
						if (errno != EINTR) {
							x_printf(LOG_CRIT, "do_local_cmd: waitpid: %s", strerror(errno));
							return -1;
						}
					}
					break;
			}

			/* 检查子进程状态 */
			if (WIFEXITED(status)) {
				/* 子进程正常退出 */
				int code = WEXITSTATUS(status);
				if (code == 0) {
					x_printf(LOG_DEBUG, "do_local_cmd: child pid %d exited normally", pid);
				} else {
					x_printf(LOG_ERR, "do_local_cmd: child pid %d exited with non-zero status %d", pid, code);
				}
				return code;
			} else if (WIFSIGNALED(status)) {
				/* 子进程被信号终止 */
				x_printf(LOG_WARNING, "Child killed by signal %d", WTERMSIG(status));
				return EXIT_FAILURE;
			} else if (WIFSTOPPED(status)) {
				x_printf(LOG_WARNING, "Child stopped by signal %d", WSTOPSIG(status));
				return EXIT_FAILURE;
			} else {
				/* 子进程异常退出 */
				x_printf(LOG_ERR, "do_local_cmd: child pid %d exited abnormally (unknown status)", pid);
				return EXIT_FAILURE;
			}
	}
}

/*
 * Sets up a Unix domain socket listener.
 * sock_path: Path to the socket file.
 * Returns the socket descriptor or -1 on error.
 */
static int setup_listener(const char *sock_path)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int rv, sd;
	int lock_fd = -1;
	char lock_path[PATH_MAX];

	/* Create lock file path based on socket path */
	snprintf(lock_path, sizeof(lock_path), "%s.lock", sock_path);

	/* Try to acquire lock */
	lock_fd = open(lock_path, O_CREAT | O_WRONLY, 0600);
	if (lock_fd < 0) {
		x_printf(LOG_ERR, "open lock file %s: error %d: %s", lock_path, errno, strerror(errno));
		return -1;
	}

	if (flock(lock_fd, LOCK_EX | LOCK_NB) < 0) {
		if (errno == EWOULDBLOCK) {
			x_printf(LOG_ERR, "Another instance is already running (lock file %s)", lock_path);
		} else {
			x_printf(LOG_ERR, "flock %s: error %d: %s", lock_path, errno, strerror(errno));
		}
		close(lock_fd);
		return -1;
	}

	/* we listen for new client connections on socket sd */
	sd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (sd < 0) {
		x_printf(LOG_ERR, "socket: error %d: %s", sd, strerror(errno));
		close(lock_fd);
		return sd;
	}

	unlink(sock_path); /* Remove stale socket file */
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
	addrlen = sizeof(addr);

	rv = bind(sd, (struct sockaddr *)&addr, addrlen);
	if (rv < 0) {
		x_printf(LOG_ERR, "bind: error %d: %s", rv, strerror(errno));
		close(sd);
		close(lock_fd);
		return rv;
	}

	rv = listen(sd, 5);
	if (rv < 0) {
		x_printf(LOG_ERR, "listen: error %d: %s", rv, strerror(errno));
		close(sd);
		close(lock_fd);
		return rv;
	}

	/* Set socket file permissions for group access */
	rv = chmod(sock_path, 0660);
	if (rv < 0) {
		x_printf(LOG_ERR, "chmod: error %d: %s", rv, strerror(errno));
		close(sd);
		close(lock_fd);
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
		x_printf(LOG_ERR, "chown: no suitable group found (tried sudo, wheel)");
		close(sd);
		close(lock_fd);
		return -1;
	}

	x_printf(LOG_INFO, "Using group '%s' (gid %d) for socket permissions", group_name, grp->gr_gid);
	rv = chown(sock_path, 0, grp->gr_gid);
	if (rv < 0) {
		x_printf(LOG_ERR, "chown: error %d: %s", rv, strerror(errno));
		close(sd);
		close(lock_fd);
		return rv;
	}

	/* Keep lock_fd open to maintain lock */
	return sd;
}

/*
 * Callback to handle command output and send it to the client.
 * private: Pointer to the client socket descriptor.
 * data: Output data to send.
 * size: Size of the data.
 * std_fileno: File descriptor (STDOUT_FILENO or STDERR_FILENO).
 */
static void csdo_got_cb(void *private, void *data, uint64_t size, int std_fileno)
{
	int *fd_ptr = (int *)private;
	if (!fd_ptr) {
		x_printf(LOG_ERR, "csdo_got_cb: null private pointer");
		return;
	}
	int fd = *fd_ptr;
	if (fd < 0) {
		x_printf(LOG_ERR, "csdo_got_cb: invalid fd %d", fd);
		return;
	}

	struct csdo_respond_header rph = {};
	csdo_query_init_header(&rph.bh);
	rph.length = size;
	rph.std_fileno = std_fileno;
	int rv = do_write(fd, &rph, sizeof(rph));
	if (rv < 0) {
		x_printf(LOG_ERR, "csdo_got_cb: write header failed: %s", strerror(errno));
		return;
	}
	rv = do_write(fd, data, size);
	if (rv < 0) {
		x_printf(LOG_ERR, "csdo_got_cb: write data failed: %s", strerror(errno));
	}
}

/*
 * Processes a command request by decoding and executing it.
 * fd: Client socket descriptor.
 * cmd: Encoded command data.
 * len: Length of the command data.
 * uid: User ID to run the command as.
 * no_pty: If non-zero, run without a PTY.
 * ws: Window size to set for PTY.
 * term: Terminal settings to apply to PTY.
 */
static void do_query_work(int fd, char *cmd, uint64_t len, uid_t uid, int no_pty, struct winsize ws, struct termios term)
{
	struct cmd_arg_list list = {};

	if (len > 0 && !cmd) {
		x_printf(LOG_ERR, "do_query_work: null cmd with non-zero len=%lu", len);
		return;
	}

	if (cmd_decode(&list, cmd, len) < 0) {
		x_printf(LOG_ERR, "do_query_work: cmd_decode failed");
		return;
	}

	for (int i = 0; i < list.argc; i++) {
		x_printf(LOG_DEBUG, "arg %d: %s", i, list.argv[i] ? list.argv[i] : "(null)");
	}
	if (list.cwd) {
		x_printf(LOG_DEBUG, "do_query_work: cwd='%s'", list.cwd);
	}

	int result = do_local_cmd(list.argv, csdo_got_cb, (void *)&fd, uid, no_pty, fd, list.cwd, ws, term);

	struct csdo_respond_header rph = {};
	csdo_query_init_header(&rph.bh);
	rph.length = 0;
	rph.result = result;
	do_write(fd, &rph, sizeof(rph));
	/* Note: list.argv and list.cwd point to cmd buffer, freed by caller */
}

/*
 * Handles a client connection in a separate thread.
 * arg: Client socket descriptor cast to void*.
 */
static void *csdo_query_handle(void *arg)
{
	int fd = (int)(uintptr_t)arg;
	struct csdo_request_header rqh;
	char *extra = NULL;

	if (fd < 0) {
		x_printf(LOG_ERR, "csdo_query_handle: invalid fd %d", fd);
		pthread_exit(0);
	}

	int rv = do_read(fd, &rqh, sizeof(rqh));
	if (rv < 0) {
		goto out;
	}

	if (rqh.bh.magic != CSDO_QUERY_MAGIC) {
		x_printf(LOG_ERR, "Invalid magic number: %u", rqh.bh.magic);
		goto out;
	}

	if ((rqh.bh.version & 0xFFFF0000) != (CSDO_QUERY_VERSION & 0xFFFF0000)) {
		x_printf(LOG_ERR, "Invalid version: %u", rqh.bh.version);
		goto out;
	}

	if (rqh.type == CSDO_MSG_WINSIZE) {
		/* 不应在连接初始化时收到窗口大小更新 */
		x_printf(LOG_ERR, "csdo_query_handle: unexpected winsize message at connection start");
		goto out;
	}

	if (rqh.type != CSDO_MSG_COMMAND) {
		x_printf(LOG_ERR, "csdo_query_handle: invalid request type %d", rqh.type);
		goto out;
	}

	if (rqh.length > 0) {
		extra = malloc(rqh.length);
		if (!extra) {
			x_printf(LOG_ERR, "csdo_query_handle: no memory for %lu bytes", rqh.length);
			goto out;
		}
		memset(extra, 0, rqh.length);

		rv = do_read(fd, extra, rqh.length);
		if (rv < 0) {
			x_printf(LOG_DEBUG, "connection %d: extra read error %d", fd, rv);
			goto out;
		}
	}

	do_query_work(fd, extra, rqh.length, rqh.uid, rqh.no_pty, rqh.ws, rqh.term);

out:
	if (extra) {
		free(extra);
	}
	close(fd);
	pthread_exit(0);
}

/*
 * Main server loop to accept and process client connections.
 * Runs as a daemon, creating threads for each client.
 * Returns NULL on error.
 */
static void *csdo_query_process(void)
{
	int sd, fd, rv;
	pthread_t thread;

	/* Check if running as root */
	if (geteuid() != 0) {
		x_printf(LOG_CRIT, "csdod must run as root");
		return NULL;
	}

	/* 忽略 SIGPIPE 信号以防止客户端断开时进程终止 */
	if (ssh_signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		x_printf(LOG_CRIT, "Failed to ignore SIGPIPE: %s", strerror(errno));
		return NULL;
	}

	sd = setup_listener(CSDO_SOCKET_PATH);
	if (sd < 0)
		return NULL;

	for (;;) {
		fd = accept(sd, NULL, NULL);
		if (fd < 0) {
			if (errno == EINTR) {
				continue; /* 忽略中断 */
			}
			x_printf(LOG_ERR, "accept: %s", strerror(errno));
			continue;
		}

		rv = pthread_create(&thread, NULL, csdo_query_handle, (void *)(uintptr_t)fd);
		if (rv < 0) {
			x_printf(LOG_CRIT, "pthread_create failed: %s", strerror(errno));
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
	x_set_log_level(LOG_INFO);
	daemon(0, 0);
	csdo_query_process();
	return 0;
}
