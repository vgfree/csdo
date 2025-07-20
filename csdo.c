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
#include <syslog.h>
#include <pwd.h>
#include <grp.h>
#include <poll.h>
#include <termios.h>
#include <signal.h>
#include <sys/ioctl.h>

#include "utils.h"

/* Global variables for signal handling */
static struct termios orig_termios;
static int global_fd = -1;
static int no_pty_flag = 0;

/*
 * SIGWINCH handler for window size changes.
 */
static volatile sig_atomic_t winch_received = 0;
static void handle_sigwinch(int sig)
{
	winch_received = 1;
}

/*
 * Sets a file descriptor to non-blocking mode.
 * Exits on failure to ensure consistent state.
 */
static void set_non_blocking(int fd)
{
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

/*
 * Connects to the Unix domain socket at sock_path.
 * Returns the socket descriptor or -1 on error.
 */
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

/*
 * Sets the terminal to raw mode and returns the original termios settings.
 * Returns 0 on success, -1 on error.
 */
static int setup_termios(int fd, struct termios *orig_termios)
{
	struct termios term;

	if (!isatty(fd)) {
		syslog(LOG_ERR, "setup_termios: fd is not a terminal");
		return -1;
	}
	if (tcgetattr(fd, orig_termios) == -1) {
		syslog(LOG_ERR, "setup_termios: tcgetattr: %s", strerror(errno));
		return -1;
	}

	term = *orig_termios;
	// 自定义“半原始”模式：避免输出错位
	term.c_lflag &= ~(ECHO | ICANON | IEXTEN); // Keep ISIG enabled to allow Ctrl+C
	term.c_iflag &= ~(IXON | ICRNL | BRKINT | INPCK | ISTRIP);
	term.c_oflag |= OPOST;                             // 保留输出处理（如 \n 自动转 \r\n）
	term.c_iflag |= ICRNL;                             // 保留输入处理（如 \n 自动转 \r\n）
	term.c_cflag |= CS8;

	term.c_cc[VMIN] = 1; // 最小读取字节数
	term.c_cc[VTIME] = 0; // 无超时

	if (tcsetattr(fd, TCSANOW, &term) == -1) {
		syslog(LOG_ERR, "setup_termios: tcsetattr: %s", strerror(errno));
		return -1;
	}
	return 0;
}

/*
 * Restores the original terminal settings.
 * fd: File descriptor of the terminal.
 * orig_termios: Original terminal settings to restore.
 * Returns 0 on success, -errno on error.
 */
static int restore_termios(int fd, struct termios *orig_termios)
{
	if (!isatty(fd)) {
		syslog(LOG_ERR, "restore_termios: fd is not a terminal");
		return -1;
	}
	if (tcsetattr(fd, TCSANOW, orig_termios) == -1) {
		syslog(LOG_ERR, "restore_termios: tcsetattr: %s", strerror(errno));
		return -1;
	}
	return 0;
}

/*
 * Signal handler for SIGINT (Ctrl+C)
 */
static void handle_sigint(int sig)
{
	if (!no_pty_flag && global_fd != -1) {
		restore_termios(STDIN_FILENO, &orig_termios);
	}
	if (global_fd != -1) {
		close(global_fd);
	}
	closelog();
	exit(EXIT_FAILURE);
}

/*
 * Sends a command request to the server and processes the response.
 * cmd: Encoded command data.
 * len: Length of the command data.
 * uid: User ID to run the command as.
 * no_pty: If non-zero, run without a PTY.
 * Returns 0 on success, negative error code on failure.
 */
int csdo_query_request(void *cmd, size_t len, uid_t uid, int no_pty)
{
	struct csdo_request_header rqh = {};
	struct csdo_respond_header rph = {};
	int fd, rv;
	char data[PAGE_SIZE];
	struct pollfd pfds[2];
	struct winsize ws;

	/* 获取客户端终端窗口大小 */
	if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == -1) {
		syslog(LOG_ERR, "csdo_query_request: ioctl TIOCGWINSZ: %s", strerror(errno));
		ws.ws_row = 24;
		ws.ws_col = 80;
	} else {
		syslog(LOG_DEBUG, "csdo_query_request: window size rows=%d, cols=%d", ws.ws_row, ws.ws_col);
	}

	no_pty_flag = no_pty; // Set global flag for signal handler

	fd = do_connect(CSDO_SOCKET_PATH);
	if (fd < 0) {
		rv = fd;
		if (rv == -EPERM)
			fprintf(stderr, "Permission denied: cannot connect to /var/run/csdod.sock\n");
		goto out;
	}
	global_fd = fd; // Store fd for signal handler
	set_non_blocking(fd);
	if (!no_pty) {
		// 设置原始模式以处理交互式输入
		if (setup_termios(STDIN_FILENO, &orig_termios) == -1) {
			goto out_close;
		}
	}

	/* 注册 SIGWINCH 信号处理程序 */
	struct sigaction sa;
	sa.sa_handler = handle_sigwinch;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGWINCH, &sa, NULL) == -1) {
		syslog(LOG_ERR, "csdo_query_request: sigaction SIGWINCH: %s", strerror(errno));
	}

	/* 发送命令请求 */
	csdo_query_init_header(&rqh.bh);
	rqh.length = len;
	rqh.uid = uid;
	rqh.no_pty = no_pty;
	rqh.type = CSDO_MSG_COMMAND;
	rqh.std_fileno = STDIN_FILENO;
	rqh.ws = ws; /* 将窗口大小添加到请求头 */

	rv = do_write(fd, &rqh, sizeof(rqh));
	if (rv < 0)
		goto out_close;

	if (len) {
		rv = do_write(fd, cmd, len);
		if (rv < 0)
			goto out_close;
	}

	if (no_pty) {
		/* Non-interactive mode: only read server output */
		do {
			rv = do_read(fd, &rph, sizeof(rph));
			if (rv < 0)
				goto out_close;
			if (rph.bh.magic != CSDO_QUERY_MAGIC) {
				syslog(LOG_ERR, "csdo_query_request: invalid response magic: %u", rph.bh.magic);
				rv = -EINVAL;
				goto out_close;
			}
			if (rph.length == 0) {
				rv = rph.result;
				break;
			}
			if (rph.std_fileno != STDOUT_FILENO && rph.std_fileno != STDERR_FILENO) {
				syslog(LOG_ERR, "csdo_query_request: invalid std_fileno %d", rph.std_fileno);
				rv = -EINVAL;
				goto out_close;
			}
			uint64_t len = rph.length;
			while (len) {
				int todo = MIN(len, PAGE_SIZE);
				rv = do_read(fd, data, todo);
				if (rv < 0)
					goto out_close;
				if (rph.std_fileno == STDOUT_FILENO || rph.std_fileno == STDERR_FILENO) {
					rv = do_write(rph.std_fileno, data, todo);
					if (rv < 0) {
						syslog(LOG_ERR, "csdo_query_request: write output: %s", strerror(errno));
						goto out_close;
					}
					fflush(rph.std_fileno == STDOUT_FILENO ? stdout : stderr);
				}
				len -= todo;
			}
		} while (1);
	} else {
		/* Interactive mode: handle stdin and server output */
		pfds[0].fd = STDIN_FILENO;
		pfds[0].events = POLLIN;
		pfds[1].fd = fd;
		pfds[1].events = POLLIN;

		while (1) {
			/* 检查窗口大小变化并发送更新 */
			if (winch_received) {
				if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) != -1) {
					csdo_query_init_header(&rqh.bh);
					rqh.length = 0;
					rqh.uid = uid;
					rqh.no_pty = no_pty;
					rqh.type = CSDO_MSG_WINSIZE;
					rqh.std_fileno = STDIN_FILENO;
					rqh.ws = ws;

					rv = do_write(fd, &rqh, sizeof(rqh));
					if (rv < 0) {
						syslog(LOG_ERR, "csdo_query_request: write winsize: %s", strerror(errno));
						goto out_restore;
					}
					syslog(LOG_DEBUG, "csdo_query_request: sent window size rows=%d, cols=%d", ws.ws_row, ws.ws_col);
				}
				winch_received = 0; /* 重置信号标志 */
			}

			rv = poll(pfds, 2, -1);
			if (rv < 0) {
				if (errno == EINTR || errno == EAGAIN)
					continue;
				fprintf(stderr, "csdo_query_request: poll: %s\n", strerror(errno));
				syslog(LOG_ERR, "csdo_query_request: poll: %s", strerror(errno));
				rv = -errno;
				goto out_restore;
			}
			if (rv == 0)
				continue;

			if (pfds[0].revents & (POLLIN | POLLHUP)) {
				char buf[PAGE_SIZE];
				ssize_t bytes = read(STDIN_FILENO, buf, sizeof(buf));
				if (bytes <= 0) {
					if (bytes == 0 || errno == EAGAIN)
						continue;
					syslog(LOG_ERR, "csdo_query_request: read stdin: %s", strerror(errno));
					rv = -errno;
					goto out_restore;
				}

				csdo_query_init_header(&rqh.bh);
				rqh.length = bytes;
				rqh.uid = uid;
				rqh.no_pty = no_pty;
				rqh.type = CSDO_MSG_OPERATE;
				rqh.std_fileno = STDIN_FILENO;
				rqh.ws = ws;

				rv = do_write(fd, &rqh, sizeof(rqh));
				if (rv < 0)
					goto out_restore;
				rv = do_write(fd, buf, bytes);
				if (rv < 0)
					goto out_restore;
			}

			if (pfds[1].revents & (POLLIN | POLLHUP | POLLRDHUP)) {
				rv = do_read(fd, &rph, sizeof(rph));
				if (rv < 0)
					goto out_restore;
				if (rph.bh.magic != CSDO_QUERY_MAGIC) {
					syslog(LOG_ERR, "csdo_query_request: invalid response magic: %u", rph.bh.magic);
					rv = -EINVAL;
					goto out_restore;
				}
				if (rph.length == 0) {
					rv = rph.result;
					break;
				}
				if (rph.std_fileno != STDOUT_FILENO && rph.std_fileno != STDERR_FILENO) {
					syslog(LOG_ERR, "csdo_query_request: invalid std_fileno %d", rph.std_fileno);
					rv = -EINVAL;
					goto out_restore;
				}
				uint64_t len = rph.length;
				while (len) {
					int todo = MIN(len, PAGE_SIZE);
					rv = do_read(fd, data, todo);
					if (rv < 0)
						goto out_restore;
					if (rph.std_fileno == STDOUT_FILENO || rph.std_fileno == STDERR_FILENO) {
						rv = do_write(rph.std_fileno, data, todo);
						if (rv < 0) {
							syslog(LOG_ERR, "csdo_query_request: write output: %s", strerror(errno));
							goto out_restore;
						}
						/* 立即刷新输出以保持 ANSI 序列的时序 */
						fflush(rph.std_fileno == STDOUT_FILENO ? stdout : stderr);
					}
					len -= todo;
				}
			}
		}
	}

	/* 恢复终端设置 */
out_restore:
	if (!no_pty) {
		restore_termios(STDIN_FILENO, &orig_termios);
	}
out_close:
	close(fd);
	global_fd = -1; /* Reset global fd */
out:
	return rv;
}

/*
 * Checks if the current user is in the sudo or wheel group.
 * Returns 0 if the user is in either group, -1 on error, or -EPERM if not in either group.
 */
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

/*
 * Main function to parse arguments and send a command request to the server.
 * argc, argv: Command-line arguments.
 * Returns 0 on success, negative error code on failure.
 */
int main(int argc, char **argv)
{
	openlog("csdo", LOG_PID | LOG_CONS, LOG_DAEMON);

	/* Set up SIGINT handler */
	struct sigaction sa;
	sa.sa_handler = handle_sigint;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		syslog(LOG_ERR, "main: sigaction SIGINT: %s", strerror(errno));
		closelog();
		return -errno;
	}

	if (argc < 2) {
		fprintf(stderr, "Usage: %s [-u username] [-n] <cmd> <...>\n", argv[0]);
		closelog();
		return -EINVAL;
	}

	if (getuid() && is_user_in_sudo_or_wheel_group()) {
		closelog();
		return -EPERM;
	}

	struct cmd_arg_list list = {};
	list.argc = 0;
	list.cwd = NULL;
	uid_t target_uid = 0; /* Default to root */
	int no_pty = 0;
	int optind = 1;

	while (optind < argc) {
		if (strcmp(argv[optind], "-u") == 0) {
			if (optind + 1 >= argc) {
				fprintf(stderr, "Option -u requires an argument\n");
				closelog();
				return -EINVAL;
			}
			struct passwd *pw = getpwnam(argv[optind + 1]);
			if (!pw) {
				fprintf(stderr, "Invalid user: %s\n", argv[optind + 1]);
				syslog(LOG_ERR, "main: invalid user '%s'", argv[optind + 1]);
				closelog();
				return -EINVAL;
			}
			target_uid = pw->pw_uid;
			optind += 2;
		} else if (strcmp(argv[optind], "-n") == 0) {
			no_pty = 1;
			optind++;
		} else if (strcmp(argv[optind], "--help") == 0) {
			printf("Usage: %s [options] <cmd> <...>\n", argv[0]);
			printf("Options:\n");
			printf("  -u <username>  Specify the user to run the command as (default: root)\n");
			printf("  -n             Do not use a pseudo-terminal (PTY)\n");
			printf("  --help         Display this help message and exit\n");
			printf("\nDescription:\n");
			printf("  csdo is a command-line tool to execute commands with specified user privileges.\n");
			printf("  It requires root privileges or membership in the sudo or wheel group.\n");
			closelog();
			exit(0);
		} else {
			break;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Usage: %s [-u username] [-n] <cmd> <...>\n", argv[0]);
		closelog();
		return -EINVAL;
	}

	list.argc = argc - optind;
	memcpy(list.argv, argv + optind, sizeof(char *) * list.argc);

	/* 获取当前工作目录 */
	char cwd_buf[CSDO_CWD_MAX] = {};
	if (getcwd(cwd_buf, sizeof(cwd_buf)) == NULL) {
		syslog(LOG_ERR, "main: getcwd failed: %s", strerror(errno));
		closelog();
		return -errno;
	}
	list.cwd = cwd_buf;
	syslog(LOG_DEBUG, "main: cwd='%s'", list.cwd);

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
	if (cmd_encode(&list, data, &size) || size == 0) {
		syslog(LOG_ERR, "main: cmd_encode failed for command '%s'", argv[optind]);
		free(data);
		closelog();
		return -EINVAL;
	}
	syslog(LOG_DEBUG, "main: encoded command '%s', size=%u", argv[optind], size);

	int res = csdo_query_request(data, size, target_uid, no_pty);
	free(data);
	closelog();
	return res;
}
