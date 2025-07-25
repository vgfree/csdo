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
#include <stdbool.h>

#include "utils.h"

/* Global variables for signal handling and terminal state */
static struct termios g_orig_termios;
static int g_sktfd = -1;
static int g_inpty = 0;

/*
 * Handles SIGWINCH signal for terminal window size changes.
 */
static volatile sig_atomic_t g_winch_received = 0;
static void handle_sigwinch(int sig)
{
	g_winch_received = 1;
}

/*
 * Establishes a connection to the Unix domain socket at the specified path.
 * sock_path: Path to the Unix domain socket.
 * Returns the socket descriptor or -1 on error.
 */
static int do_connect(const char *sock_path)
{
	struct sockaddr_un sun;
	socklen_t addrlen;
	int rv, fd;

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		x_printf(LOG_ERR, "Failed to create socket: %s", strerror(errno));
		return fd;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, sock_path, sizeof(sun.sun_path) - 1);
	addrlen = sizeof(sun);

	rv = connect(fd, (struct sockaddr *)&sun, addrlen);
	if (rv < 0) {
		if (errno != EPERM)
			x_printf(LOG_ERR, "Failed to connect to socket %s: %s", sock_path, strerror(errno));
		close(fd);
		return rv;
	}
	x_printf(LOG_DEBUG, "Successfully connected to socket: %s", sock_path);
	return fd;
}

/*
 * Configures the terminal to raw mode and saves the original termios settings.
 * fd: File descriptor of the terminal.
 * orig_termios: Pointer to store original terminal settings.
 * Returns 0 on success, -1 on error.
 */
static int setup_termios(int fd, struct termios *orig_termios)
{
	struct termios term;

	if (!isatty(fd)) {
		x_printf(LOG_DEBUG, "File descriptor %d is not a terminal", fd);
		return 0;
	}
	if (tcgetattr(fd, orig_termios) == -1) {
		x_printf(LOG_ERR, "Failed to get terminal attributes: %s", strerror(errno));
		return -1;
	}

	term = *orig_termios;
	/* Configure semi-raw mode to prevent output misalignment */
	term.c_lflag &= ~(ECHO | ICANON | IEXTEN); /* Keep ISIG enabled for Ctrl+C */
	term.c_iflag &= ~(IXON | ICRNL | BRKINT | INPCK | ISTRIP);
	term.c_oflag |= OPOST; /* Retain output processing (e.g., \n to \r\n) */
	term.c_iflag |= ICRNL; /* Retain input processing (e.g., \n to \r\n) */
	term.c_cflag |= CS8;

	term.c_cc[VMIN] = 1; /* Minimum bytes to read */
	term.c_cc[VTIME] = 0; /* No timeout */

	if (tcsetattr(fd, TCSANOW, &term) == -1) {
		x_printf(LOG_ERR, "Failed to set terminal attributes: %s", strerror(errno));
		return -1;
	}
	x_printf(LOG_DEBUG, "Terminal set to raw mode for fd=%d", fd);
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
		x_printf(LOG_DEBUG, "File descriptor %d is not a terminal", fd);
		return 0;
	}
	if (tcsetattr(fd, TCSANOW, orig_termios) == -1) {
		x_printf(LOG_ERR, "Failed to restore terminal attributes: %s", strerror(errno));
		return -1;
	}
	x_printf(LOG_DEBUG, "Restored original terminal settings for fd=%d", fd);
	return 0;
}

/*
 * Handles SIGINT signal (Ctrl+C) to clean up and exit.
 */
static void handle_sigint(int sig)
{
	if (g_inpty) {
		restore_termios(STDIN_FILENO, &g_orig_termios);
		x_printf(LOG_DEBUG, "SIGINT received, restored terminal settings");
	}
	if (g_sktfd != -1) {
		close(g_sktfd);
		x_printf(LOG_DEBUG, "SIGINT received, closed socket: fd=%d", g_sktfd);
	}
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
	int i, fd, rv;
	char data[PAGE_SIZE];
	struct pollfd pfds[2];
	struct winsize ws;

	ws.ws_row = 24;
	ws.ws_col = 80;
	if (!no_pty) {
		if (isatty(STDIN_FILENO)) {
			/* Retrieve client terminal window size */
			if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == -1) {
				x_printf(LOG_ERR, "Failed to get window size: %s", strerror(errno));
			} else {
				x_printf(LOG_DEBUG, "Retrieved window size: rows=%d, cols=%d", ws.ws_row, ws.ws_col);
			}
			/* Retrieve client terminal settings */
			if (tcgetattr(STDIN_FILENO, &rqh.term) == -1) {
				x_printf(LOG_ERR, "Failed to get terminal settings: %s", strerror(errno));
			}
		}
	}

	fd = do_connect(CSDO_SOCKET_PATH);
	if (fd < 0) {
		rv = fd;
		if (rv == -EPERM)
			fprintf(stderr, "Permission denied: cannot connect to /var/run/csdod.sock\n");
		return rv;
	}
	if (set_nonblocking(fd, "socket fd") == -1) {
		x_printf(LOG_ERR, "Failed to set socket to non-blocking mode: fd=%d", fd);
		close(fd);
		return -1;
	}
	g_sktfd = fd; /* Store fd for signal handler */
	if (!no_pty) {
		/* Set terminal to raw mode for interactive input */
		if (setup_termios(STDIN_FILENO, &g_orig_termios) == -1) {
			close(fd);
			return -1;
		}
		g_inpty = 1; /* Set global flag for signal handler */
	}

	/* Register SIGWINCH signal handler */
	struct sigaction sa;
	sa.sa_handler = handle_sigwinch;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGWINCH, &sa, NULL) == -1) {
		x_printf(LOG_ERR, "Failed to set SIGWINCH handler: %s", strerror(errno));
	}

	/* Send command request */
	csdo_query_init_header(&rqh.bh);
	rqh.length = len;
	rqh.uid = uid;
	rqh.no_pty = no_pty;
	rqh.type = CSDO_MSG_COMMAND;
	rqh.std_fileno = STDIN_FILENO;
	rqh.ws = ws; /* Include window size in request header */

	rv = do_write(fd, &rqh, sizeof(rqh));
	if (rv < 0) {
		x_printf(LOG_ERR, "Failed to write request header: %s", strerror(errno));
		goto out_restore;
	}
	x_printf(LOG_DEBUG, "Sent command request header: length=%zu, uid=%u, no_pty=%d", len, uid, no_pty);

	if (len) {
		rv = do_write(fd, cmd, len);
		if (rv < 0) {
			x_printf(LOG_ERR, "Failed to write command data: %s", strerror(errno));
			goto out_restore;
		}
		x_printf(LOG_DEBUG, "Sent command data: size=%zu", len);
	}

	bool input_finish = false;
	bool sktfd_finish = false;
	while (!sktfd_finish) {
		if (!no_pty) {
			/* Check for window size changes and send updates */
			if (g_winch_received) {
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
						x_printf(LOG_ERR, "Failed to send window size update: %s", strerror(errno));
						goto out_restore;
					}
					x_printf(LOG_DEBUG, "Sent window size update: rows=%d, cols=%d", ws.ws_row, ws.ws_col);
				}
				g_winch_received = 0; /* Reset signal flag */
			}
		}

		/* Monitor stdin and server socket for events */
		int idxs = 0;
		if (!input_finish) {
			pfds[idxs].fd = STDIN_FILENO;
			pfds[idxs].events = POLLIN;
			idxs++;
			x_printf(LOG_DEBUG, "Monitoring stdin for input");
		}
		if (!sktfd_finish) {
			pfds[idxs].fd = fd;
			pfds[idxs].events = POLLIN;
			idxs++;
			x_printf(LOG_DEBUG, "Monitoring socket for data");
		}
		rv = poll(pfds, idxs, -1);
		if (rv < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			fprintf(stderr, "Poll error: %s\n", strerror(errno));
			x_printf(LOG_ERR, "Poll failed: %s", strerror(errno));
			rv = -errno;
			goto out_restore;
		}
		x_printf(LOG_DEBUG, "Poll completed: %d events", rv);
		if (rv == 0) {
			continue;
		}

		for (i = 0; i < idxs; i++) {
			if (pfds[i].fd == STDIN_FILENO) {
				if (pfds[i].revents & (POLLIN | POLLHUP)) {
					ssize_t bytes = read(STDIN_FILENO, data, sizeof(data));
					if (bytes == 0) {
						input_finish = true;
						x_printf(LOG_DEBUG, "Stdin input completed");

						csdo_query_init_header(&rqh.bh);
						rqh.length = 0;
						rqh.uid = uid;
						rqh.no_pty = no_pty;
						rqh.type = CSDO_MSG_OPERATE;
						rqh.std_fileno = STDIN_FILENO;
						rqh.ws = ws;

						rv = do_write(fd, &rqh, sizeof(rqh));
						if (rv < 0) {
							x_printf(LOG_ERR, "Failed to send input completion: %s", strerror(errno));
							goto out_restore;
						}
						x_printf(LOG_DEBUG, "Sent input completion signal");
						continue;
					} else if (bytes < 0) {
						if (errno == EAGAIN)
							continue;
						rv = -errno;
						x_printf(LOG_ERR, "Failed to read from stdin: %s", strerror(errno));
						goto out_restore;
					} else {
						x_printf(LOG_DEBUG, "Read %zd bytes from stdin", bytes);
						csdo_query_init_header(&rqh.bh);
						rqh.length = bytes;
						rqh.uid = uid;
						rqh.no_pty = no_pty;
						rqh.type = CSDO_MSG_OPERATE;
						rqh.std_fileno = STDIN_FILENO;
						rqh.ws = ws;

						rv = do_write(fd, &rqh, sizeof(rqh));
						if (rv < 0) {
							x_printf(LOG_ERR, "Failed to write request header: %s", strerror(errno));
							goto out_restore;
						}
						rv = do_write(fd, data, bytes);
						if (rv < 0) {
							x_printf(LOG_ERR, "Failed to write stdin data: %s", strerror(errno));
							goto out_restore;
						}
						x_printf(LOG_DEBUG, "Wrote %zd bytes to socket", bytes);
					}
				}
			} else {
				if (pfds[i].revents & (POLLIN | POLLHUP | POLLRDHUP)) {
					rv = do_read(fd, &rph, sizeof(rph));
					if (rv < 0) {
						x_printf(LOG_ERR, "Failed to read response header: %s", strerror(errno));
						goto out_restore;
					}
					if (rph.bh.magic != CSDO_QUERY_MAGIC) {
						x_printf(LOG_ERR, "Invalid response magic number: %u", rph.bh.magic);
						rv = -EINVAL;
						goto out_restore;
					}
					if (rph.length == 0) {
						rv = rph.result;
						sktfd_finish = true;
						x_printf(LOG_DEBUG, "Socket communication completed");
						break;
					}
					if (rph.std_fileno != STDOUT_FILENO && rph.std_fileno != STDERR_FILENO) {
						x_printf(LOG_ERR, "Invalid std_fileno in response: %d", rph.std_fileno);
						rv = -EINVAL;
						goto out_restore;
					}
					uint64_t len = rph.length;
					while (len) {
						int todo = MIN(len, sizeof(data));
						rv = do_read(fd, data, todo);
						if (rv < 0) {
							x_printf(LOG_ERR, "Failed to read response data: %s", strerror(errno));
							goto out_restore;
						}
						x_printf(LOG_DEBUG, "Read %d bytes from socket", todo);
						if (rph.std_fileno == STDOUT_FILENO || rph.std_fileno == STDERR_FILENO) {
							rv = do_write(rph.std_fileno, data, todo);
							if (rv < 0) {
								x_printf(LOG_ERR, "Failed to write to output: %s", strerror(errno));
								goto out_restore;
							}
							x_printf(LOG_DEBUG, "Wrote %d bytes to %s", todo, rph.std_fileno == STDOUT_FILENO ? "stdout" : "stderr");
							/* Flush output immediately to preserve ANSI sequence timing */
							fflush(rph.std_fileno == STDOUT_FILENO ? stdout : stderr);
						}
						len -= todo;
					}
				}
			}
		}
	}

out_restore:
	if (!no_pty) {
		/* Restore terminal settings */
		restore_termios(STDIN_FILENO, &g_orig_termios);
		g_inpty = 0;
	}
	close(fd);
	x_printf(LOG_DEBUG, "Closed socket: fd=%d", fd);
	g_sktfd = -1; /* Reset global fd */
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
		x_printf(LOG_ERR, "Failed to get user info for uid %u: %s", uid, strerror(errno));
		return -1;
	}

	const char *groups[] = {"sudo", "wheel"};
	for (int i = 0; i < 2; i++) {
		struct group *grp = getgrnam(groups[i]);
		if (!grp) {
			x_printf(LOG_DEBUG, "Failed to get group info for '%s': %s", groups[i], strerror(errno));
			continue;
		}
		for (char **member = grp->gr_mem; *member; member++) {
			if (strcmp(*member, pw->pw_name) == 0) {
				x_printf(LOG_DEBUG, "User '%s' found in group '%s'", pw->pw_name, groups[i]);
				return 0;
			}
		}
	}
	x_printf(LOG_ERR, "User '%s' not in sudo or wheel group", pw->pw_name);
	fprintf(stderr, "Permission denied: user not in sudo or wheel group\n");
	return -EPERM;
}

/*
 * Main function to parse command-line arguments and send a command request to the server.
 * argc, argv: Command-line arguments.
 * Returns 0 on success, negative error code on failure.
 */
int main(int argc, char **argv)
{
	x_set_log_to_file(false);
	x_set_log_level(LOG_INFO);

	/* Set up SIGINT handler */
	struct sigaction sa;
	sa.sa_handler = handle_sigint;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		x_printf(LOG_ERR, "Failed to set SIGINT handler: %s", strerror(errno));
		return -errno;
	}

	if (argc < 2) {
		fprintf(stderr, "Usage: %s [-u username] [-n] <cmd> <...>\n", argv[0]);
		return -EINVAL;
	}

	if (getuid() && is_user_in_sudo_or_wheel_group()) {
		return -EPERM;
	}

	struct cmd_arg_list list = {};
	list.argc = 0;
	list.cwd = NULL;
	uid_t target_uid = 0; /* Default to root */
	int no_pty = !isatty(STDIN_FILENO);
	int optind = 1;

	while (optind < argc) {
		if (strcmp(argv[optind], "-u") == 0) {
			if (optind + 1 >= argc) {
				fprintf(stderr, "Option -u requires an argument\n");
				return -EINVAL;
			}
			struct passwd *pw = getpwnam(argv[optind + 1]);
			if (!pw) {
				fprintf(stderr, "Invalid user: %s\n", argv[optind + 1]);
				x_printf(LOG_ERR, "Invalid user: %s", argv[optind + 1]);
				return -EINVAL;
			}
			target_uid = pw->pw_uid;
			x_printf(LOG_DEBUG, "Set target user: %s (uid=%u)", argv[optind + 1], target_uid);
			optind += 2;
		} else if (strcmp(argv[optind], "-n") == 0) {
			no_pty = 1;
			x_printf(LOG_DEBUG, "Disabled PTY usage");
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
			exit(0);
		} else {
			break;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Usage: %s [-u username] [-n] <cmd> <...>\n", argv[0]);
		return -EINVAL;
	}

	list.argc = argc - optind;
	memcpy(list.argv, argv + optind, sizeof(char *) * list.argc);

	/* Retrieve current working directory */
	char cwd_buf[CSDO_CWD_MAX] = {};
	if (getcwd(cwd_buf, sizeof(cwd_buf)) == NULL) {
		x_printf(LOG_ERR, "Failed to get current working directory: %s", strerror(errno));
		return -errno;
	}
	list.cwd = cwd_buf;
	x_printf(LOG_DEBUG, "Current working directory: %s", list.cwd);

	uint32_t size = 0;
	if (cmd_encode(&list, NULL, &size)) {
		x_printf(LOG_ERR, "Failed to encode command '%s'", argv[optind]);
		return -EINVAL;
	}
	if (size == 0) {
		x_printf(LOG_ERR, "Command encoding returned zero size for '%s'", argv[optind]);
		return -EINVAL;
	}
	char *data = malloc(size);
	if (!data) {
		x_printf(LOG_ERR, "Failed to allocate memory for command encoding: size=%u", size);
		return -ENOMEM;
	}
	if (cmd_encode(&list, data, &size) || size == 0) {
		x_printf(LOG_ERR, "Failed to encode command '%s'", argv[optind]);
		free(data);
		return -EINVAL;
	}
	x_printf(LOG_DEBUG, "Encoded command '%s': size=%u", argv[optind], size);

	int res = csdo_query_request(data, size, target_uid, no_pty);
	free(data);
	x_printf(LOG_DEBUG, "Command execution completed with result: %d", res);
	return res;
}
