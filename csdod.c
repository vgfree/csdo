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
	exit_steps_success = 0,    /* Successful operation completion */
	exit_steps_server_error,    /* Server-side error */
	exit_steps_client_error,    /* Client-side error */
	exit_steps_child_error,     /* Child process error */
};

/* Resource structure for managing file descriptors */
typedef struct relay_session {
	int client_fd;        /* Client socket file descriptor */
	int master_fd;        /* PTY master file descriptor */
	int slave_fd;         /* PTY slave file descriptor */
	int pipe_stdin[2];    /* Standard input pipe */
	int pipe_stdout[2];   /* Standard output pipe */
	int pipe_stderr[2];   /* Standard error pipe */
	int epoll_fd;         /* Epoll instance file descriptor */
	int no_pty;           /* Flag to indicate if PTY is disabled */
	struct winsize ws;    /* Terminal window size */
	struct termios term;  /* Terminal settings */
} relay_session_t;

/* Initializes the relay session structure with default values */
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

/* Cleans up resources by closing all open file descriptors */
void cleanup_relay_session(relay_session_t *rs) {
	if (rs->master_fd != -1) {
		close(rs->master_fd);
		x_printf(LOG_INFO, "Closed PTY master file descriptor: master_fd=%d", rs->master_fd);
	}
	if (rs->slave_fd != -1) {
		close(rs->slave_fd);
		x_printf(LOG_INFO, "Closed PTY slave file descriptor: slave_fd=%d", rs->slave_fd);
	}
	if (rs->pipe_stdin[0] != -1) {
		close(rs->pipe_stdin[0]);
		x_printf(LOG_INFO, "Closed stdin pipe read end: pipe_stdin[0]=%d", rs->pipe_stdin[0]);
	}
	if (rs->pipe_stdin[1] != -1) {
		close(rs->pipe_stdin[1]);
		x_printf(LOG_INFO, "Closed stdin pipe write end: pipe_stdin[1]=%d", rs->pipe_stdin[1]);
	}
	if (rs->pipe_stdout[0] != -1) {
		close(rs->pipe_stdout[0]);
		x_printf(LOG_INFO, "Closed stdout pipe read end: pipe_stdout[0]=%d", rs->pipe_stdout[0]);
	}
	if (rs->pipe_stdout[1] != -1) {
		close(rs->pipe_stdout[1]);
		x_printf(LOG_INFO, "Closed stdout pipe write end: pipe_stdout[1]=%d", rs->pipe_stdout[1]);
	}
	if (rs->pipe_stderr[0] != -1) {
		close(rs->pipe_stderr[0]);
		x_printf(LOG_INFO, "Closed stderr pipe read end: pipe_stderr[0]=%d", rs->pipe_stderr[0]);
	}
	if (rs->pipe_stderr[1] != -1) {
		close(rs->pipe_stderr[1]);
		x_printf(LOG_INFO, "Closed stderr pipe write end: pipe_stderr[1]=%d", rs->pipe_stderr[1]);
	}
	if (rs->epoll_fd != -1) {
		close(rs->epoll_fd);
		x_printf(LOG_INFO, "Closed epoll instance: epoll_fd=%d", rs->epoll_fd);
	}
}

/* Creates pipes or socketpairs for non-PTY communication */
int create_norm_bridge(relay_session_t *rs)
{
#ifdef USE_PIPES
	if (pipe(rs->pipe_stdin) == -1) {
		x_printf(LOG_ERR, "Failed to create stdin pipe: %s", strerror(errno));
		return -1;
	}
	fcntl(rs->pipe_stdin[1], F_SETFD, FD_CLOEXEC); /* Set stdin write end to close on exec for proper EOF handling */
	x_printf(LOG_INFO, "Created stdin pipe: read_fd=%d, write_fd=%d", rs->pipe_stdin[0], rs->pipe_stdin[1]);

	if (pipe(rs->pipe_stdout) == -1) {
		x_printf(LOG_ERR, "Failed to create stdout pipe: %s", strerror(errno));
		return -1;
	}
	fcntl(rs->pipe_stdout[1], F_SETFD, FD_CLOEXEC); /* Set stdout write end to close on exec for proper EOF handling */
	x_printf(LOG_INFO, "Created stdout pipe: read_fd=%d, write_fd=%d", rs->pipe_stdout[0], rs->pipe_stdout[1]);

	if (pipe(rs->pipe_stderr) == -1) {
		x_printf(LOG_ERR, "Failed to create stderr pipe: %s", strerror(errno));
		return -1;
	}
	fcntl(rs->pipe_stderr[1], F_SETFD, FD_CLOEXEC); /* Set stderr write end to close on exec for proper EOF handling */
	x_printf(LOG_INFO, "Created stderr pipe: read_fd=%d, write_fd=%d", rs->pipe_stderr[0], rs->pipe_stderr[1]);
#else
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, rs->pipe_stdin) == -1) {
		x_printf(LOG_ERR, "Failed to create stdin socketpair: %s", strerror(errno));
		return -1;
	}
	fcntl(rs->pipe_stdin[1], F_SETFD, FD_CLOEXEC); /* Set stdin write end to close on exec for proper EOF handling */
	x_printf(LOG_INFO, "Created stdin socketpair: read_fd=%d, write_fd=%d", rs->pipe_stdin[0], rs->pipe_stdin[1]);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, rs->pipe_stdout) == -1) {
		x_printf(LOG_ERR, "Failed to create stdout socketpair: %s", strerror(errno));
		return -1;
	}
	fcntl(rs->pipe_stdout[1], F_SETFD, FD_CLOEXEC); /* Set stdout write end to close on exec for proper EOF handling */
	x_printf(LOG_INFO, "Created stdout socketpair: read_fd=%d, write_fd=%d", rs->pipe_stdout[0], rs->pipe_stdout[1]);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, rs->pipe_stderr) == -1) {
		x_printf(LOG_ERR, "Failed to create stderr socketpair: %s", strerror(errno));
		return -1;
	}
	fcntl(rs->pipe_stderr[1], F_SETFD, FD_CLOEXEC); /* Set stderr write end to close on exec for proper EOF handling */
	x_printf(LOG_INFO, "Created stderr socketpair: read_fd=%d, write_fd=%d", rs->pipe_stderr[0], rs->pipe_stderr[1]);
#endif
	return 0;
}

/* Creates a PTY and applies terminal settings */
int create_pty_bridge(relay_session_t *rs)
{
	char slave_name[128];

	/* Use client-provided window size or default */
	struct winsize default_ws = { .ws_row = 24, .ws_col = 80 };
	if (rs->ws.ws_row == 0 || rs->ws.ws_col == 0) {
		rs->ws = default_ws;
		x_printf(LOG_WARNING, "No window size provided, using default: rows=%d, cols=%d", rs->ws.ws_row, rs->ws.ws_col);
	} else {
		x_printf(LOG_DEBUG, "Using provided window size: rows=%d, cols=%d", rs->ws.ws_row, rs->ws.ws_col);
	}

	/* Create PTY and apply terminal settings */
	if (openpty(&rs->master_fd, &rs->slave_fd, slave_name, &rs->term, &rs->ws) == -1) {
		x_printf(LOG_ERR, "Failed to create PTY: %s", strerror(errno));
		return -1;
	}
	fcntl(rs->master_fd, F_SETFD, FD_CLOEXEC); /* Set master to close on exec for proper EOF handling */
	fcntl(rs->slave_fd, F_SETFD, FD_CLOEXEC); /* Set slave to close on exec for proper EOF handling */
	x_printf(LOG_INFO, "Created PTY: name=%s, master_fd=%d, slave_fd=%d", slave_name, rs->master_fd, rs->slave_fd);
	return 0;
}

/* Registers a file descriptor with epoll instance */
int register_epoll(int epfd, int fd, const char *name) {
	struct epoll_event ev = { .events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP, .data.fd = fd };
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
		x_printf(LOG_ERR, "Failed to register %s (fd=%d) with epoll: %s", name, fd, strerror(errno));
		return -1;
	}
	x_printf(LOG_INFO, "Successfully registered %s (fd=%d) with epoll", name, fd);
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

	/* Mask all other signals while in handler */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handler;
	sigfillset(&sa.sa_mask);
#if defined(SA_RESTART) && !defined(NO_SA_RESTART)
	if (signum != SIGALRM)
		sa.sa_flags = SA_RESTART;
#endif
	if (sigaction(signum, &sa, &osa) == -1) {
		x_printf(LOG_WARNING, "Failed to set signal handler for %s: %s", strsignal(signum), strerror(errno));
		return SIG_ERR;
	}
	return osa.sa_handler;
}

typedef void (*CSDO_GOT_CB)(void *private, void *data, uint64_t size, int std_fileno);

/* Configures the child process environment and file descriptors */
void child_process(relay_session_t *rs)
{
	/* Ignore SIGHUP and SIGPIPE signals in child process */
	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	x_printf(LOG_INFO, "Child process: Ignored SIGHUP and SIGPIPE signals");

	/* Close file descriptors not needed by child */
	close(rs->client_fd);
	x_printf(LOG_INFO, "Child process: Closed client socket: client_fd=%d", rs->client_fd);
	if (!rs->no_pty) {
		close(rs->master_fd);
		x_printf(LOG_INFO, "Child process: Closed PTY master: master_fd=%d", rs->master_fd);
	} else {
		close(rs->pipe_stdin[1]);
		x_printf(LOG_INFO, "Child process: Closed stdin pipe write end: pipe_stdin[1]=%d", rs->pipe_stdin[1]);
		close(rs->pipe_stdout[0]);
		x_printf(LOG_INFO, "Child process: Closed stdout pipe read end: pipe_stdout[0]=%d", rs->pipe_stdout[0]);
		close(rs->pipe_stderr[0]);
		x_printf(LOG_INFO, "Child process: Closed stderr pipe read end: pipe_stderr[0]=%d", rs->pipe_stderr[0]);
	}

	if (!rs->no_pty) {
		/* Set slave_fd as controlling terminal */
		if (login_tty(rs->slave_fd) == -1) {
			x_printf(LOG_ERR, "Child process: Failed to set controlling terminal on slave_fd=%d: %s", rs->slave_fd, strerror(errno));
			exit(EXIT_FAILURE);
		}
		x_printf(LOG_INFO, "Child process: Successfully set controlling terminal on slave_fd=%d", rs->slave_fd);
		close(rs->slave_fd);
		x_printf(LOG_INFO, "Child process: Closed PTY slave: slave_fd=%d", rs->slave_fd);
	} else {
		/* Redirect standard input */
		if (dup2(rs->pipe_stdin[0], STDIN_FILENO) == -1) {
			x_printf(LOG_ERR, "Child process: Failed to redirect stdin: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}
		close(rs->pipe_stdin[0]);
		x_printf(LOG_INFO, "Child process: Closed stdin pipe read end: pipe_stdin[0]=%d", rs->pipe_stdin[0]);

		/* Redirect standard output */
		if (dup2(rs->pipe_stdout[1], STDOUT_FILENO) == -1) {
			x_printf(LOG_ERR, "Child process: Failed to redirect stdout: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}
		close(rs->pipe_stdout[1]);
		x_printf(LOG_INFO, "Child process: Closed stdout pipe write end: pipe_stdout[1]=%d", rs->pipe_stdout[1]);

		/* Redirect standard error */
		if (dup2(rs->pipe_stderr[1], STDERR_FILENO) == -1) {
			x_printf(LOG_ERR, "Child process: Failed to redirect stderr: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}
		close(rs->pipe_stderr[1]);
		x_printf(LOG_INFO, "Child process: Closed stderr pipe write end: pipe_stderr[1]=%d", rs->pipe_stderr[1]);
	}
}

/* Processes client events and handles input data */
int do_client_event(relay_session_t *rs)
{
	char data[PAGE_SIZE] = {};
	int fd = rs->client_fd;
	struct csdo_request_header rqh = {};
	int rv = do_read(fd, &rqh, sizeof(rqh));
	if (rv < 0) {
		x_printf(LOG_INFO, "Client disconnected: %s", strerror(errno));
		return exit_steps_client_error; /* Client disconnected, initiate cleanup */
	}
	if (rqh.bh.magic != CSDO_QUERY_MAGIC) {
		x_printf(LOG_ERR, "Received invalid request magic number: %u", rqh.bh.magic);
		return exit_steps_client_error;
	}
	if (rqh.type == CSDO_MSG_WINSIZE) {
		/* Handle window size update */
		if (!rs->no_pty) {
			if (ioctl(rs->master_fd, TIOCSWINSZ, &rqh.ws) == -1) {
				x_printf(LOG_ERR, "Failed to update PTY window size: %s", strerror(errno));
			} else {
				rs->ws = rqh.ws; /* Update window size in relay_session_t */
				x_printf(LOG_DEBUG, "Updated PTY window size: rows=%d, cols=%d", rqh.ws.ws_row, rqh.ws.ws_col);
			}
		}
		return exit_steps_success;
	}
	if (rqh.type != CSDO_MSG_OPERATE) {
		x_printf(LOG_ERR, "Received invalid request type: %d", rqh.type);
		return exit_steps_client_error;
	}
	if (rqh.std_fileno != STDIN_FILENO) {
		x_printf(LOG_ERR, "Received invalid std_fileno: %d", rqh.std_fileno);
		return exit_steps_client_error;
	}
	if (rqh.length == 0) {
		x_printf(LOG_INFO, "Client signaled input completion");
		if (!rs->no_pty) {
			/* Close controlling terminal to trigger EOF */
			close(rs->master_fd);
			x_printf(LOG_INFO, "Parent: Closed PTY master to trigger EOF: master_fd=%d", rs->master_fd);
			rs->master_fd = -1;
		} else {
			/* Close stdin pipe write end to trigger EOF */
			close(rs->pipe_stdin[1]);
			x_printf(LOG_INFO, "Parent: Closed stdin pipe write end to trigger EOF: pipe_stdin[1]=%d", rs->pipe_stdin[1]);
			rs->pipe_stdin[1] = -1;
		}
		return exit_steps_success;
	}
	uint64_t len = rqh.length;
	while (len) {
		int todo = MIN(len, PAGE_SIZE);
		rv = do_read(fd, data, todo);
		if (rv < 0) {
			x_printf(LOG_INFO, "Failed to read client data: %s", strerror(errno));
			return exit_steps_client_error;
		}
		if (!rs->no_pty) {
			rv = do_write(rs->master_fd, data, todo);
		} else {
			rv = do_write(rs->pipe_stdin[1], data, todo);
		}
		if (rv < 0) {
			x_printf(LOG_ERR, "Failed to write to child process: %s", strerror(errno));
			return exit_steps_child_error;
		}
		len -= todo;
	}
	return exit_steps_success;
}

/* Handles epoll events for client and child process communication */
int handle_epoll_events(int epfd, relay_session_t *rs, CSDO_GOT_CB got_cb, void *private)
{
	int max = 3;
	struct epoll_event events[max];
	bool stdout_done = false, stderr_done = false;

	while (!(stdout_done && stderr_done)) {
		x_printf(LOG_DEBUG, "Waiting for epoll events: stdout_done=%d, stderr_done=%d", stdout_done, stderr_done);
		int num = epoll_wait(epfd, events, max, -1);
		x_printf(LOG_INFO, "epoll_wait returned %d events", num);

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
							x_printf(LOG_DEBUG, "Received data from %s: %zd bytes", source, bytes);
						} else if (bytes == 0) {
							/* Write end closed, no more data */
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
							/* Non-blocking mode, no data available */
							break;
						} else {
							x_printf(LOG_ERR, "Read error on %s: %s", source, strerror(errno));
							epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);

							/* Handle PTY EOF returning EIO */
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

	/* Validate arglist and got_cb */
	if (!arglist || !arglist[0] || !got_cb) {
		x_printf(LOG_ERR, "Invalid arguments: arglist=%p, got_cb=%p", arglist, got_cb);
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

	/* Create child process */
	pid_t pid = fork();

	switch (pid) {
		case -1:
			x_printf(LOG_CRIT, "Fork failed: %s", strerror(errno));
			cleanup_relay_session(&rs);
			return -1;
		case 0:
			/* Child process */
			child_process(&rs);

			x_printf(LOG_DEBUG, "Child process: Executing command: %s", arglist[0]);
			if (getpwuid(uid) == NULL) {
				x_printf(LOG_ERR, "Invalid user ID %u for command '%s'", uid, arglist[0]);
				fprintf(stderr, "Invalid user with UID %u for command '%s'\n", uid, arglist[0]);
				exit(EXIT_FAILURE);
			}
			if (setuid(uid) < 0) {
				x_printf(LOG_ERR, "Failed to set UID %u for command '%s': %s", uid, arglist[0], strerror(errno));
				fprintf(stderr, "Failed to switch to user with UID %u for command '%s'\n", uid, arglist[0]);
				exit(EXIT_FAILURE);
			}

			/* Set working directory */
			if (cwd && *cwd) {
				if (chdir(cwd) < 0) {
					x_printf(LOG_ERR, "Failed to change to directory '%s': %s", cwd, strerror(errno));
					fprintf(stderr, "Failed to change to directory '%s': %s\n", cwd, strerror(errno));
					exit(EXIT_FAILURE);
				}
				x_printf(LOG_DEBUG, "Changed to working directory: cwd='%s'", cwd);
			}

			/* Set TERM environment variable */
			char *term = getenv("TERM");
			if (term) {
				setenv("TERM", term, 1);
				x_printf(LOG_DEBUG, "Set environment variable TERM=%s", term);
			} else {
				setenv("TERM", "xterm-256color", 1); /* Use modern terminal type */
				x_printf(LOG_DEBUG, "Set default environment variable TERM=xterm-256color");
			}

			/* Set COLUMNS and LINES environment variables */
			char cols[16], rows[16];
			snprintf(cols, sizeof(cols), "%d", rs.ws.ws_col);
			snprintf(rows, sizeof(rows), "%d", rs.ws.ws_row);
			setenv("COLUMNS", cols, 1);
			setenv("LINES", rows, 1);
			x_printf(LOG_DEBUG, "Set environment variables: COLUMNS=%s, LINES=%s", cols, rows);

			/*
			 * Ignore SIGINT to prevent ssh process termination, but allow SIGTERM
			 * for graceful command abortion by sftp.
			 */
			ssh_signal(SIGINT, SIG_IGN);
			ssh_signal(SIGTERM, SIG_DFL);
			execvp(arglist[0], arglist);
			int exit_code = errno;
			fprintf(stderr, "execvp %s: %s\n", arglist[0], strerror(exit_code));
			x_printf(LOG_ERR, "Failed to execute command %s: %s", arglist[0], strerror(exit_code));
			close(STDIN_FILENO);
			close(STDOUT_FILENO);
			close(STDERR_FILENO);
			_exit(exit_code);
		default:
			/* Parent process: Close unused file descriptors */
			if (!rs.no_pty) {
				close(rs.slave_fd);
				x_printf(LOG_INFO, "Parent: Closed PTY slave: slave_fd=%d", rs.slave_fd);
				rs.slave_fd = -1;
			} else {
				close(rs.pipe_stdin[0]);
				x_printf(LOG_INFO, "Parent: Closed stdin pipe read end: pipe_stdin[0]=%d", rs.pipe_stdin[0]);
				rs.pipe_stdin[0] = -1;
				close(rs.pipe_stdout[1]);
				x_printf(LOG_INFO, "Parent: Closed stdout pipe write end: pipe_stdout[1]=%d", rs.pipe_stdout[1]);
				rs.pipe_stdout[1] = -1;
				close(rs.pipe_stderr[1]);
				x_printf(LOG_INFO, "Parent: Closed stderr pipe write end: pipe_stderr[1]=%d", rs.pipe_stderr[1]);
				rs.pipe_stderr[1] = -1;
			}

			/* Set file descriptors to non-blocking mode */
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

			/* Create epoll instance */
			rs.epoll_fd = epoll_create1(0);
			if (rs.epoll_fd == -1) {
				x_printf(LOG_ERR, "Failed to create epoll instance: %s", strerror(errno));
				cleanup_relay_session(&rs);
				return -1;
			}
			x_printf(LOG_INFO, "Parent: Created epoll instance: epoll_fd=%d", rs.epoll_fd);

			/* Register file descriptors with epoll */
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

			x_printf(LOG_DEBUG, "Parent: Processing command: %s", arglist[0]);
			/* Handle epoll events */
			int exit_steps = handle_epoll_events(rs.epoll_fd, &rs, got_cb, private);

			/* Clean up resources */
			cleanup_relay_session(&rs);

			switch (exit_steps) {
				case exit_steps_server_error:
					return -1;
				case exit_steps_client_error:
					x_printf(LOG_INFO, "Terminating child process pid %d due to client disconnect", pid);
					kill(pid, SIGTERM);
					struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
					nanosleep(&ts, NULL);
					/* Check child process status */
					int ret = waitpid(pid, &status, WNOHANG);
					if (ret == pid) {
						/* Child process status changed */
					} else if (ret == 0) {
						/* Child process has not terminated */
						x_printf(LOG_WARNING, "Child process pid %d did not terminate, sending SIGKILL", pid);
						kill(pid, SIGKILL);
						while (waitpid(pid, &status, 0) == -1) {
							if (errno != EINTR) {
								x_printf(LOG_CRIT, "waitpid failed: %s", strerror(errno));
								return -1;
							}
						}
					} else {
						/* waitpid error */
						if (errno == ECHILD) {
							x_printf(LOG_ERR, "waitpid: No child process (pid %d), possibly already reaped", pid);
						} else {
							x_printf(LOG_ERR, "waitpid error for pid %d: %s", pid, strerror(errno));
						}
						return -1;
					}
					break;
				case exit_steps_child_error:
				default:
					while (waitpid(pid, &status, 0) == -1) {
						if (errno != EINTR) {
							x_printf(LOG_CRIT, "waitpid failed: %s", strerror(errno));
							return -1;
						}
					}
					break;
			}

			/* Check child process status */
			if (WIFEXITED(status)) {
				/* Child process exited normally */
				int code = WEXITSTATUS(status);
				if (code == 0) {
					x_printf(LOG_DEBUG, "Child process pid %d exited normally", pid);
				} else {
					x_printf(LOG_ERR, "Child process pid %d exited with non-zero status %d", pid, code);
				}
				return code;
			} else if (WIFSIGNALED(status)) {
				/* Child process terminated by signal */
				x_printf(LOG_WARNING, "Child process killed by signal %d", WTERMSIG(status));
				return EXIT_FAILURE;
			} else if (WIFSTOPPED(status)) {
				x_printf(LOG_WARNING, "Child process stopped by signal %d", WSTOPSIG(status));
				return EXIT_FAILURE;
			} else {
				/* Child process exited abnormally */
				x_printf(LOG_ERR, "Child process pid %d exited abnormally (unknown status)", pid);
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
		x_printf(LOG_ERR, "Failed to open lock file %s: %s", lock_path, strerror(errno));
		return -1;
	}

	if (flock(lock_fd, LOCK_EX | LOCK_NB) < 0) {
		if (errno == EWOULDBLOCK) {
			x_printf(LOG_ERR, "Another instance is already running (lock file %s)", lock_path);
		} else {
			x_printf(LOG_ERR, "Failed to lock file %s: %s", lock_path, strerror(errno));
		}
		close(lock_fd);
		return -1;
	}

	/* Create Unix domain socket */
	sd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (sd < 0) {
		x_printf(LOG_ERR, "Failed to create socket: %s", strerror(errno));
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
		x_printf(LOG_ERR, "Failed to bind socket: %s", strerror(errno));
		close(sd);
		close(lock_fd);
		return rv;
	}

	rv = listen(sd, 5);
	if (rv < 0) {
		x_printf(LOG_ERR, "Failed to listen on socket: %s", strerror(errno));
		close(sd);
		close(lock_fd);
		return rv;
	}

	/* Set socket file permissions for group access */
	rv = chmod(sock_path, 0660);
	if (rv < 0) {
		x_printf(LOG_ERR, "Failed to set socket permissions: %s", strerror(errno));
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
		x_printf(LOG_ERR, "No suitable group found for socket permissions (tried sudo, wheel)");
		close(sd);
		close(lock_fd);
		return -1;
	}

	x_printf(LOG_INFO, "Using group '%s' (gid %d) for socket permissions", group_name, grp->gr_gid);
	rv = chown(sock_path, 0, grp->gr_gid);
	if (rv < 0) {
		x_printf(LOG_ERR, "Failed to set socket ownership: %s", strerror(errno));
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
		x_printf(LOG_ERR, "Callback: Null private pointer");
		return;
	}
	int fd = *fd_ptr;
	if (fd < 0) {
		x_printf(LOG_ERR, "Callback: Invalid file descriptor: fd=%d", fd);
		return;
	}

	struct csdo_respond_header rph = {};
	csdo_query_init_header(&rph.bh);
	rph.length = size;
	rph.std_fileno = std_fileno;
	int rv = do_write(fd, &rph, sizeof(rph));
	if (rv < 0) {
		x_printf(LOG_ERR, "Callback: Failed to write response header: %s", strerror(errno));
		return;
	}
	rv = do_write(fd, data, size);
	if (rv < 0) {
		x_printf(LOG_ERR, "Callback: Failed to write response data: %s", strerror(errno));
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
		x_printf(LOG_ERR, "Invalid command: null cmd with non-zero length=%lu", len);
		return;
	}

	if (cmd_decode(&list, cmd, len) < 0) {
		x_printf(LOG_ERR, "Failed to decode command");
		return;
	}

	for (int i = 0; i < list.argc; i++) {
		x_printf(LOG_DEBUG, "Command argument %d: %s", i, list.argv[i] ? list.argv[i] : "(null)");
	}
	if (list.cwd) {
		x_printf(LOG_DEBUG, "Command working directory: cwd='%s'", list.cwd);
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
		x_printf(LOG_ERR, "Invalid client socket: fd=%d", fd);
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
		/* Unexpected window size message at connection start */
		x_printf(LOG_ERR, "Unexpected window size message at connection start");
		goto out;
	}

	if (rqh.type != CSDO_MSG_COMMAND) {
		x_printf(LOG_ERR, "Invalid request type: %d", rqh.type);
		goto out;
	}

	if (rqh.length > 0) {
		extra = malloc(rqh.length);
		if (!extra) {
			x_printf(LOG_ERR, "Failed to allocate memory for command: length=%lu", rqh.length);
			goto out;
		}
		memset(extra, 0, rqh.length);

		rv = do_read(fd, extra, rqh.length);
		if (rv < 0) {
			x_printf(LOG_DEBUG, "Failed to read extra data for connection %d: %s", fd, strerror(errno));
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

	/* Ignore SIGPIPE to prevent process termination on client disconnect */
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
				continue; /* Ignore interrupt */
			}
			x_printf(LOG_ERR, "Failed to accept connection: %s", strerror(errno));
			continue;
		}

		rv = pthread_create(&thread, NULL, csdo_query_handle, (void *)(uintptr_t)fd);
		if (rv < 0) {
			x_printf(LOG_CRIT, "Failed to create thread: %s", strerror(errno));
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
