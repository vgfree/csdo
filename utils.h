/*
 * Copyright(c) 2024-2025 vgfree omstor
 */
#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <poll.h>
#include "x_printf.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define ARG_MAX          4096
#define CSDO_CWD_MAX     4096  /* Maximum length for working directory, aligned with PATH_MAX */
#define CSDO_SOCKET_PATH "/var/run/csdod.sock"

#define CSDO_QUERY_MAGIC 0x4353444F /* 'CSDO' ASCII representation */
#define CSDO_QUERY_VERSION 0x00010000 /* Version 1.0.0 */
#define CSDO_MSG_COMMAND 0 /* Command execution request */
#define CSDO_MSG_WINSIZE 1 /* Terminal window size update */
#define CSDO_MSG_OPERATE 2 /* Interactive operation message */

struct csdo_base_header {
	uint32_t magic;    /* Magic number for validation */
	uint32_t version;  /* Protocol version */
};

struct csdo_request_header {
	struct csdo_base_header bh; /* Base header with magic and version */
	uint64_t length;            /* Length of command data payload */
	uid_t uid;                  /* User ID for command execution */
	int no_pty;                 /* Flag to disable pseudo-terminal (PTY) */
	int type;                   /* Message type (COMMAND, WINSIZE, OPERATE) */
	int std_fileno;             /* File descriptor for input data */
	struct winsize ws;          /* Terminal window size configuration */
	struct termios term;        /* Terminal attributes */
};

struct csdo_respond_header {
	struct csdo_base_header bh; /* Base header with magic and version */
	uint64_t length;            /* Length of output data payload */
	int result;                 /* Command execution exit status */
	int std_fileno;             /* File descriptor for output data */
};

/*
 * Initializes a csdo_base_header with predefined magic and version values.
 * bh: Pointer to the header structure to initialize.
 */
static inline void csdo_query_init_header(struct csdo_base_header *bh)
{
	memset(bh, 0, sizeof(struct csdo_base_header));
	bh->magic = CSDO_QUERY_MAGIC;
	bh->version = CSDO_QUERY_VERSION;
}

struct cmd_arg_list {
	int argc;                /* Number of command arguments */
	char *argv[ARG_MAX];     /* Array of command argument strings */
	char *cwd;               /* Current working directory path */
};

/*
 * Encodes a command argument list and working directory into a buffer.
 * Format: [argc][arg_len1][arg_len2]...[arg_lenn][cwd_len][arg1][arg2]...[argn][cwd]
 * list: Pointer to the command argument list and working directory.
 * data: Output buffer for encoded data (NULL to calculate size only).
 * size: Pointer to store the total encoded data size.
 * Returns 0 on success, -1 on error.
 */
static inline int cmd_encode(struct cmd_arg_list *list, char *data, uint32_t *size)
{
	uint32_t done = 0;
	uint32_t *psize;
	char *pdata;
	int i;

	/* Validate input parameters */
	if (!list || list->argc < 1) {
		x_printf(LOG_ERR, "cmd_encode: Invalid argument list or argc=%d", list ? list->argc : -1);
		return -1;
	}
	if (list->argc > ARG_MAX) {
		x_printf(LOG_ERR, "cmd_encode: Argument count %d exceeds maximum %d", list->argc, ARG_MAX);
		return -1;
	}
	if (list->cwd && strlen(list->cwd) >= CSDO_CWD_MAX) {
		x_printf(LOG_ERR, "cmd_encode: Working directory length %zu exceeds maximum %d", strlen(list->cwd), CSDO_CWD_MAX);
		return -1;
	}

	/* Calculate required buffer size */
	uint32_t total_size = sizeof(uint32_t); /* argc */
	total_size += list->argc * sizeof(uint32_t); /* Lengths of arguments */
	total_size += sizeof(uint32_t); /* cwd length */
	for (i = 0; i < list->argc; i++) {
		total_size += strlen(list->argv[i]) + 1; /* Argument strings including null terminator */
	}
	total_size += list->cwd ? strlen(list->cwd) + 1 : 0; /* Working directory string */

	if (!data) {
		*size = total_size;
		x_printf(LOG_DEBUG, "cmd_encode: Calculated required buffer size: %u bytes", total_size);
		return 0;
	}

	/* Encode data into buffer */
	psize = (uint32_t *)data;
	*psize = list->argc;
	x_printf(LOG_DEBUG, "cmd_encode: Encoded argument count: %d", list->argc);
	psize++;
	done += sizeof(uint32_t);

	/* Encode argument lengths */
	for (i = 0; i < list->argc; i++) {
		uint32_t arg_len = strlen(list->argv[i]) + 1;
		*psize = arg_len;
		x_printf(LOG_DEBUG, "cmd_encode: Encoded argument %d length: %u bytes", i, arg_len);
		psize++;
		done += sizeof(uint32_t);
	}

	/* Encode working directory length */
	uint32_t cwd_len = list->cwd ? strlen(list->cwd) + 1 : 0;
	*psize = cwd_len;
	x_printf(LOG_DEBUG, "cmd_encode: Encoded working directory length: %u bytes", cwd_len);
	psize++;
	done += sizeof(uint32_t);

	/* Encode argument strings */
	pdata = (char *)psize;
	for (i = 0; i < list->argc; i++) {
		uint32_t arg_len = strlen(list->argv[i]) + 1;
		memcpy(pdata, list->argv[i], arg_len);
		x_printf(LOG_DEBUG, "cmd_encode: Encoded argument %d: '%s'", i, pdata);
		pdata += arg_len;
		done += arg_len;
	}

	/* Encode working directory string */
	if (cwd_len > 0) {
		memcpy(pdata, list->cwd, cwd_len);
		x_printf(LOG_DEBUG, "cmd_encode: Encoded working directory: '%s'", pdata);
		done += cwd_len;
	}

	*size = done;
	x_printf(LOG_DEBUG, "cmd_encode: Completed encoding, total size: %u bytes", done);
	return 0;
}

/*
 * Decodes a command argument list and working directory from a buffer.
 * Format: [argc][arg_len1][arg_len2]...[arg_lenn][cwd_len][arg1][arg2]...[argn][cwd]
 * list: Pointer to store the decoded argument list and working directory.
 * data: Input buffer containing encoded data.
 * size: Size of the input buffer.
 * Returns 0 on success, -1 on error.
 */
static inline int cmd_decode(struct cmd_arg_list *list, char *data, uint32_t size)
{
	uint32_t done = 0;
	uint32_t *psize;
	char *pdata;
	int i;

	/* Initialize output structure */
	memset(list->argv, 0, sizeof(list->argv));
	list->cwd = NULL;

	/* Validate input buffer */
	if (!data || size < sizeof(uint32_t)) {
		x_printf(LOG_ERR, "cmd_decode: Invalid buffer or insufficient size: %u bytes", size);
		return -1;
	}

	/* Decode argument count */
	psize = (uint32_t *)data;
	list->argc = *psize;
	if (list->argc < 1 || list->argc > ARG_MAX) {
		x_printf(LOG_ERR, "cmd_decode: Invalid argument count: %d", list->argc);
		return -1;
	}
	psize++;
	done += sizeof(uint32_t);
	x_printf(LOG_DEBUG, "cmd_decode: Decoded argument count: %d", list->argc);

	/* Validate buffer size for argument lengths and cwd length */
	if (size < done + list->argc * sizeof(uint32_t) + sizeof(uint32_t)) {
		x_printf(LOG_ERR, "cmd_decode: Buffer too small for argument lengths: %u bytes", size);
		return -1;
	}

	/* Decode argument lengths */
	uint32_t arg_len[ARG_MAX];
	for (i = 0; i < list->argc; i++) {
		arg_len[i] = *psize;
		if (arg_len[i] == 0 || arg_len[i] > size) {
			x_printf(LOG_ERR, "cmd_decode: Invalid length for argument %d: %u bytes", i, arg_len[i]);
			return -1;
		}
		psize++;
		done += sizeof(uint32_t);
		x_printf(LOG_DEBUG, "cmd_decode: Decoded argument %d length: %u bytes", i, arg_len[i]);
	}

	/* Decode working directory length */
	uint32_t cwd_len = *psize;
	if (cwd_len >= CSDO_CWD_MAX) {
		x_printf(LOG_ERR, "cmd_decode: Working directory length %u exceeds maximum %d", cwd_len, CSDO_CWD_MAX);
		return -1;
	}
	psize++;
	done += sizeof(uint32_t);
	x_printf(LOG_DEBUG, "cmd_decode: Decoded working directory length: %u bytes", cwd_len);

	/* Validate total buffer length */
	uint32_t total_len = done;
	for (i = 0; i < list->argc; i++) {
		total_len += arg_len[i];
	}
	total_len += cwd_len;
	if (total_len > size) {
		x_printf(LOG_ERR, "cmd_decode: Total decoded length %u exceeds buffer size %u", total_len, size);
		return -1;
	}

	/* Decode argument strings */
	pdata = (char *)psize;
	for (i = 0; i < list->argc; i++) {
		if (pdata[arg_len[i] - 1] != '\0') {
			x_printf(LOG_ERR, "cmd_decode: Argument %d is not null-terminated", i);
			return -1;
		}
		list->argv[i] = pdata;
		x_printf(LOG_DEBUG, "cmd_decode: Decoded argument %d: '%s'", i, list->argv[i]);
		pdata += arg_len[i];
		done += arg_len[i];
	}

	/* Decode working directory string */
	if (cwd_len > 0) {
		if (pdata[cwd_len - 1] != '\0') {
			x_printf(LOG_ERR, "cmd_decode: Working directory is not null-terminated");
			return -1;
		}
		list->cwd = pdata;
		x_printf(LOG_DEBUG, "cmd_decode: Decoded working directory: '%s'", list->cwd);
		done += cwd_len;
	}

	x_printf(LOG_DEBUG, "cmd_decode: Completed decoding, total size: %u bytes", done);
	return 0;
}

/*
 * Reads exactly count bytes from a file descriptor into a buffer.
 * Supports both blocking and non-blocking file descriptors.
 * fd: File descriptor to read from.
 * buf: Buffer to store read data.
 * count: Number of bytes to read.
 * Returns 0 on success, -1 on error or EOF.
 */
static inline int do_read(int fd, void *buf, size_t count)
{
	int rv;
	size_t off = 0;
	struct pollfd pfd;

	if (!buf) {
		x_printf(LOG_ERR, "do_read: Null buffer provided for fd %d", fd);
		return -1;
	}
	if (fd < 0) {
		x_printf(LOG_ERR, "do_read: Invalid file descriptor: %d", fd);
		return -1;
	}
	if (count == 0) {
		x_printf(LOG_DEBUG, "do_read: No bytes to read for fd %d", fd);
		return 0;
	}

	while (off < count) {
		rv = read(fd, (char *)buf + off, count - off);
		if (rv == 0) {
			x_printf(LOG_ERR, "do_read: End of file or connection closed on fd %d", fd);
			return -1;
		}
		if (rv == -1 && errno == EINTR) {
			x_printf(LOG_DEBUG, "do_read: Interrupted by signal on fd %d, retrying", fd);
			continue;
		}
		if (rv == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			pfd.fd = fd;
			pfd.events = POLLIN;
			rv = poll(&pfd, 1, -1);
			if (rv < 0) {
				if (errno == EINTR) {
					x_printf(LOG_DEBUG, "do_read: Poll interrupted on fd %d, retrying", fd);
					continue;
				}
				x_printf(LOG_ERR, "do_read: Poll failed on fd %d: %s", fd, strerror(errno));
				return -1;
			}
			if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
				x_printf(LOG_ERR, "do_read: Poll error on fd %d: %s%s%s",
						fd,
						(pfd.revents & POLLERR) ? "POLLERR " : "",
						(pfd.revents & POLLHUP) ? "POLLHUP " : "",
						(pfd.revents & POLLNVAL) ? "POLLNVAL " : "");
				return -1;
			}
			if (!(pfd.revents & POLLIN)) {
				x_printf(LOG_ERR, "do_read: Poll did not indicate POLLIN on fd %d", fd);
				return -1;
			}
			x_printf(LOG_DEBUG, "do_read: Poll indicates data available on fd %d", fd);
			continue;
		}
		if (rv < 0) {
			x_printf(LOG_ERR, "do_read: Read error on fd %d: %s", fd, strerror(errno));
			return -1;
		}
		off += rv;
		x_printf(LOG_DEBUG, "do_read: Read %d bytes from fd %d, total %zu/%zu", rv, fd, off, count);
	}
	x_printf(LOG_DEBUG, "do_read: Successfully read %zu bytes from fd %d", count, fd);
	return 0;
}

/*
 * Writes exactly count bytes from a buffer to a file descriptor.
 * Supports both blocking and non-blocking file descriptors.
 * fd: File descriptor to write to.
 * buf: Buffer containing data to write.
 * count: Number of bytes to write.
 * Returns 0 on success, -1 on error.
 */
static inline int do_write(int fd, void *buf, size_t count)
{
	int rv;
	size_t off = 0;
	struct pollfd pfd;

	if (!buf) {
		x_printf(LOG_ERR, "do_write: Null buffer provided for fd %d", fd);
		return -1;
	}
	if (fd < 0) {
		x_printf(LOG_ERR, "do_write: Invalid file descriptor: %d", fd);
		return -1;
	}
	if (count == 0) {
		x_printf(LOG_DEBUG, "do_write: No bytes to write for fd %d", fd);
		return 0;
	}

	while (off < count) {
		rv = write(fd, (char *)buf + off, count - off);
		if (rv == 0) {
			x_printf(LOG_ERR, "do_write: Write returned zero bytes on fd %d", fd);
			return -1;
		}
		if (rv == -1 && errno == EINTR) {
			x_printf(LOG_DEBUG, "do_write: Interrupted by signal on fd %d, retrying", fd);
			continue;
		}
		if (rv == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			pfd.fd = fd;
			pfd.events = POLLOUT;
			rv = poll(&pfd, 1, -1);
			if (rv < 0) {
				if (errno == EINTR) {
					x_printf(LOG_DEBUG, "do_write: Poll interrupted on fd %d, retrying", fd);
					continue;
				}
				x_printf(LOG_ERR, "do_write: Poll failed on fd %d: %s", fd, strerror(errno));
				return -1;
			}
			if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
				x_printf(LOG_ERR, "do_write: Poll error on fd %d: %s%s%s",
						fd,
						(pfd.revents & POLLERR) ? "POLLERR " : "",
						(pfd.revents & POLLHUP) ? "POLLHUP " : "",
						(pfd.revents & POLLNVAL) ? "POLLNVAL " : "");
				return -1;
			}
			if (!(pfd.revents & POLLOUT)) {
				x_printf(LOG_ERR, "do_write: Poll did not indicate POLLOUT on fd %d", fd);
				return -1;
			}
			x_printf(LOG_DEBUG, "do_write: Poll indicates write possible on fd %d", fd);
			continue;
		}
		if (rv < 0) {
			x_printf(LOG_ERR, "do_write: Write error on fd %d: %s", fd, strerror(errno));
			return -1;
		}
		off += rv;
		x_printf(LOG_DEBUG, "do_write: Wrote %d bytes to fd %d, total %zu/%zu", rv, fd, off, count);
	}
	x_printf(LOG_DEBUG, "do_write: Successfully wrote %zu bytes to fd %d", count, fd);
	return 0;
}

/*
 * Sets a file descriptor to non-blocking mode.
 * fd: File descriptor to modify.
 * name: Descriptive name for logging purposes.
 * Returns 0 on success, -1 on error.
 */
static inline int set_nonblocking(int fd, const char *name)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		x_printf(LOG_ERR, "set_nonblocking: Failed to retrieve flags for %s (fd=%d): %s", name, fd, strerror(errno));
		return -1;
	}
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) == -1) {
		x_printf(LOG_ERR, "set_nonblocking: Failed to set %s (fd=%d) to non-blocking: %s", name, fd, strerror(errno));
		return -1;
	}
	x_printf(LOG_DEBUG, "set_nonblocking: Successfully set %s (fd=%d) to non-blocking mode", name, fd);
	return 0;
}
#endif
