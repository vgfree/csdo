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
#define CSDO_CWD_MAX     4096  /* 最大工作目录长度，与 PATH_MAX 一致 */
#define CSDO_SOCKET_PATH "/var/run/csdod.sock"

#define CSDO_QUERY_MAGIC 0x4353444F /* 'CSDO' */
#define CSDO_QUERY_VERSION 0x00010000 /* 1.0.0 */
#define CSDO_MSG_COMMAND 0 /* 命令请求 */
#define CSDO_MSG_WINSIZE 1 /* 窗口大小更新 */
#define CSDO_MSG_OPERATE 2 /* 交互操作 */

struct csdo_base_header {
	uint32_t magic;
	uint32_t version;
};

struct csdo_request_header {
	struct csdo_base_header bh;
	uint64_t length; /* 命令数据长度 */
	uid_t uid; /* 执行命令的用户 ID */
	int no_pty; /* 是否禁用 PTY */
	int type; /* 消息类型：CSDO_MSG_COMMAND 或 CSDO_MSG_WINSIZE */
	int std_fileno; /* 输入数据对应的文件描述符（仅用于命令数据） */
	struct winsize ws; /* 终端窗口大小 */
};

struct csdo_respond_header {
	struct csdo_base_header bh;
	uint64_t length; /* 输出数据长度 */
	int result; /* 命令退出状态 */
	int std_fileno; /* 输出数据对应的文件描述符 */
};


/*
 * Initializes a csdo_base_header with magic and version.
 * bh: Pointer to the header to initialize.
 */
static inline void csdo_query_init_header(struct csdo_base_header *bh)
{
	memset(bh, 0, sizeof(struct csdo_base_header));

	bh->magic = CSDO_QUERY_MAGIC;
	bh->version = CSDO_QUERY_VERSION;
}

struct cmd_arg_list {
	int argc;
	char *argv[ARG_MAX];
	char *cwd; /* 当前工作目录 */
};

/*
 * Encodes a command argument list and working directory into a buffer.
 * Format: [argc][arg_len1][arg_len2]...[arg_lenn][cwd_len][arg1][arg2]...[argn][cwd]
 * list: Pointer to the command argument list and cwd.
 * data: Output buffer for encoded data (can be NULL to calculate size).
 * size: Pointer to store the total encoded size.
 * Returns 0 on success, -1 on error.
 */
static inline int cmd_encode(struct cmd_arg_list *list, char *data, uint32_t *size)
{
	uint32_t done = 0;
	uint32_t *psize;
	char *pdata;
	int i;

	/* 输入验证 */
	if (!list || list->argc < 1) {
		x_printf(LOG_ERR, "cmd_encode: invalid list or argc=%d", list ? list->argc : -1);
		return -1;
	}
	if (list->argc > ARG_MAX) {
		x_printf(LOG_ERR, "cmd_encode: argc %d exceeds ARG_MAX %d", list->argc, ARG_MAX);
		return -1;
	}
	if (list->cwd && strlen(list->cwd) >= CSDO_CWD_MAX) {
		x_printf(LOG_ERR, "cmd_encode: cwd too long (%zu >= %d)", strlen(list->cwd), CSDO_CWD_MAX);
		return -1;
	}

	/* 计算所需缓冲区大小 */
	uint32_t total_size = sizeof(uint32_t); /* argc */
	total_size += list->argc * sizeof(uint32_t); /* arg_len1...arg_lenn */
	total_size += sizeof(uint32_t); /* cwd_len */
	for (i = 0; i < list->argc; i++) {
		total_size += strlen(list->argv[i]) + 1; /* arg1...argn */
	}
	total_size += list->cwd ? strlen(list->cwd) + 1 : 0; /* cwd */

	if (!data) {
		*size = total_size;
		x_printf(LOG_DEBUG, "cmd_encode: calculated size=%u", total_size);
		return 0;
	}

	/* 编码数据 */
	psize = (uint32_t *)data;
	*psize = list->argc;
	x_printf(LOG_DEBUG, "cmd_encode: encoded argc=%d", list->argc);
	psize++;
	done += sizeof(uint32_t);

	/* 编码参数长度 */
	for (i = 0; i < list->argc; i++) {
		uint32_t arg_len = strlen(list->argv[i]) + 1;
		*psize = arg_len;
		x_printf(LOG_DEBUG, "cmd_encode: encoded argv[%d] length=%u", i, arg_len);
		psize++;
		done += sizeof(uint32_t);
	}

	/* 编码 cwd 长度 */
	uint32_t cwd_len = list->cwd ? strlen(list->cwd) + 1 : 0;
	*psize = cwd_len;
	x_printf(LOG_DEBUG, "cmd_encode: encoded cwd length=%u", cwd_len);
	psize++;
	done += sizeof(uint32_t);

	/* 编码参数字符串 */
	pdata = (char *)psize;
	for (i = 0; i < list->argc; i++) {
		uint32_t arg_len = strlen(list->argv[i]) + 1;
		memcpy(pdata, list->argv[i], arg_len);
		x_printf(LOG_DEBUG, "cmd_encode: encoded argv[%d]='%s'", i, pdata);
		pdata += arg_len;
		done += arg_len;
	}

	/* 编码 cwd 字符串 */
	if (cwd_len > 0) {
		memcpy(pdata, list->cwd, cwd_len);
		x_printf(LOG_DEBUG, "cmd_encode: encoded cwd='%s'", pdata);
		done += cwd_len;
	}

	*size = done;
	x_printf(LOG_DEBUG, "cmd_encode: total encoded size=%u", done);
	return 0;
}

/*
 * Decodes a command argument list and working directory from a buffer.
 * Format: [argc][arg_len1][arg_len2]...[arg_lenn][cwd_len][arg1][arg2]...[argn][cwd]
 * list: Pointer to the command argument list to fill.
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

	/* 初始化 list */
	memset(list->argv, 0, sizeof(list->argv));
	list->cwd = NULL;

	/* 输入验证 */
	if (!data || size < sizeof(uint32_t)) {
		x_printf(LOG_ERR, "cmd_decode: invalid buffer or size (%u < %zu)", size, sizeof(uint32_t));
		return -1;
	}

	/* 解码 argc */
	psize = (uint32_t *)data;
	list->argc = *psize;
	if (list->argc < 1 || list->argc > ARG_MAX) {
		x_printf(LOG_ERR, "cmd_decode: invalid argc=%d", list->argc);
		return -1;
	}
	psize++;
	done += sizeof(uint32_t);

	/* 验证缓冲区大小 */
	if (size < done + list->argc * sizeof(uint32_t) + sizeof(uint32_t)) {
		x_printf(LOG_ERR, "cmd_decode: buffer too small (%u < %lu)", size,
				done + list->argc * sizeof(uint32_t) + sizeof(uint32_t));
		return -1;
	}

	/* 解码参数长度 */
	uint32_t arg_len[ARG_MAX];
	for (i = 0; i < list->argc; i++) {
		arg_len[i] = *psize;
		if (arg_len[i] == 0 || arg_len[i] > size) {
			x_printf(LOG_ERR, "cmd_decode: invalid arg_len[%d]=%u", i, arg_len[i]);
			return -1;
		}
		psize++;
		done += sizeof(uint32_t);
	}

	/* 解码 cwd 长度 */
	uint32_t cwd_len = *psize;
	if (cwd_len >= CSDO_CWD_MAX) {
		x_printf(LOG_ERR, "cmd_decode: cwd_len=%u exceeds CSDO_CWD_MAX=%d", cwd_len, CSDO_CWD_MAX);
		return -1;
	}
	psize++;
	done += sizeof(uint32_t);

	/* 验证总长度 */
	uint32_t total_len = done;
	for (i = 0; i < list->argc; i++) {
		total_len += arg_len[i];
	}
	total_len += cwd_len;
	if (total_len > size) {
		x_printf(LOG_ERR, "cmd_decode: total length %u exceeds buffer size %u", total_len, size);
		return -1;
	}

	/* 解码参数字符串 */
	pdata = (char *)psize;
	for (i = 0; i < list->argc; i++) {
		/* 验证字符串长度和 NUL 终止 */
		if (pdata[arg_len[i] - 1] != '\0') {
			x_printf(LOG_ERR, "cmd_decode: arg %d not null-terminated", i);
			return -1;
		}
		list->argv[i] = pdata;
		x_printf(LOG_DEBUG, "cmd_decode: decoded argv[%d]='%s'", i, list->argv[i]);
		pdata += arg_len[i];
		done += arg_len[i];
	}

	/* 解码 cwd 字符串 */
	if (cwd_len > 0) {
		if (pdata[cwd_len - 1] != '\0') {
			x_printf(LOG_ERR, "cmd_decode: cwd not null-terminated");
			return -1;
		}
		list->cwd = pdata;
		done += cwd_len;
		x_printf(LOG_DEBUG, "cmd_decode: decoded cwd='%s'", list->cwd);
	}

	x_printf(LOG_DEBUG, "cmd_decode: total decoded size=%u", done);
	return 0;
}

/*
 * Reads exactly count bytes from fd into buf.
 * Supports both blocking and non-blocking fds.
 * Returns 0 on success, -1 on error or EOF.
 */
static inline int do_read(int fd, void *buf, size_t count)
{
	int rv;
	size_t off = 0;
	struct pollfd pfd;

	if (!buf) {
		x_printf(LOG_ERR, "do_read: null buffer for fd %d", fd);
		return -1;
	}
	if (fd < 0) {
		x_printf(LOG_ERR, "do_read: invalid file descriptor %d", fd);
		return -1;
	}
	if (count == 0) {
		return 0; /* No-op for zero bytes */
	}

	while (off < count) {
		rv = read(fd, (char *)buf + off, count - off);
		if (rv == 0) {
			x_printf(LOG_ERR, "do_read: EOF or connection closed for fd %d", fd);
			return -1;
		}
		if (rv == -1 && errno == EINTR) {
			continue;
		}
		if (rv == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			pfd.fd = fd;
			pfd.events = POLLIN;
			rv = poll(&pfd, 1, -1); /* Infinite timeout */
			if (rv < 0) {
				if (errno == EINTR)
					continue;
				x_printf(LOG_ERR, "do_read: poll failed for fd %d: %s", fd, strerror(errno));
				return -1;
			}
			if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
				x_printf(LOG_ERR, "do_read: poll error on fd %d: %s%s%s",
						fd,
						(pfd.revents & POLLERR) ? "POLLERR " : "",
						(pfd.revents & POLLHUP) ? "POLLHUP " : "",
						(pfd.revents & POLLNVAL) ? "POLLNVAL" : "");
				return -1;
			}
			if (!(pfd.revents & POLLIN)) {
				x_printf(LOG_ERR, "do_read: poll did not return POLLIN for fd %d", fd);
				return -1;
			}
			continue;
		}
		if (rv < 0) {
			x_printf(LOG_ERR, "do_read: read failed for fd %d: %s", fd, strerror(errno));
			return -1;
		}
		off += rv;
	}
	return 0;
}

/*
 * Writes exactly count bytes from buf to fd.
 * Supports both blocking and non-blocking fds.
 * Returns 0 on success, -1 on error.
 */
static inline int do_write(int fd, void *buf, size_t count)
{
	int rv;
	size_t off = 0;
	struct pollfd pfd;

	if (!buf) {
		x_printf(LOG_ERR, "do_write: null buffer for fd %d", fd);
		return -1;
	}
	if (fd < 0) {
		x_printf(LOG_ERR, "do_write: invalid file descriptor %d", fd);
		return -1;
	}
	if (count == 0) {
		return 0; /* No-op for zero bytes */
	}

	while (off < count) {
		rv = write(fd, (char *)buf + off, count - off);
		if (rv == 0) {
			x_printf(LOG_ERR, "do_write: write returned 0 for fd %d", fd);
			return -1;
		}
		if (rv == -1 && errno == EINTR) {
			continue;
		}
		if (rv == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			pfd.fd = fd;
			pfd.events = POLLOUT;
			rv = poll(&pfd, 1, -1); /* Infinite timeout */
			if (rv < 0) {
				if (errno == EINTR)
					continue;
				x_printf(LOG_ERR, "do_write: poll failed for fd %d: %s", fd, strerror(errno));
				return -1;
			}
			if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
				x_printf(LOG_ERR, "do_write: poll error on fd %d: %s%s%s",
						fd,
						(pfd.revents & POLLERR) ? "POLLERR " : "",
						(pfd.revents & POLLHUP) ? "POLLHUP " : "",
						(pfd.revents & POLLNVAL) ? "POLLNVAL" : "");
				return -1;
			}
			if (!(pfd.revents & POLLOUT)) {
				x_printf(LOG_ERR, "do_write: poll did not return POLLOUT for fd %d", fd);
				return -1;
			}
			continue;
		}
		if (rv < 0) {
			x_printf(LOG_ERR, "do_write: write failed for fd %d: %s", fd, strerror(errno));
			return -1;
		}
		off += rv;
	}
	return 0;
}

/*
 * Sets a file descriptor to non-blocking mode.
 */
static inline int set_nonblocking(int fd, const char *name)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		x_printf(LOG_ERR, "Failed to get %s=%d flags: %s", name, fd, strerror(errno));
		return -1;
	}
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) == -1) {
		x_printf(LOG_ERR, "Failed to set %s=%d to non-blocking: %s", name, fd, strerror(errno));
		return -1;
	}
	x_printf(LOG_DEBUG, "Set %s=%d to non-blocking", name, fd);
	return 0;
}
#endif
