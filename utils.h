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

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define ARG_MAX          4096
#define CSDO_CWD_MAX     4096  /* 最大工作目录长度，与 PATH_MAX 一致 */
#define CSDO_SOCKET_PATH "/var/run/csdod.sock"

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
		syslog(LOG_ERR, "cmd_encode: invalid list or argc=%d", list ? list->argc : -1);
		return -1;
	}
	if (list->argc > ARG_MAX) {
		syslog(LOG_ERR, "cmd_encode: argc %d exceeds ARG_MAX %d", list->argc, ARG_MAX);
		return -1;
	}
	if (list->cwd && strlen(list->cwd) >= CSDO_CWD_MAX) {
		syslog(LOG_ERR, "cmd_encode: cwd too long (%zu >= %d)", strlen(list->cwd), CSDO_CWD_MAX);
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
		syslog(LOG_DEBUG, "cmd_encode: calculated size=%u", total_size);
		return 0;
	}

	/* 编码数据 */
	psize = (uint32_t *)data;
	*psize = list->argc;
	syslog(LOG_DEBUG, "cmd_encode: encoded argc=%d", list->argc);
	psize++;
	done += sizeof(uint32_t);

	/* 编码参数长度 */
	for (i = 0; i < list->argc; i++) {
		uint32_t arg_len = strlen(list->argv[i]) + 1;
		*psize = arg_len;
		syslog(LOG_DEBUG, "cmd_encode: encoded argv[%d] length=%u", i, arg_len);
		psize++;
		done += sizeof(uint32_t);
	}

	/* 编码 cwd 长度 */
	uint32_t cwd_len = list->cwd ? strlen(list->cwd) + 1 : 0;
	*psize = cwd_len;
	syslog(LOG_DEBUG, "cmd_encode: encoded cwd length=%u", cwd_len);
	psize++;
	done += sizeof(uint32_t);

	/* 编码参数字符串 */
	pdata = (char *)psize;
	for (i = 0; i < list->argc; i++) {
		uint32_t arg_len = strlen(list->argv[i]) + 1;
		memcpy(pdata, list->argv[i], arg_len);
		syslog(LOG_DEBUG, "cmd_encode: encoded argv[%d]='%s'", i, pdata);
		pdata += arg_len;
		done += arg_len;
	}

	/* 编码 cwd 字符串 */
	if (cwd_len > 0) {
		memcpy(pdata, list->cwd, cwd_len);
		syslog(LOG_DEBUG, "cmd_encode: encoded cwd='%s'", pdata);
		done += cwd_len;
	}

	*size = done;
	syslog(LOG_DEBUG, "cmd_encode: total encoded size=%u", done);
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
		syslog(LOG_ERR, "cmd_decode: invalid buffer or size (%u < %zu)", size, sizeof(uint32_t));
		return -1;
	}

	/* 解码 argc */
	psize = (uint32_t *)data;
	list->argc = *psize;
	syslog(LOG_DEBUG, "cmd_decode: decoded argc=%d", list->argc);
	if (list->argc <= 0 || list->argc > ARG_MAX) {
		syslog(LOG_ERR, "cmd_decode: invalid argc %d (must be 1 to %d)", list->argc, ARG_MAX);
		return -1;
	}
	psize++;
	done += sizeof(uint32_t);

	/* 检查参数长度数组空间 */
	if (done + list->argc * sizeof(uint32_t) > size) {
		syslog(LOG_ERR, "cmd_decode: insufficient buffer for %d arg lengths (done=%u, size=%u)", list->argc, done, size);
		return -1;
	}

	/* 解码参数长度 */
	uint32_t *arg_lengths = psize;
	for (i = 0; i < list->argc; i++) {
		if (arg_lengths[i] == 0) {
			syslog(LOG_ERR, "cmd_decode: invalid zero length for arg %d", i);
			return -1;
		}
		syslog(LOG_DEBUG, "cmd_decode: arg[%d] length=%u", i, arg_lengths[i]);
	}
	psize += list->argc;
	done += list->argc * sizeof(uint32_t);

	/* 解码 cwd 长度 */
	if (done + sizeof(uint32_t) > size) {
		syslog(LOG_ERR, "cmd_decode: insufficient buffer for cwd length (done=%u, size=%u)", done, size);
		return -1;
	}
	uint32_t cwd_len = *psize;
	if (cwd_len >= CSDO_CWD_MAX) {
		syslog(LOG_ERR, "cmd_decode: cwd length too long (%u >= %d)", cwd_len, CSDO_CWD_MAX);
		return -1;
	}
	syslog(LOG_DEBUG, "cmd_decode: cwd length=%u", cwd_len);
	psize++;
	done += sizeof(uint32_t);

	/* 验证总长度 */
	uint32_t total_data_len = 0;
	for (i = 0; i < list->argc; i++) {
		total_data_len += arg_lengths[i];
	}
	total_data_len += cwd_len;
	if (done + total_data_len > size) {
		syslog(LOG_ERR, "cmd_decode: insufficient buffer for args and cwd (done=%u, total_data_len=%u, size=%u)", done, total_data_len, size);
		return -1;
	}

	/* 解码参数字符串 */
	pdata = (char *)psize;
	for (i = 0; i < list->argc; i++) {
		/* 验证字符串长度和 NUL 终止 */
		if (pdata[arg_lengths[i] - 1] != '\0') {
			syslog(LOG_ERR, "cmd_decode: arg %d not null-terminated", i);
			return -1;
		}
		list->argv[i] = pdata;
		syslog(LOG_DEBUG, "cmd_decode: decoded argv[%d]='%s'", i, list->argv[i]);
		pdata += arg_lengths[i];
		done += arg_lengths[i];
	}

	/* 解码 cwd */
	if (cwd_len > 0) {
		if (pdata[cwd_len - 1] != '\0') {
			syslog(LOG_ERR, "cmd_decode: cwd not null-terminated");
			return -1;
		}
		list->cwd = pdata;
		syslog(LOG_DEBUG, "cmd_decode: decoded cwd='%s'", list->cwd);
	} else {
		list->cwd = NULL;
		syslog(LOG_DEBUG, "cmd_decode: no cwd provided");
	}

	syslog(LOG_DEBUG, "cmd_decode: total decoded size=%u", done);
	return 0;
}

struct csdo_base_header {
	uint32_t magic;
	uint32_t version;
};

struct csdo_request_header {
	struct csdo_base_header bh;
	uint64_t length;
	uid_t uid; /* Added for -u option */
	int32_t no_pty; /* Added for -n option */
};

struct csdo_respond_header {
	struct csdo_base_header bh;
	uint64_t length;
	uint32_t std_fileno;
	int32_t result;
};

#define CSDO_QUERY_MAGIC                        0xA12BA12B
#define CSDO_QUERY_VERSION                      0x00010001

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
		syslog(LOG_ERR, "do_read: null buffer");
		return -1;
	}

	pfd.fd = fd;
	pfd.events = POLLIN;

	while (off < count) {
		rv = read(fd, (char *)buf + off, count - off);
		if (rv == 0) {
			syslog(LOG_ERR, "do_read: connection closed");
			return -1;
		}
		if (rv == -1 && errno == EINTR) {
			continue;
		}
		if (rv == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			rv = poll(&pfd, 1, -1);
			if (rv < 0) {
				if (errno == EINTR)
					continue;
				syslog(LOG_ERR, "do_read: poll: %s", strerror(errno));
				return -1;
			}
			if (rv == 0 || !(pfd.revents & POLLIN)) {
				syslog(LOG_ERR, "do_read: poll returned no POLLIN event");
				return -1;
			}
			continue;
		}
		if (rv == -1) {
			syslog(LOG_ERR, "do_read: %s", strerror(errno));
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
		syslog(LOG_ERR, "do_write: null buffer");
		return -1;
	}

	pfd.fd = fd;
	pfd.events = POLLOUT;

	while (off < count) {
		rv = write(fd, (char *)buf + off, count - off);
		if (rv == -1 && errno == EINTR) {
			continue;
		}
		if (rv == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			rv = poll(&pfd, 1, -1);
			if (rv < 0) {
				if (errno == EINTR)
					continue;
				syslog(LOG_ERR, "do_write: poll: %s", strerror(errno));
				return -1;
			}
			if (rv == 0 || !(pfd.revents & POLLOUT)) {
				syslog(LOG_ERR, "do_write: poll returned no POLLOUT event");
				return -1;
			}
			continue;
		}
		if (rv < 0) {
			syslog(LOG_ERR, "do_write: %s", strerror(errno));
			return rv;
		}
		off += rv;
	}
	return 0;
}

#endif
