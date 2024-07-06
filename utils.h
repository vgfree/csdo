/*
* Copyright(c) 2023-2024 IOdepth Corporation
*/
#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ARG_MAX          4096

struct cmd_arg_list {
	int argc;
	char *argv[ARG_MAX];
};

static inline int cmd_encode(struct cmd_arg_list *list, char *data, uint32_t *size)
{
	int i;
	uint32_t done = 0;
	uint32_t *psize = (uint32_t *)data;
	if (data) {
		*psize = list->argc;
	}
	psize ++;
	done += sizeof(*psize);
	for (i = 0; i < list->argc; i ++) {
		if (data) {
			*psize = strlen(list->argv[i]) + 1;
		}
		psize ++;
		done += sizeof(*psize);
	}
	char *pdata = (char *)psize;
	for (i = 0; i < list->argc; i ++) {
		if (data) {
			memcpy(pdata, list->argv[i], strlen(list->argv[i]) + 1);
		}
		pdata += strlen(list->argv[i]) + 1;
		done += strlen(list->argv[i]) + 1;
	}
	if (size)
		*size = done;
	return 0;
}

static inline int cmd_decode(struct cmd_arg_list *list, char *data, uint32_t size)
{
	int i;
	uint32_t done = 0;
	uint32_t *psize = (uint32_t *)data;
	list->argc = *psize;
	psize ++;
	done += sizeof(*psize);
	char *pdata = (char *)psize;
	for (i = 0; i < list->argc; i ++) {
		pdata += sizeof(*psize);
		done += sizeof(*psize);
	}
	for (i = 0; i < list->argc; i ++) {
		list->argv[i] = pdata;
		pdata += psize[i];
		done += psize[i];
	}
	return 0;
}


struct csdo_base_header {
	uint32_t magic;
	uint32_t version;
};

struct csdo_request_header {
	struct csdo_base_header bh;
	uint64_t length;
};

struct csdo_respond_header {
	struct csdo_base_header bh;
	uint64_t length;
	uint32_t std_fileno;
	int32_t result;
};

#define CSDO_QUERY_MAGIC			0xA12BA12B
#define CSDO_QUERY_VERSION			0x00010001
#define CSDO_QUERY_QUERY_SOCK_PATH		"csdo_query_sock"

static inline void csdo_query_init_header(struct csdo_base_header *bh)
{
	memset(bh, 0, sizeof(struct csdo_base_header));

	bh->magic = CSDO_QUERY_MAGIC;
	bh->version = CSDO_QUERY_VERSION;
}

#endif
