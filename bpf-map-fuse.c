/*
  bpf-map-fuse: BPF Map Filesystem

  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2017-2018  Netronome Systems, Inc.
  Copyright (C) 2020       Kinvolk GmbH

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.


  Reusing some code from the libfuse hello example under GNU GPL:
  https://github.com/libfuse/libfuse/blob/master/example/hello.c

  Reusing some code from bpftool under GPL-2.0-only OR BSD-2-Clause
  https://github.com/torvalds/linux/blob/master/tools/bpf/bpftool/map.c

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>

#define FUSE_USE_VERSION 31
#include <fuse.h>

#define PTR_TO_INT(p) ((int)((intptr_t)(p)))
#define INT_TO_PTR(u) ((void *)((intptr_t)(u)))
#define PTR_TO_UINT64(p) ((uint64_t)((intptr_t)(p)))
#define INTTYPE_TO_PTR(u) ((void *)((intptr_t)(u)))

const char * const map_type_name[] = {
	[BPF_MAP_TYPE_UNSPEC]			= "unspec",
	[BPF_MAP_TYPE_HASH]			= "hash",
	[BPF_MAP_TYPE_ARRAY]			= "array",
	[BPF_MAP_TYPE_PROG_ARRAY]		= "prog_array",
	[BPF_MAP_TYPE_PERF_EVENT_ARRAY]		= "perf_event_array",
	[BPF_MAP_TYPE_PERCPU_HASH]		= "percpu_hash",
	[BPF_MAP_TYPE_PERCPU_ARRAY]		= "percpu_array",
	[BPF_MAP_TYPE_STACK_TRACE]		= "stack_trace",
	[BPF_MAP_TYPE_CGROUP_ARRAY]		= "cgroup_array",
	[BPF_MAP_TYPE_LRU_HASH]			= "lru_hash",
	[BPF_MAP_TYPE_LRU_PERCPU_HASH]		= "lru_percpu_hash",
	[BPF_MAP_TYPE_LPM_TRIE]			= "lpm_trie",
	[BPF_MAP_TYPE_ARRAY_OF_MAPS]		= "array_of_maps",
	[BPF_MAP_TYPE_HASH_OF_MAPS]		= "hash_of_maps",
	[BPF_MAP_TYPE_DEVMAP]			= "devmap",
	[BPF_MAP_TYPE_DEVMAP_HASH]		= "devmap_hash",
	[BPF_MAP_TYPE_SOCKMAP]			= "sockmap",
	[BPF_MAP_TYPE_CPUMAP]			= "cpumap",
	[BPF_MAP_TYPE_XSKMAP]			= "xskmap",
	[BPF_MAP_TYPE_SOCKHASH]			= "sockhash",
	[BPF_MAP_TYPE_CGROUP_STORAGE]		= "cgroup_storage",
	[BPF_MAP_TYPE_REUSEPORT_SOCKARRAY]	= "reuseport_sockarray",
	[BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE]	= "percpu_cgroup_storage",
	[BPF_MAP_TYPE_QUEUE]			= "queue",
	[BPF_MAP_TYPE_STACK]			= "stack",
	[BPF_MAP_TYPE_SK_STORAGE]		= "sk_storage",
	//[BPF_MAP_TYPE_STRUCT_OPS]		= "struct_ops",
};

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
const size_t map_type_name_size = ARRAY_SIZE(map_type_name);

enum bpf_file_type {
	BPF_FILE_TYPE_ROOT,
	BPF_FILE_TYPE_MAP_DIR,
	BPF_FILE_TYPE_MAP_INFO,
	BPF_FILE_TYPE_MAP_TYPE
};


struct bpf_file_info {
	enum bpf_file_type type;
	__u32 bpf_id;
	int bpf_fd;
	struct bpf_map_info info;
};

static int bpf_parse_path(const char *path, struct bpf_file_info *file_info, int keep_open) {
	file_info->bpf_fd = -1;

	if (path[0] == '\0') {
		return -ENOENT;
	}

	if (strcmp(path, "/") == 0) {
		file_info->type = BPF_FILE_TYPE_ROOT;
		return 0;
	}

	const char *after_dir = path + 1 + strcspn(path + 1, "/");
	const char *filename = after_dir + strspn(after_dir, "/");
	char *dirname = strndup(path + 1, after_dir - (path + 1));

        if (strspn(dirname, "0123456789") != strlen(dirname) || dirname[0] == '0') {
		return -ENOENT;
	}
	file_info->bpf_id = atoi(dirname);

	memset(&file_info->info, 0, sizeof(file_info->info));
	__u32 len = sizeof(file_info->info);
	int err;

	file_info->bpf_fd = bpf_map_get_fd_by_id(file_info->bpf_id);
	if (file_info->bpf_fd < 0) {
		if (errno == ENOENT)
			return -ENOENT;
		return -EIO;
	}

	err = bpf_obj_get_info_by_fd(file_info->bpf_fd, &file_info->info, &len);
	if (err) {
		printf("can't get map info: %s\n", strerror(errno));
		close(file_info->bpf_fd);
		return -EIO;
	}

	if (!keep_open) {
		close(file_info->bpf_fd);
		file_info->bpf_fd = -1;
	}

        if (after_dir == filename) {
		file_info->type = BPF_FILE_TYPE_MAP_DIR;
		return 0;
	}
	if (strcmp(filename, "info") == 0) {
		file_info->type = BPF_FILE_TYPE_MAP_INFO;
		return 0;
	}
	if (strcmp(filename, "type") == 0) {
		file_info->type = BPF_FILE_TYPE_MAP_TYPE;
		return 0;
	}

	return -ENOENT;
}


static int bpf_readdir_root(void *buf, fuse_fill_dir_t filler) {
	struct bpf_map_info info = {};
	__u32 len = sizeof(info);
	__u32 id = 0;
	int err;
	int fd;
	char str[16];

	while (true) {
		err = bpf_map_get_next_id(id, &id);
		if (err) {
			if (errno == ENOENT)
				break;
			printf("can't get next map: %s%s\n", strerror(errno),
			      errno == EINVAL ? " -- kernel too old?" : "");
			return -EIO;
		}
		snprintf(str, sizeof(str), "%u", id);
		filler(buf, str, NULL, 0);

		fd = bpf_map_get_fd_by_id(id);
		if (fd < 0) {
			if (errno == ENOENT)
				continue;
			printf("can't get map by id (%u): %s\n",
			      id, strerror(errno));
			return -EIO;
		}

		err = bpf_obj_get_info_by_fd(fd, &info, &len);
		if (err) {
			printf("can't get map info: %s\n", strerror(errno));
			close(fd);
			continue;
		}
		if (info.name[0] != '\0' && strnlen(info.name, BPF_OBJ_NAME_LEN) < BPF_OBJ_NAME_LEN) {
			filler(buf, info.name, NULL, 0);
		}

		if (info.type >= ARRAY_SIZE(map_type_name)) {
			printf("unknown map type: %u\n", info.type);
			close(fd);
			continue;
		}

		printf("id %u type %s key %uB  value %uB  max_entries %u\n",
			info.id, map_type_name[info.type], info.key_size, info.value_size, info.max_entries);
		close(fd);
	}
	return 0;
}

static int bpf_readdir_mapdir(void *buf, fuse_fill_dir_t filler, struct bpf_file_info *file_info) {
	filler(buf, "info", NULL, 0);
	filler(buf, "type", NULL, 0);
	return 0;
}


static struct options {
	int show_help;
} options;

#define OPTION(t, p)                           \
    { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
	OPTION("-h", show_help),
	OPTION("--help", show_help),
	FUSE_OPT_END
};

static int bpf_getattr(const char *path, struct stat *stbuf)
{
	struct bpf_file_info file_info = {};
	int err = bpf_parse_path(path, &file_info, 0);
	if (err) {
		return err;
	}

	memset(stbuf, 0, sizeof(struct stat));

	switch (file_info.type) {
		case BPF_FILE_TYPE_ROOT:
		case BPF_FILE_TYPE_MAP_DIR:
			stbuf->st_mode = S_IFDIR | 0700;
			stbuf->st_nlink = 2;
			return 0;
		case BPF_FILE_TYPE_MAP_INFO:
		case BPF_FILE_TYPE_MAP_TYPE:
			stbuf->st_mode = S_IFREG | 0400;
			stbuf->st_nlink = 1;
			stbuf->st_size = 0;
			return 0;
		default:
			return -EIO;
	}

	return -ENOENT;
}

static int bpf_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
{
	(void) offset;
	(void) fi;

	struct bpf_file_info file_info = {};
	int err = bpf_parse_path(path, &file_info, 0);
	if (err) {
		return err;
	}

	switch (file_info.type) {
		case BPF_FILE_TYPE_ROOT:
			filler(buf, ".", NULL, 0);
			filler(buf, "..", NULL, 0);
			return bpf_readdir_root(buf, filler);
		case BPF_FILE_TYPE_MAP_DIR:
			filler(buf, ".", NULL, 0);
			filler(buf, "..", NULL, 0);
			return bpf_readdir_mapdir(buf, filler, &file_info);
		default:
			return -EIO;
	}

	return -EIO;
}

static int bpf_open(const char *path, struct fuse_file_info *fi)
{
	struct bpf_file_info *file_info;
	file_info = malloc(sizeof(*file_info));

	int err = bpf_parse_path(path, file_info, 1);
	if (err) {
		free(file_info);
		return err;
	}

	if ((fi->flags & O_ACCMODE) != O_RDONLY) {
		free(file_info);
		return -EACCES;
	}

	switch (file_info->type) {
		case BPF_FILE_TYPE_ROOT:
		case BPF_FILE_TYPE_MAP_DIR:
			free(file_info);
			return -EIO;
		case BPF_FILE_TYPE_MAP_INFO:
		case BPF_FILE_TYPE_MAP_TYPE:
			fi->direct_io = 1;
			fi->fh = PTR_TO_UINT64(file_info);
			return 0;
		default:
			free(file_info);
			return -EIO;
	}

	free(file_info);
	return -EIO;
}

static int bpf_release(const char *path, struct fuse_file_info *fi)
{
	struct bpf_file_info *file_info;

	file_info = INTTYPE_TO_PTR(fi->fh);
	if (!file_info)
		return 0;

	fi->fh = 0;

	if (file_info->bpf_fd != -1) {
		close(file_info->bpf_fd);
	}
	free(file_info);

	return 0;
}


static int bpf_read_info(struct bpf_file_info *file_info, char *buf, size_t size, off_t offset)
{
	char content[256] = {0,};
	size_t len;

	len = snprintf(content, sizeof(content), "id %u name %.*s type %s key %uB  value %uB  max_entries %u\n",
		file_info->info.id,
		BPF_OBJ_NAME_LEN, file_info->info.name,
		file_info->info.type < ARRAY_SIZE(map_type_name) ? map_type_name[file_info->info.type] : "unknown",
		file_info->info.key_size,
		file_info->info.value_size,
		file_info->info.max_entries);


	if (offset < len) {
		if (offset + size > len)
			size = len - offset;
		memcpy(buf, content + offset, size);
	} else {
		size = 0;
	}

	return size;
}

static int bpf_read_type(struct bpf_file_info *file_info, char *buf, size_t size, off_t offset)
{
	char content[256] = {0,};
	size_t len;

	len = snprintf(content, sizeof(content), "%s\n",
		file_info->info.type < ARRAY_SIZE(map_type_name) ? map_type_name[file_info->info.type] : "unknown");

	if (offset < len) {
		if (offset + size > len)
			size = len - offset;
		memcpy(buf, content + offset, size);
	} else {
		size = 0;
	}

	return size;
}

static int bpf_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	struct bpf_file_info *file_info = INTTYPE_TO_PTR(fi->fh);

	switch (file_info->type) {
		case BPF_FILE_TYPE_ROOT:
		case BPF_FILE_TYPE_MAP_DIR:
			return -EIO;
		case BPF_FILE_TYPE_MAP_INFO:
			return bpf_read_info(file_info, buf, size, offset);
		case BPF_FILE_TYPE_MAP_TYPE:
			return bpf_read_type(file_info, buf, size, offset);
		default:
			return -EIO;
	}
	return -EIO;
}

static const struct fuse_operations bpf_oper = {
	.getattr	= bpf_getattr,
	.readdir	= bpf_readdir,
	.open		= bpf_open,
	.release	= bpf_release,
	.read		= bpf_read,
};

static void show_help(const char *progname)
{
	printf("usage: %s [options] <mountpoint>\n\n", progname);
}

int main(int argc, char *argv[]) {
	int ret;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	/* Parse options */
	if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
		return 1;

	/* When --help is specified, first print our own file-system
	   specific help text, then signal fuse_main to show
	   additional help (by adding `--help` to the options again)
	   without usage: line (by setting argv[0] to the empty
	   string) */
	if (options.show_help) {
		show_help(argv[0]);
		assert(fuse_opt_add_arg(&args, "--help") == 0);
		args.argv[0][0] = '\0';
	}

	ret = fuse_main(args.argc, args.argv, &bpf_oper, NULL);
	fuse_opt_free_args(&args);
	return ret;
}

