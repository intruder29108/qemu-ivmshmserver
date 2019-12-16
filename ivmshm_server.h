/*
 * InterVM Shared Memory server for QEMU.
 *
 */
#ifndef __IVMSHMSERVER_H__
#define __IVMSHMSERVER_H__

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/select.h>

#include "list.h"

#define MAX_VEC		(64)

struct ivmshm_server_t {
	char sock_path[PATH_MAX];
	int sock_fd;
	char shm_path[PATH_MAX];
	int shm_fd;
	bool use_shm_open;
	size_t shm_size;
	int nvectors;
	unsigned int curr_peer_id;
	bool verbose;
	struct list_head_t peer_list;
};

struct event_notifier_t {
	int rfd;
	int wfd;
};

struct ivmshm_peer_t {
	int sock_fd;
	unsigned int peer_id;
	struct event_notifier_t vectors[MAX_VEC];
	unsigned int nvectors;
	struct list_head_t node;
};

int ivmshm_server_init(struct ivmshm_server_t *server, bool verbose,
		const char *sock_path, const char *shm_path, size_t shm_size,
		int nvecs);
void ivmshm_server_get_fds(struct ivmshm_server_t *server, fd_set *fds,
		int *maxfd);
int ivmshm_server_handle_fds(struct ivmshm_server_t *server, fd_set *fds,
		int maxfd);
void ivmshm_server_close(struct ivmshm_server_t *server);

#endif
