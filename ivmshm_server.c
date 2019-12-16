/*
 * Implements a Inter VM shared memory server for QEMU.
 *
 * Heavily based on QEMU ivmshmserver example.
 */
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>

#include "ivmshm_server.h"

#define ivmshm_server_dbg(server, fmt, ...) do { \
	if ((server)->verbose) {		\
		printf(fmt, ## __VA_ARGS__);	\
	}					\
} while (0)

#define IVM_SHM_PROTO_VER	(0)
#define MAX_SOCK_BACKLOG	(10)  // Max number of connection not accepted.

static int ivmshm_event_notifier_set(struct event_notifier_t *e) {

	const eventfd_t value = 1;
	int ret;

	ret = eventfd_write(e->wfd, value);

	return ret;
}

static int ivmshm_event_notifier_get(struct event_notifier_t *e) {

	return (e->rfd);
}
static int ivmshm_event_notifier_init(struct event_notifier_t *e, bool active) {

	int ret = 0;

	ret = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (ret >= 0) {
		e->rfd = e->wfd = ret;
	} else {
		printf("[ERROR]: failed to create event notification\n");
		goto fail;
	}
	if (active) {
		ret = ivmshm_event_notifier_set(e);
		if (ret) {
			printf("[ERROR]: failed set event notifier\n");
			goto fail;
		}
	}

	return 0;

fail:
	return ret;
}

static void ivmshm_event_notifier_cleanup(struct event_notifier_t *e) {

	close(e->wfd);
	e->wfd = e->rfd = -1;
}

static int ivmshm_server_send_msg(int sock_fd, int64_t data, int fd) {

	struct msghdr msg = {0};
	struct cmsghdr *cmsg;
	struct iovec iov[1];
	union {
		/* ancillary data buffer */
		char buf[CMSG_SPACE(sizeof fd)];
		struct cmsghdr align;
	} u;
	int *fdptr;
	int ret = 0;

	/*
	 * Populate message.
	 * 1) Fill in IOV entries.
	 * 2) Fill in ancillary data if a valid fd is passed.
	 */
	iov[0].iov_base = &data;
	iov[0].iov_len = sizeof data;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	if (fd > 0) {
		msg.msg_control = u.buf;
		msg.msg_controllen = sizeof u.buf;
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		fdptr = (int *)CMSG_DATA(cmsg);
		*fdptr = fd;
	}

	ret = sendmsg(sock_fd, &msg, 0);

	return ret;
}

static int ivmshm_server_send_initial_info(struct ivmshm_server_t *server,
		struct ivmshm_peer_t *peer) {

	int ret = 0;

	ret = ivmshm_server_send_msg(peer->sock_fd, IVM_SHM_PROTO_VER, -1);
	if (ret == -1) {
		printf("[ERROR]: failed to send protocol version(%d)\n",
				errno);

		goto fail;
	}
	ret = ivmshm_server_send_msg(peer->sock_fd, peer->peer_id, -1);
	if (ret == -1) {
		printf("[ERROR]: failed to send peer_id(%d)\n", errno);

		goto fail;
	}
	ret = ivmshm_server_send_msg(peer->sock_fd, -1, server->shm_fd);
	if (ret == -1) {
		printf("[ERROR]: failed to send shm_fd(%d)\n", errno);

		goto fail;
	}

fail:
	return ret;
}

static int ivmshm_handle_new_connection(struct ivmshm_server_t *server) {

	int ret = 0;
	int sock_fd;
	int flag, i;
	struct ivmshm_peer_t *peer, *other_peer;

	/*
	 * 1) Accept incoming connection and save the peer socked fd.
	 * 2) Make peer socket non-blocking.
	 * 3) Allocate and initailize peer entry with peer_id.
	 * 4) Allocate and assign event vectors for peer.
	 * 5) Send initial connection information to peer.
	 *     *) protocol version.
	 *     *) peer_id.
	 *     *) shm_fd.
	 * 6) Advertise new peer to all existing peers.
	 * 7) Advertise all existing peers to new peer.
	 * 8) Advertise new peer to itself.
	 * 9) Add new peer to server's list.
	 */
	sock_fd = accept(server->sock_fd, NULL, NULL);
	if (sock_fd == -1) {
		printf("[ERROR]: accept failed with errno(%d)\n", errno);
		ret = -1;

		goto fail;
	}
	flag = fcntl(sock_fd, F_GETFL);
	fcntl(sock_fd, F_SETFL, flag | O_NONBLOCK);
	ivmshm_server_dbg(server, "[INFO]: accepted new connection with fd(%d)\n",
			sock_fd);
	peer = (struct ivmshm_peer_t *)calloc(1, sizeof *peer);
	if (!peer) {
		printf("[ERROR]: failed to allocate peer, OOM\n");
		ret = -1;
		goto peer_oom_fail;
	}
	peer->sock_fd = sock_fd;
	peer->peer_id = server->curr_peer_id++;
	peer->nvectors = 0;
	for (int i = 0; i < server->nvectors; i++) {
		ret = ivmshm_event_notifier_init(&peer->vectors[i], false);
		if (ret) {
			printf("[ERROR]: failed to create eventfd for vector(%d)\n",
					i);
		} else {
			ivmshm_server_dbg(server, "[INFO]: vector(%d) alloted eventfd(%d)\n",
					i, peer->vectors[i].wfd);
			peer->nvectors++;
		}
	}

	ret = ivmshm_server_send_initial_info(server, peer);
	if (ret == -1) {
		printf("[ERROR]: failed to send initial info to peer\n");
		goto fail_initial_info;
	}
	list_for_each_entry(other_peer, &server->peer_list, node) {
		for (i = 0; i < peer->nvectors; i++) {
			ret = ivmshm_server_send_msg(other_peer->sock_fd,
					peer->peer_id,
					peer->vectors[i].wfd);
			if (ret == -1) {
				printf("[ERROR]: failed to advertise vector(%d)"\
						" of peer(%d) to other_peer(%d)\n",
						i, peer->peer_id, other_peer->peer_id);
			}
		}
	}
	list_for_each_entry(other_peer, &server->peer_list, node) {
		for (i = 0; i < other_peer->nvectors; i++) {
			ret = ivmshm_server_send_msg(peer->sock_fd,
					other_peer->peer_id,
					other_peer->vectors[i].wfd);
			if (ret == -1) {
				printf("[ERROR]: failed to advertise vector(%d)"\
						" of other_peer(%d) to peer(%d)\n",
						i, other_peer->peer_id, peer->peer_id);
			}
		}
	}
	for (i = 0; i< peer->nvectors; i++) {
		ret = ivmshm_server_send_msg(peer->sock_fd, peer->peer_id,
				ivmshm_event_notifier_get(&peer->vectors[i]));
		if (ret == -1) {
			printf("[ERROR]: failed to advertise vector(%d) to"\
					"self(%d)\n", i, peer->peer_id);
		}
	}

	list_add_tail(&peer->node, &server->peer_list);
	ivmshm_server_dbg(server, "[INFO]: successfully added peerid(%d)\n",
			peer->peer_id);

	return 0;

fail_initial_info:
	for (int i = 0; i < peer->nvectors; i++) {
		ivmshm_event_notifier_cleanup(&peer->vectors[i]);
	}
	free(peer);
peer_oom_fail:
	close(sock_fd);
fail:
	return ret;
}

static void ivmshm_server_free_peer(struct ivmshm_server_t *server,
		struct ivmshm_peer_t *peer) {

	struct ivmshm_peer_t *other_peer;
	int ret;

	ivmshm_server_dbg(server, "[INFO]: freeing peer(%d)\n", peer->peer_id);
	close(peer->sock_fd);
	list_del(&peer->node);
	list_for_each_entry(other_peer, &server->peer_list, node) {
		ret = ivmshm_server_send_msg(other_peer->sock_fd,
				peer->peer_id, -1);
		if (ret < 0) {
			printf("[ERROR]: failed to send disconnect message"\
					" to peer(%d)\n", other_peer->peer_id);
		}
	}
	for (int i = 0; i < peer->nvectors; i++) {
		ivmshm_event_notifier_cleanup(&peer->vectors[i]);
	}

	free(peer);
}

int ivmshm_server_init(struct ivmshm_server_t *server, bool verbose,
		const char *sock_path, const char *shm_path, size_t shm_size,
		int nvecs) {

	struct sockaddr_un sock_addr;
	int shm_fd, sock_fd, ret;
	struct stat mapstat;

	INIT_LIST_HEAD(&server->peer_list);
	snprintf(server->sock_path, sizeof server->sock_path, "%s", sock_path);
	snprintf(server->shm_path, sizeof server->shm_path, "%s", shm_path);
	server->shm_size = shm_size;
	server->nvectors = nvecs;
	server->verbose = verbose;
	server->curr_peer_id = 1;

	/*
	 * Shared memory initalization.
	 *
	 * 1) Create or open shmfd to specified path.
	 * 2) Round shm_size of next higher power of 2.
	 * 2) Check size of shmfd and trucate if <  shm_size.
	 */
	shm_fd = shm_open(server->shm_path, O_RDWR | O_CREAT, S_IRWXU);
	if (shm_fd  == -1) {
		printf("[ERROR]: shm_open failed(\"%s\") errno(%d)\n",
				server->shm_path, errno);
		ret = -1;

		goto shm_open_fail;
	}
	ivmshm_server_dbg(server, "[INFO]: shm_open success, shm_fd(%d)\n",
			shm_fd);
	server->shm_size = pow(2, ceil(log2(shm_size)));
	if (server->shm_size > shm_size) {
		ivmshm_server_dbg(server, "[INFO]: rounding shm_size(%zu) ==> (%zu)\n",
				shm_size, server->shm_size);
	}
	if (fstat(shm_fd, &mapstat) != -1 && mapstat.st_size == server->shm_size) {
		goto sock_setup;
	}
	ret = ftruncate(shm_fd, server->shm_size);
	if (ret != 0) {
		printf("[ERROR]: ftruncate failed for size(%zu) with errno(%d)\n",
				server->shm_size, errno);
		goto shm_truncate_fail;
	}
	ivmshm_server_dbg(server, "[INFO]: truncated shm to size(%zu)\n",
			server->shm_size);


sock_setup:
	/*
	 * Server socket initialization.
	 *
	 * 1) Create socket fd.
	 * 2) Form socket address to specified path.
	 * 3) Bind socket to specified address.
	 * 4) Listen on the socket for incoming connections.
	 */
	sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	sock_addr.sun_family = AF_UNIX;
	strncpy(sock_addr.sun_path, server->sock_path,
			(sizeof sock_addr.sun_path) -1);
	if ((ret = bind(sock_fd, (struct sockaddr *)&sock_addr,
					sizeof sock_addr)) == -1) {
		printf("[ERROR]: failed to bind socket to path(\"%s\")"
			" error(\"%s\")\n", server->sock_path,
			strerror(errno));
		goto bind_fail;
	}
	if ((ret = listen(sock_fd, MAX_SOCK_BACKLOG)) != 0) {
		printf("[ERROR]: failed to listen on socket, errno(\"%s\")\n",
				strerror(errno));
		goto listen_fail;
	}
	ivmshm_server_dbg(server, "[INFO]: listening on server socket(%d)\n",
			sock_fd);
	server->sock_fd = sock_fd;
	server->shm_fd = shm_fd;
	return 0;

bind_fail:
listen_fail:
	close(sock_fd);
shm_truncate_fail:
	close(shm_fd);
shm_open_fail:
	return ret;
}

void ivmshm_server_close(struct ivmshm_server_t *server) {

	struct ivmshm_peer_t *peer, *tmp_peer;

	ivmshm_server_dbg(server, "shutting down server\n");
	list_for_each_entry_safe(peer, tmp_peer, &server->peer_list, node) {
		ivmshm_server_free_peer(server, peer);
	}

	close(server->sock_fd);
	close(server->shm_fd);
	unlink(server->sock_path);
	server->sock_fd = -1;
	server->shm_fd = -1;
}

void ivmshm_server_get_fds(struct ivmshm_server_t *server, fd_set *fds,
		int *maxfd) {

	struct ivmshm_peer_t *peer;
	/*
	 * Add all peer sockets and server socket to the FD_SET and update maxfd
	 * to value one greater than highest fd.
	 */
	FD_SET(server->sock_fd, fds);
	if (server->sock_fd > *maxfd) {
		*maxfd = server->sock_fd + 1;
	}
	list_for_each_entry(peer, &server->peer_list, node) {
		FD_SET(peer->sock_fd, fds);
		if (peer->sock_fd > *maxfd) {
			*maxfd = peer->sock_fd + 1;
		}
	}
}

int ivmshm_server_handle_fds(struct ivmshm_server_t *server, fd_set *fds,
		int maxfd) {

	int ret = 0;
	struct ivmshm_peer_t *peer, *temp;

	/*
	 * 1) If server->sock_fd is set, process incoming client connection.
	 * 2) If peer->sock_fd is set, process peer disconnection
	 */
	if (server->sock_fd < maxfd && FD_ISSET(server->sock_fd, fds)) {
		ret = ivmshm_handle_new_connection(server);
		if (ret) {
			printf("[ERROR]: failed to process new connection\n");
			goto fail;
		}
	}
	list_for_each_entry_safe(peer, temp, &server->peer_list, node) {
		if (peer->sock_fd < maxfd && FD_ISSET(peer->sock_fd, fds)) {
			ivmshm_server_free_peer(server, peer);
		}
	}

fail:
	return ret;
}
