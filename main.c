/*
 * main.c
 *
 * Inter-VM Shared memory server for QEMU.
 */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <sys/select.h>

#include "ivmshm_server.h"

#define IVMSHM_SERVER_DEFAULT_SOCK_PATH			"/tmp/ivmshm_socket"
#define IVMSHM_SERVER_DEFAULT_SHM_PATH			"ivshm"
#define IVMSHM_SERVER_DEFAULT_SHM_SIZE			(4 * 1024 * 1024)
#define IVMSHM_SERVER_DEFAULT_NVECTORS			(1)

extern char *optarg;
extern int optind, opterr, optopt;
static int ivmshm_server_quit = false;

struct ivmshm_server_args {
	bool verbose;
	const char *unix_sock_path;
	const char *shm_path;
	size_t shm_size;
	unsigned n_vectors;
};

static void ivshm_server_usage(const char *progname) {

	printf("Usage: %s [OPTION]...\n"
		"  -h: show this help\n"
		"  -v: verbose mode\n"
		"  -S <unix-socket-path>: path to unix socket to listen to\n"
		"     default " IVMSHM_SERVER_DEFAULT_SOCK_PATH "\n"
		"  -M <shm-name>: POSIX shared memory object name to use\n"
		"     default " IVMSHM_SERVER_DEFAULT_SHM_PATH "\n"
		"  -l <size>: size of shared memory\n"
		"     suffixes K, M, and G can be used. 1K means 1024\n"
		"     default %u\n"
		"  -n <nvectors>: number of vectors\n"
		"     default %u\n",
		progname, IVMSHM_SERVER_DEFAULT_SHM_SIZE,
		IVMSHM_SERVER_DEFAULT_NVECTORS);
};

static void ivmshm_server_help(const char *progname) {

	fprintf(stderr, "Try %s -h' for more information\n", progname);
}

static void ivmshm_server_parse_args(struct ivmshm_server_args *args,
		int argc, char *argv[]) {

	int c;

	while ((c = getopt(argc, argv, "hvS:M:l:n:")) != -1) {

		switch (c) {
			case 'h':
				ivshm_server_usage(argv[0]);
				exit(0);
				break;
			case 'v':
				args->verbose = true;
				break;
			case 'S':
				args->unix_sock_path = optarg;
				break;
			case 'M':
				args->shm_path = optarg;
				break;
			case 'l':
				args->shm_size = strtol(optarg, NULL, 10);
				break;
			case 'n':
				args->n_vectors = strtol(optarg, NULL, 10);
				break;
			default:
				ivmshm_server_help(argv[0]);
				exit(0);
		}
	}
}

static int ivmshm_server_poll_events(struct ivmshm_server_t *server) {

	fd_set fds;
	int ret = 0, maxfd;

	while (!ivmshm_server_quit) {

		FD_ZERO(&fds);
		maxfd = 0;
		ivmshm_server_get_fds(server, &fds, &maxfd);
		ret = select(maxfd, &fds, NULL, NULL, NULL);
		if (ret < 0) {
			if (errno == EINTR) {
				continue;
			}
			fprintf(stderr, "select error: %s\n", strerror(errno));
			break;
		}
		if( ret == 0) {
			continue;
		}
		if (ivmshm_server_handle_fds(server, &fds, maxfd) < 0) {
			fprintf(stderr, "ivmshm_server_handle_fds() failed\n");
			break;
		}
	}

	return ret;
}

static void ivmshm_server_quit_cb(int signum) {
	ivmshm_server_quit = true;
}

int main (int argc, char *argv[]) {

	struct ivmshm_server_t server;
	struct sigaction sa, sa_quit;
	struct ivmshm_server_args args = {
		.verbose = true,
		.unix_sock_path = IVMSHM_SERVER_DEFAULT_SOCK_PATH,
		.shm_path = IVMSHM_SERVER_DEFAULT_SHM_PATH,
		.shm_size = IVMSHM_SERVER_DEFAULT_SHM_SIZE,
		.n_vectors = IVMSHM_SERVER_DEFAULT_NVECTORS
	};
	int ret = 1;

	ivmshm_server_parse_args(&args, argc, argv);
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	if (sigemptyset(&sa.sa_mask) == -1 ||
			sigaction(SIGPIPE, &sa, 0) == -1) {
		perror("failed to ignore SIGPIPE; sigaction");
		goto err;
	}

	sa_quit.sa_handler = ivmshm_server_quit_cb;
	sa_quit.sa_flags = 0;
	if (sigemptyset(&sa_quit.sa_mask) == -1 ||
			sigaction(SIGTERM, &sa_quit, 0) == -1) {
		perror("failed to add SIGTERM handler; sigaction");
		goto err;
	}

	if (ivmshm_server_init(&server, args.verbose, args.unix_sock_path,
				args.shm_path, args.shm_size,
				args.n_vectors) < 0) {
		fprintf(stderr, "cannot start server\n");
		goto err;
	}

	ivmshm_server_poll_events(&server);
	fprintf(stderr, "server disconnected\n");
	ret = 0;

err:
	return ret;
}
