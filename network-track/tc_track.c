// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */

/**
 * !주의
 * !Cilium이 TCX 프로그램을 사용하여 패킷을 검증하는 탓에, Classic TC가 붙으면 식별 X
 * !대신 TCX 형태로 작성한 뒤, 각 Interface의 최우선순위의 ID를 식별하여 부착하면 가져올 수 있다.
 * !아니면, XDP를 통해 접근해야 한다. 안그러면, 패킷 캡처링 자체가 안된다.
 */

#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "tc_track.skel.h"
#include "tc_track.h"

#define LO_IFINDEX 1

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static void ip_addr_parser(__u8 * ip_buf, __u32 raw_ip) {
	int idx = 0;
	memset(ip_buf, 0, 4);
	for (; raw_ip > 0 && idx < 4; idx++) {
		ip_buf[idx] = raw_ip % 256U;
		raw_ip = raw_ip >> 8U;
	}
	return;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int log_handler(void *ctx, void *data, size_t size) {
	struct http_event *event = data;
	__u8 src_ip[4], dst_ip[4];

	ip_addr_parser(src_ip, event->src_ip);
	ip_addr_parser(dst_ip, event->dst_ip);

	printf("time: %llu src_ip=%u.%u.%u.%u, dst_ip=%u.%u.%u.%u, method: %s, path: %s\n", 
		event->timestamp_ns,
		src_ip[0], src_ip[1], src_ip[2], src_ip[3],
		dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3],
		event->method,
		event->path
		);
 	return 0;
}


void list_tc_bpf_programs_on_iface(const char *iface) {
    struct bpf_prog_info info = {};
    struct bpf_link_info link_info = {};

    __u32 id = 0, next_id = 0;
    __u32 info_len = sizeof(info);
    __u32 link_info_len = sizeof(link_info);
    int fd, link_fd;
    __u32 iface_index = if_nametoindex(iface);

    if (iface_index == 0) {
        fprintf(stderr, "Failed to get interface index for %s\n", iface);
        return;
    }

    printf("Listing TC BPF programs on interface: %s\n", iface);

    while (bpf_prog_get_next_id(id, &next_id) == 0) {
        fd = bpf_prog_get_fd_by_id(next_id);
        if (fd < 0) {
            fprintf(stderr, "Failed to get program FD for ID %u: %s\n", next_id, strerror(errno));
            break;
        }

        if (bpf_obj_get_info_by_fd(fd, &info, &info_len) == 0) {
            // 링크 정보 가져오기 (이 프로그램이 특정 인터페이스에 부착되어 있는지 확인)
            for (__u32 link_id = 0, next_link_id; 
                 bpf_link_get_next_id(link_id, &next_link_id) == 0; 
                 link_id = next_link_id) {

                link_fd = bpf_link_get_fd_by_id(next_link_id);
                if (link_fd < 0)
                    continue;

                if (bpf_obj_get_info_by_fd(link_fd, &link_info, &link_info_len) == 0) {
                    if (link_info.tcx.ifindex == iface_index) {
                        printf("Program ID: %u, Name: %s, Type: %u\n",
                               next_id, info.name, info.type);
                    }
                }
                close(link_fd);
            }
        } else {
            fprintf(stderr, "Failed to get program info for ID2 %u: %s / %d\n", next_id, strerror(errno), fd);
        }

        close(fd);
        id = next_id;  // 다음 ID로 이동
    }
}

//-------------------------[MAIN]---------------------------------

int main(int argc, char **argv)
{
	unsigned int net_ifindex;
	struct tc_track_bpf *skel;
	int err;
	
	struct bpf_link * link = NULL;
	struct ring_buffer *ring_buf = NULL;

	if (argc < 2) {
		fprintf(stderr, "USAGE: %s [netif]\n", argv[0]);
		return 1;
	}

	// Initialization -----------------------------------------------------------------

	DECLARE_LIBBPF_OPTS(bpf_tcx_opts, tcx_opts,
		.flags = BPF_F_BEFORE,
		.relative_fd = 0,
		.relative_id = 1725,     // bpftool 기준 prog_id를 의미.
		.expected_revision = 0
	);

	net_ifindex = if_nametoindex(argv[1]);
	if (!net_ifindex) {
        perror("if_nametoindex");
        return 1;
    }

	// libbpf 처리 로그 출력기.
	libbpf_set_print(libbpf_print_fn);

	// Open/Load Program ---------------------------------------------------------------
	// eBPF 프로그램을 Skeleton으로 만들었을 때, 이를 가져오는 것.
	skel = tc_track_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// RingBuf Init. -------------------------------------------------------------------
	
	ring_buf = ring_buffer__new(bpf_map__fd(skel->maps.log_map), log_handler, NULL, NULL);
	if (!ring_buf) {
		perror("ring_buffer__new");
		goto cleanup;
	}

	// Attach Program ------------------------------------------------------------------

	link = bpf_program__attach_tcx(skel->progs.tc_ingress, net_ifindex, &tcx_opts);
	if (!link) {
		perror("bpf_program__attach_tcx");
		goto cleanup;
	}
	
	// Prevent Corruption by Keyboard-Interrupt ----------------------------------------
	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Successfully started.\n");

	list_tc_bpf_programs_on_iface(argv[1]);

	// Working Area 
	// Stop when Ctrl+C occured
	while (!exiting) {
		ring_buffer__poll(ring_buf, -1);
	}

	err = bpf_link__detach(link);
	if (err) {
		fprintf(stderr, "Failed to detach TC: %d\n", err);
		goto cleanup;
	}

cleanup:
	printf("Try to Finish Program. Clean-Up Procedure begins.\n");

	if (link) 
		bpf_link__destroy(link);
	if (ring_buf != NULL) 
		ring_buffer__free(ring_buf);
	tc_track_bpf__destroy(skel);

	printf("Clean Up Finished.\n");
	return -err;
}
