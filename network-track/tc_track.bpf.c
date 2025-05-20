// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "tc_track.h"

#define ETH_P_IP  0x0800 /* Internet Protocol packet	*/

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} log_map SEC(".maps");


/**
 * TestNote - veth pair 중 lxc에 부착된 경우.
 * 2025.03.14: Pod 기준으로, ingress는 나가는 Packet이 되고, egress는 Pod로 들어오는 패킷이 된다.
 *     사실 이유는 간단하다. lxc는 Host에 있는 것이고, Pod는 외부 시스템으로 취급되기 때문이다.
 */

SEC("tcx/ingress")
int tc_ingress(struct __sk_buff *ctx)
{
	/*
	if (bpf_skb_pull_data(ctx, ctx->len) < 0)
		return TCX_NEXT;
	*/
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct tcphdr *l4;
	char * l7;
	struct http_event *event;

	if (ctx->protocol != bpf_htons(ETH_P_IP))
		return TCX_NEXT;

	// Extract Ethernet Header
	// l2 + 1 -> end of eth header
	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		return TCX_NEXT;

	// Extract IP Header
	l3 = (struct iphdr *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end)
		return TCX_NEXT;
	if (l3->protocol != IPPROTO_TCP)
		return TCX_NEXT;

	// Extract TCP Header
	l4 = (void *)l3 + (l3->ihl * 4);
	if ((void *)(l4 + 1) > data_end)
		return TCX_NEXT;

	// Allocate Space of Ringbuf for data
	event = bpf_ringbuf_reserve(&log_map, sizeof(*event), 0);
	if (!event) {
		bpf_printk("Error: ringbuf allocation failed");
		return TCX_NEXT;
	}
	// init memory
	__builtin_memset(event, 0, sizeof(struct http_event));


	event->timestamp_ns = bpf_ktime_get_ns();
	event->src_ip = l3->saddr;
	event->dst_ip = l3->daddr;
	event->data[0] = '\0'; // bpf_get_current_pid_tgid() >> 32;

	l7 = (char *)l4 + (l4->doff * 4);
	
	event->dport = ((void*)ctx->data_end - (void*)l7); // bpf_ntohs(l4->dest);
	event->sport = bpf_ntohs(l4->source);


	if ((void *)l7 + 3 >= ctx->data_end)
		goto submit;

	int i;
	for (i = 0; i < 3; i++)
		event->data[i] = l7[i];
	l7[i] = '\0';

submit:
	bpf_ringbuf_submit(event, 0);
	return TCX_NEXT;
}

char __license[] SEC("license") = "GPL";
