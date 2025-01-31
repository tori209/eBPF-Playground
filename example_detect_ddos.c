#include <linux/skbuff.h>
#include <uapi/linux/ip.h>

#define MAX_NB_PACKETS 1000
#define LEGAL_DIFF_TIMESTAMP_PACKETS 1000000

BPF_HASH(rcv_packets);

struct detectionPackets {
    u64 nb_ddos_packets;
};

BPF_PERF_OUTPUT(events);

int detect_ddos(struct pt_regs * ctx, void *skb) {
    struct detectionPackets detectionPacket = {};

    // 수신 Packet의 수를 계산하는데 사용
    u64 rcv_packets_nb_index = 0,
        rcv_packets_nb_inter = 1,
        *rcv_packets_nb_ptr;

    // 2개의 연속된 패킷의 수신 간격을 계산하는데 사용
    u64 rcv_packets_ts_index = 1,
        rcv_packets_ts_inter = 0,
        *rcv_packets_ts_ptr;
    
    rcv_packets_nb_ptr = rcv_packets.lookup(&rcv_packets_nb_index);
    rcv_packets_ts_ptr = rcv_packets.lookup(&rcv_packets_ts_index);

    if (rcv_packets_nb_ptr != 0 && rcv_packets_ts_ptr != 0) {
        rcv_packets_nb_inter = *rcv_packets_nb_ptr;
        rcv_packets_ts_inter = bpf_ktime_get_ns() - *rcv_packets_ts_ptr;
        
        if (rcv_packets_ts_inter < LEGAL_DIFF_TIMESTAMP_PACKETS) {  rcv_packets_nb_inter++;  }
        else {  rcv_packets_nb_inter = 0;  }

        if (rcv_packets_nb_inter > MAX_NB_PACKETS) {
            detectionPacket.nb_ddos_packets = rcv_packets_nb_inter;
            events.perf_submit(ctx, &detectionPacket, sizeof(detectionPacket));
        }
    }
    rcv_packets_ts_inter = bpf_ktime_get_ns();
    rcv_packets.update(&rcv_packets_nb_index, &rcv_packets_nb_inter);
    rcv_packets.update(&rcv_packets_ts_index, &rcv_packets_ts_inter);
    return 0;
}