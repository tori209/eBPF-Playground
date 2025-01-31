#! /usr/bin/env python3

from bcc import BPF

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define BPF_LICENSE GPL

BPF_HASH(currsock, u32, struct sock *);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock * sk, struct sockaddr *uaddr, int addr_len) 
{
    u32 pid = bpf_get_current_pid_tgid();
    currsock.update(&pid, &sk);

    //bpf_trace_printk("%d\\n", addr_len);

    return 0;
}

int kretprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock * sk) {
    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid();

    struct sock ** skpp; // 애초에 Map에 저장을 sock**로 했기 때문.
    skpp = currsock.lookup(&pid);

    /* Untracked Socket */
    if (skpp == 0) {  return 0;  }

    /* Connection Failed */
    if (ret != 0) {
        currsock.delete(&pid);
        return 0;
    }

    struct sock * skp = *skpp;
    u32 saddr = 0, daddr = 0;
    u16 dport = 0;
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &(skp->__sk_common.skc_rcv_saddr));
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &(skp->__sk_common.skc_daddr));
    bpf_probe_read_kernel(&dport, sizeof(dport), &(skp->__sk_common.skc_dport));

    bpf_trace_printk("trace_tcp4connect %x %x %d \\n", saddr, daddr, dport);

    currsock.delete(&pid);

    return 0;
}

"""

b = BPF(text = bpf_text)

# print("%-6s %-12s %-16s %-16s %-4s" % ("PID", "COMM", "SADDR", "DADDR", "DPORT"))
print(f"{'PID':<6}{'COMM':<12}{'SADDR':<16}{'DADDR':<16}{'DPORT':<4}")

def inet_ntoa(addr):
    """
    Formatting Address to Human-Readable Format
    """
    dq = ''
    for i in range(0, 4):
        dq = dq + str(addr & 0xff)
        if (i != 3):
            dq = dq + '.'
        addr = addr >> 8
    return dq

while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        (_tag, saddr_hs, daddr_hs, dport_s) = msg.decode("utf-8").split(" ")
    except ValueError as e:
        print (e)
        continue
    if _tag != "trace_tcp4connect":
        continue

    print(f"{int(pid):<6}{task.decode("utf-8"):<12}{inet_ntoa(int(saddr_hs, 16)):<16}{inet_ntoa(int(daddr_hs, 16)):<16}{dport_s:<4}")
