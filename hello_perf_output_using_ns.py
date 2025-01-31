#! /usr/bin/env python3

from bcc import BPF
from bcc.utils import printb
import sys, os
from stat import *

# 코드의 "DEV", "INO"는 하단의 for loop에 의해서 실제 DEV와 INO로 교체될 예정. 
prog = r"""
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

int hello (struct pt_regs * ctx) {
    struct data_t data = {};
    struct bpf_pidns_info ns = {};

    if (bpf_get_ns_current_pid_tgid(DEV, INO, &ns, sizeof(struct bpf_pidns_info))) {  return 0;  }
    data.pid = ns.pid;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

devinfo = os.stat("/proc/self/ns/pid")
for r in (("DEV", str(devinfo.st_dev)), ("INO", str(devinfo.st_ino))):
    prog = prog.replace(*r)

b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")

print(f"{"TIME(s)":<18} {"COMM":<16} {"PID":<6} {"MESSAGE"}")
start = 0

def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
        start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    printb(
        b"%-18.9f %-16s %-6d %s"
        % (time_s, event.comm, event.pid, b"Hello, perf_output!")
    )

b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()