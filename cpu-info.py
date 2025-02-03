#! /usr/bin/env python3

from bcc import BPF
from time import sleep
from collections import defaultdict

# eBPF 프로그램 작성
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u64 delta_ns;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(start_time, u32);   // 프로세스 시작 시간 기록
BPF_PERF_OUTPUT(events);   // 사용자 공간으로 전송할 이벤트 정의

// 프로세스가 스케줄될 때 호출되는 tracepoint
RAW_TRACEPOINT_PROBE(sched_switch) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 now = bpf_ktime_get_ns();

    // 이전 프로세스 종료 시간 기록
    u64 *start = start_time.lookup(&pid);
    if (start != 0) {
        u64 delta = now - *start;

        struct data_t data = {};
        data.pid = pid;
        data.delta_ns = delta;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));
    }

    // 현재 프로세스의 시작 시간을 업데이트
    start_time.update(&pid, &now);
    return 0;
}
"""

# BPF 프로그램 로드
b = BPF(text=bpf_text)

# 이벤트 콜백 함수 정의
def print_event(cpu, data, size):
  event = b["events"].event(data)
  print("PID: %-6d COMM: %-16s CPU Time (ms): %.2f" % (event.pid, event.comm.decode('utf-8', 'replace'), event.delta_ns / 1e6))

# 이벤트 출력 설정
b["events"].open_perf_buffer(print_event)

print("Tracing CPU usage per process... Ctrl-C to end.")
try:
  while True:
    b.perf_buffer_poll()
    sleep(1)
except KeyboardInterrupt:
    print("Exiting...")
except Expection as e:
    print("Error:", e)
