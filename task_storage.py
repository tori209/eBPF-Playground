#! /usr/bin/env python3

from bcc import BPF

# inet_listen 함수(즉, Listening Port 생성)의 실행 시간을 측정하는 코드.
# 이때 TASK_STORAGE는 Key값을 Task로 사용하는 BPF Map의 일종이다. (참고: https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_TASK_STORAGE/)
# 하단의 경우에는 Task를 Key로 하여 u64값을 저장한다.
# Log를 띄우려면 netcat -lvp [Port] 를 입력한다.
code = r"""
BPF_TASK_STORAGE(task_storage_map, __u64);

KFUNC_PROBE(inet_listen)
{
    __u64 ts = bpf_ktime_get_ns();

    task_storage_map.task_storage_get(bpf_get_current_task_btf(), &ts, BPF_LOCAL_STORAGE_GET_F_CREATE);

    bpf_trace_printk("inet_listen entry: store timestamp %lld", ts);
    return 0;
}

KRETFUNC_PROBE(inet_listen)
{
    __u64 *ts;

    ts = task_storage_map.task_storage_get(bpf_get_current_task_btf(), 0, 0);
    if (!ts) {  return 0;  }

    task_storage_map.task_storage_delete(bpf_get_current_task_btf());

    bpf_trace_printk("inet_listen exit: cost %lldus", (bpf_ktime_get_ns() - *ts) / 1000);
    return 0;
}
"""

b = BPF(text=code)
try:
    b.trace_print()
except KeyboardInterrupt:
    pass