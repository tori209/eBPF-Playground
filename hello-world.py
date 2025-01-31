#! /usr/bin/env python3

from bcc import BPF

text = """
/* 
    bcc를 통해 kprobe로 특정 함수에 붙을 경우, 반드시 kprobe__ Prefix를 붙여야 한다.
    반드시 첫 Param은 ptrace(uapi/linux/ptrace.h)의 pt_regs * 타입을 사용하지만, 안쓸거라서 지금은 상관 없다.
*/
int kprobe__sys_clone(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
"""

# prog = BPF(text=text)
prog = BPF(src_file="./hello-world.c")
try:
    prog.trace_print()
except KeyboardInterrupt:
    print("Keyboard Interrupt Catched. Finish Tracing.")
    pass
