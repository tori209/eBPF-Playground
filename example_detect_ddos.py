#! /usr/bin/env python3

from bcc import BPF
import ctypes as ct
import datetime

# Loads eBPF program
b = BPF(src_file="./example_detect_ddos.c")

# Attach kprobe to kernel function and sets detect_ddos as kprobe handler
b.attach_kprobe(event="ip_rcv", fn_name="detect_ddos")

class DetectionTimestamp(ct.Structure):
    _fields_ = [("nb_ddos_packets", ct.c_ulonglong)]

# Show message when ePBF starts
print("DDOS detector started ... Hit Ctrl-C to end!")

print("%-26s %-10s" % ("TIME(s)", "MESSAGE"))

def trigger_alert_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(DetectionTimestamp)).contents
    print("%-26s %s %ld" % (datetime.datetime.now(),
    "DDOS Attack => nb of packets up to now : ", event.nb_ddos_packets))

# loop with callback to trigger_alert_event
b["events"].open_perf_buffer(trigger_alert_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()