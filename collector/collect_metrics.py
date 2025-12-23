#!/usr/bin/env python3
import json
import time
from datetime import datetime

def read_proc_stat():
    # CPU usage snapshot from /proc/stat
    with open("/proc/stat", "r") as f:
        line = f.readline()
    parts = line.split()
    # parts: cpu user nice system idle iowait irq softirq steal guest guest_nice
    values = list(map(int, parts[1:8]))  # take first 7 fields
    return values

def cpu_percent(interval=1.0):
    a = read_proc_stat()
    time.sleep(interval)
    b = read_proc_stat()

    idle_a = a[3] + a[4]   # idle + iowait
    idle_b = b[3] + b[4]
    nonidle_a = a[0] + a[1] + a[2] + a[5] + a[6]  # user+nice+system+irq+softirq
    nonidle_b = b[0] + b[1] + b[2] + b[5] + b[6]

    total_a = idle_a + nonidle_a
    total_b = idle_b + nonidle_b

    totald = total_b - total_a
    idled = idle_b - idle_a

    if totald <= 0:
        return 0.0
    return round((totald - idled) / totald * 100.0, 2)

def mem_info():
    info = {}
    with open("/proc/meminfo", "r") as f:
        for line in f:
            k, v = line.split(":", 1)
            info[k.strip()] = v.strip()
    # Pull a few useful ones (kB)
    mem_total = int(info["MemTotal"].split()[0])
    mem_available = int(info["MemAvailable"].split()[0])
    mem_used = mem_total - mem_available
    return mem_total, mem_used, mem_available

def process_count():
    # Count numeric dirs in /proc
    import os
    return sum(1 for name in os.listdir("/proc") if name.isdigit())

def main():
    record = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "cpu_percent": cpu_percent(0.5),
        "proc_count": process_count(),
    }
    mem_total, mem_used, mem_avail = mem_info()
    record.update({
        "mem_total_kb": mem_total,
        "mem_used_kb": mem_used,
        "mem_avail_kb": mem_avail,
    })
    print(json.dumps(record))

if __name__ == "__main__":
    main()

