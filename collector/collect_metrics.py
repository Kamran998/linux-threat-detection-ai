#!/usr/bin/env python3
import argparse
import csv
import json
import time
from datetime import datetime
from pathlib import Path
import os

def read_proc_stat():
    with open("/proc/stat", "r") as f:
        line = f.readline()
    parts = line.split()
    values = list(map(int, parts[1:8]))  # user nice system idle iowait irq softirq
    return values

def cpu_percent(interval=0.5):
    a = read_proc_stat()
    time.sleep(interval)
    b = read_proc_stat()

    idle_a = a[3] + a[4]
    idle_b = b[3] + b[4]
    nonidle_a = a[0] + a[1] + a[2] + a[5] + a[6]
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

    mem_total = int(info["MemTotal"].split()[0])
    mem_available = int(info["MemAvailable"].split()[0])
    mem_used = mem_total - mem_available
    return mem_total, mem_used, mem_available

def process_count():
    return sum(1 for name in os.listdir("/proc") if name.isdigit())

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None, help="Append metrics to CSV file (e.g., data/metrics.csv)")
    args = ap.parse_args()

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

    # Print JSON so you always see output
    print(json.dumps(record))

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        write_header = not out_path.exists()
        with out_path.open("a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(record.keys()))
            if write_header:
                writer.writeheader()
            writer.writerow(record)

if __name__ == "__main__":
    main()
