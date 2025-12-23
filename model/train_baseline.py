#!/usr/bin/env python3
import json
import time
from pathlib import Path
import numpy as np
from sklearn.ensemble import IsolationForest
from subprocess import check_output

COLLECTOR = "collector/collect_metrics.py"
SAMPLES = 60           # number of samples to learn baseline
INTERVAL = 2           # seconds between samples
MODEL_PATH = "model/baseline_model.pkl"

def collect_sample():
    out = check_output(["python3", COLLECTOR], text=True)
    data = json.loads(out)
    return [
        data["cpu_percent"],
        data["mem_used_kb"],
        data["proc_count"],
    ]

def main():
    print(f"[+] Collecting {SAMPLES} baseline samples...")
    rows = []
    for i in range(SAMPLES):
        rows.append(collect_sample())
        time.sleep(INTERVAL)

    X = np.array(rows)

    print("[+] Training IsolationForest baseline model...")
    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    )
    model.fit(X)

    Path("model").mkdir(exist_ok=True)
    import joblib
    joblib.dump(model, MODEL_PATH)

    print(f"[+] Baseline model saved to {MODEL_PATH}")

if __name__ == "__main__":
    main()
