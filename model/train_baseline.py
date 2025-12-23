#!/usr/bin/env python3
import json
import time
from pathlib import Path
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from subprocess import check_output

COLLECTOR = "collector/collect_metrics.py"
SAMPLES = 60      # 60 samples
INTERVAL = 2      # every 2 seconds (~2 minutes total)
MODEL_PATH = "model/baseline_model.pkl"

def collect_sample():
    out = check_output(["python3", COLLECTOR], text=True)
    d = json.loads(out)
    return [d["cpu_percent"], d["mem_used_kb"], d["proc_count"]]

def main():
    print(f"[+] Collecting {SAMPLES} samples...")
    rows = []
    for i in range(SAMPLES):
        rows.append(collect_sample())
        if (i + 1) % 10 == 0:
            print(f"  collected {i+1}/{SAMPLES}")
        time.sleep(INTERVAL)

    X = np.array(rows)

    print("[+] Training IsolationForest baseline...")
    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42
    )
    model.fit(X)

    Path("model").mkdir(exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"[+] Saved model to {MODEL_PATH}")

if __name__ == "__main__":
    main()

