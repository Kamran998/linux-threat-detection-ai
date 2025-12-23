#!/usr/bin/env python3
import csv
from pathlib import Path
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

DATA_PATH = "data/metrics.csv"
MODEL_PATH = "model/baseline_model.pkl"

def load_csv(path):
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append([
                float(r["cpu_percent"]),
                float(r["mem_used_kb"]),
                float(r["proc_count"]),
            ])
    return np.array(rows)

def main():
    if not Path(DATA_PATH).exists():
        raise SystemExit(f"Missing dataset: {DATA_PATH}. Run the collector with --out first.")

    X = load_csv(DATA_PATH)
    if len(X) < 30:
        raise SystemExit(f"Not enough samples to train. Need 30+, have {len(X)}.")

    print(f"[+] Training on {len(X)} samples from {DATA_PATH}")

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
