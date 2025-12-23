#!/usr/bin/env python3
import argparse
import json
import time
from datetime import datetime
from pathlib import Path
import joblib
import numpy as np
from subprocess import check_output

from engine.alerts import emit_alert
from engine.health import write_health

MODEL_PATH = "model/baseline_model.pkl"
COLLECTOR = "collector/collect_metrics.py"
ALERT_LOG = "logs/alerts.log"


def collect_live_metrics():
    out = check_output(["python3", COLLECTOR], text=True)
    d = json.loads(out)
    x = np.array([[float(d["cpu_percent"]), float(d["mem_used_kb"]), float(d["proc_count"])]])
    return d, x


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--threshold",
        type=float,
        default=-0.10,
        help="Alert if anomaly score is below this threshold (more negative = more anomalous)",
    )
    ap.add_argument("--once", action="store_true", help="Run once and exit")
    ap.add_argument(
        "--interval",
        type=int,
        default=10,
        help="Seconds between checks when running continuously",
    )
    args = ap.parse_args()

    if not Path(MODEL_PATH).exists():
        raise SystemExit(f"Missing model: {MODEL_PATH}. Run model/train_baseline.py first.")

    Path("logs").mkdir(exist_ok=True)
    model = joblib.load(MODEL_PATH)

    while True:
        try:
            raw, X = collect_live_metrics()

            # Higher is more normal. Lower (negative) is more anomalous.
            score = float(model.score_samples(X)[0])

            event = {
                "ts": datetime.utcnow().isoformat() + "Z",
                "score": round(score, 6),
                "threshold": args.threshold,
                "metrics": {
                    "cpu_percent": raw["cpu_percent"],
                    "mem_used_kb": raw["mem_used_kb"],
                    "proc_count": raw["proc_count"],
                },
                "anomalous": score < args.threshold,
            }

            # Always print to terminal so you can see it working
            print(json.dumps(event))

            # Only write to alerts log if anomalous (normalized schema)
            if event["anomalous"]:
                emit_alert(
                    event_type="ml_anomaly",
                    severity="medium",
                    source="ml",
                    summary="IsolationForest anomaly detected in host telemetry",
                    details={"metrics": event["metrics"]},
                    alert_log=ALERT_LOG,
                    score=score,
                    threshold=args.threshold,
                    tags=["telemetry", "isolation_forest"],
                )

            # Heartbeat after a successful loop
            write_health(status="ok")

            if args.once:
                break

            time.sleep(args.interval)

        except Exception as e:
            write_health(status="error", last_error=str(e))
            raise


if __name__ == "__main__":
    main()
