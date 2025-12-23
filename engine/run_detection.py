#!/usr/bin/env python3
import argparse
import json
import time
from datetime import datetime
from pathlib import Path

from engine.health import write_health

# Import the two detectors as modules and call their internal logic
# We keep this light: call each detector once per loop.
from model import detect_anomalies as ml_mod
from detectors import auth_detector as auth_mod


def utc_ts() -> str:
    return datetime.utcnow().isoformat() + "Z"


def run_once_ml(threshold: float, alert_log: str) -> dict:
    """
    Runs ONE ML check and emits an alert if anomalous.
    Returns a small status dict.
    """
    # Load model lazily once and cache it on the module
    if getattr(ml_mod, "_CACHED_MODEL", None) is None:
        if not Path(ml_mod.MODEL_PATH).exists():
            raise RuntimeError(f"Missing model: {ml_mod.MODEL_PATH}. Run model/train_baseline.py first.")
        ml_mod._CACHED_MODEL = ml_mod.joblib.load(ml_mod.MODEL_PATH)

    model = ml_mod._CACHED_MODEL

    raw, X = ml_mod.collect_live_metrics()
    score = float(model.score_samples(X)[0])

    anomalous = score < threshold

    if anomalous:
        ml_mod.emit_alert(
            event_type="ml_anomaly",
            severity="medium",
            source="ml",
            summary="IsolationForest anomaly detected in host telemetry",
            details={
                "metrics": {
                    "cpu_percent": raw["cpu_percent"],
                    "mem_used_kb": raw["mem_used_kb"],
                    "proc_count": raw["proc_count"],
                }
            },
            alert_log=alert_log,
            score=score,
            threshold=threshold,
            tags=["telemetry", "isolation_forest"],
        )

    return {
        "score": round(score, 6),
        "threshold": threshold,
        "anomalous": anomalous,
        "metrics": {
            "cpu_percent": raw["cpu_percent"],
            "mem_used_kb": raw["mem_used_kb"],
            "proc_count": raw["proc_count"],
        },
    }


def run_once_auth(unit: str, state_file: str, since: str, limit: int) -> dict:
    """
    Runs ONE auth log check and emits alerts for any matching entries.
    Returns a small status dict.
    """
    Path("logs").mkdir(exist_ok=True)

    state_path = Path(state_file)
    state = auth_mod.load_state(state_path)
    cursor = state.get("cursor")

    res = auth_mod.run_journalctl(unit=unit, cursor=cursor, since=since, limit=limit)
    entries = res["entries"]
    new_cursor = res["new_cursor"]

    emitted = auth_mod.detect_events(entries, unit)

    if new_cursor:
        auth_mod.save_state(state_path, {"cursor": new_cursor, "ts": utc_ts()})

    return {
        "unit": unit,
        "entries_read": len(entries),
        "alerts_emitted": emitted,
        "cursor_set": bool(new_cursor),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=int, default=10, help="seconds between loops")
    ap.add_argument("--ml-threshold", type=float, default=-0.70, help="ML anomaly threshold (lower = more anomalous)")
    ap.add_argument("--alert-log", default="logs/alerts.log", help="JSONL alert log path")

    ap.add_argument("--auth-unit", default="sshd", help="systemd unit for auth logs (default: sshd)")
    ap.add_argument("--auth-state", default="state/auth.state.json", help="state file for auth cursor")
    ap.add_argument("--auth-since", default="5 minutes ago", help="used on first run when no cursor exists")
    ap.add_argument("--auth-limit", type=int, default=200, help="max auth log lines per run")

    ap.add_argument("--once", action="store_true", help="run once and exit")
    args = ap.parse_args()

    # Ensure dirs exist
    Path("logs").mkdir(exist_ok=True)
    Path("state").mkdir(exist_ok=True)

    while True:
        try:
            ml_status = run_once_ml(threshold=args.ml_threshold, alert_log=args.alert_log)
            auth_status = run_once_auth(
                unit=args.auth_unit,
                state_file=args.auth_state,
                since=args.auth_since,
                limit=args.auth_limit,
            )

            write_health(status="ok", last_error="")

            print(json.dumps({
                "ts": utc_ts(),
                "component": "runner",
                "status": "ok",
                "ml": ml_status,
                "auth": auth_status,
            }))

        except Exception as e:
            write_health(status="error", last_error=str(e))
            print(json.dumps({
                "ts": utc_ts(),
                "component": "runner",
                "status": "error",
                "error": str(e),
            }))

        if args.once:
            break

        time.sleep(args.interval)


if __name__ == "__main__":
    main()
