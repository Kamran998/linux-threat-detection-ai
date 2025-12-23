#!/usr/bin/env python3
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, render_template, request

APP_ROOT = Path(__file__).resolve().parent.parent  # repo root
ALERTS_PATH = APP_ROOT / "logs" / "alerts.log"
HEALTH_PATH = APP_ROOT / "logs" / "health.json"

app = Flask(__name__)

def parse_utc(ts: str) -> Optional[datetime]:
    try:
        # expects ISO8601 with trailing Z
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts).astimezone(timezone.utc)
    except Exception:
        return None

def read_health() -> Dict[str, Any]:
    if not HEALTH_PATH.exists():
        return {"status": "unknown", "ts": None, "host": None, "last_error": "health.json not found"}
    try:
        with open(HEALTH_PATH, "r") as f:
            return json.load(f)
    except Exception as e:
        return {"status": "unknown", "ts": None, "host": None, "last_error": f"health.json parse error: {e}"}

def iter_alerts(limit: int = 2000) -> List[Dict[str, Any]]:
    if not ALERTS_PATH.exists():
        return []
    alerts: List[Dict[str, Any]] = []
    try:
        with open(ALERTS_PATH, "r") as f:
            # read last N lines without loading huge files forever
            lines = f.readlines()[-limit:]
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except Exception:
                continue
    except Exception:
        return []
    # newest first
    alerts.sort(key=lambda a: a.get("ts", ""), reverse=True)
    return alerts

def within_last_24h(alert: Dict[str, Any]) -> bool:
    ts = parse_utc(str(alert.get("ts", "")))
    if not ts:
        return False
    return ts >= datetime.now(timezone.utc) - timedelta(hours=24)

@app.route("/")
def index():
    health = read_health()
    alerts = iter_alerts()

    last_alert_ts = alerts[0].get("ts") if alerts else None
    alerts_24h = [a for a in alerts if within_last_24h(a)]
    high_24h = [a for a in alerts_24h if str(a.get("severity", "")).lower() in ("high", "critical")]

    # Determine "alive" if heartbeat is recent (<= 90 seconds old)
    alive = False
    health_ts = parse_utc(str(health.get("ts", ""))) if health.get("ts") else None
    if health_ts:
        alive = (datetime.now(timezone.utc) - health_ts) <= timedelta(seconds=90)

    return render_template(
        "index.html",
        health=health,
        alive=alive,
        alerts_24h=len(alerts_24h),
        high_24h=len(high_24h),
        last_alert_ts=last_alert_ts,
    )

@app.route("/alerts")
def alerts():
    severity = request.args.get("severity", "").strip().lower()
    source = request.args.get("source", "").strip().lower()
    event_type = request.args.get("event_type", "").strip().lower()
    q = request.args.get("q", "").strip().lower()

    rows = iter_alerts()

    def match(a: Dict[str, Any]) -> bool:
        if severity and str(a.get("severity", "")).lower() != severity:
            return False
        if source and str(a.get("source", "")).lower() != source:
            return False
        if event_type and str(a.get("event_type", "")).lower() != event_type:
            return False
        if q:
            blob = json.dumps(a).lower()
            if q not in blob:
                return False
        return True

    rows = [a for a in rows if match(a)]
    return render_template(
        "alerts.html",
        rows=rows[:500],
        severity=severity,
        source=source,
        event_type=event_type,
        q=q,
    )

if __name__ == "__main__":
    # Bind to localhost only (safe default). Use SSH port forward to view remotely.
    app.run(host="127.0.0.1", port=5000, debug=False)
