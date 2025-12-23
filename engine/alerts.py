#!/usr/bin/env python3
import json
import socket
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_ALERT_LOG = "logs/alerts.log"

def utc_ts() -> str:
    return datetime.utcnow().isoformat() + "Z"

def emit_alert(
    *,
    event_type: str,
    severity: str,
    source: str,
    summary: str,
    details: Dict[str, Any],
    alert_log: str = DEFAULT_ALERT_LOG,
    score: Optional[float] = None,
    threshold: Optional[float] = None,
    tags: Optional[list] = None,
) -> Dict[str, Any]:
    """
    Append one normalized JSON alert to a JSONL file.
    """
    Path(alert_log).parent.mkdir(parents=True, exist_ok=True)

    event: Dict[str, Any] = {
        "ts": utc_ts(),
        "host": socket.gethostname(),
        "source": source,
        "event_type": event_type,
        "severity": severity,
        "summary": summary,
        "details": details,
    }

    if score is not None:
        event["score"] = round(float(score), 6)
    if threshold is not None:
        event["threshold"] = float(threshold)
    if tags:
        event["tags"] = tags

    with open(alert_log, "a") as f:
        f.write(json.dumps(event) + "\n")

    return event
