#!/usr/bin/env python3
import json
import socket
from datetime import datetime
from pathlib import Path
from typing import Optional

HEALTH_PATH = "logs/health.json"

def write_health(status: str = "ok", last_error: str = "", version: Optional[str] = None) -> None:
    Path("logs").mkdir(exist_ok=True)
    payload = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "host": socket.gethostname(),
        "status": status,
        "last_error": last_error,
    }
    if version:
        payload["version"] = version

    with open(HEALTH_PATH, "w") as f:
        json.dump(payload, f)
