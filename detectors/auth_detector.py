#!/usr/bin/env python3
import argparse
import json
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List

from engine.alerts import emit_alert

STATE_DIR = Path("state")
DEFAULT_STATE_FILE = STATE_DIR / "auth.state.json"
ALERT_LOG = "logs/alerts.log"

# Simple patterns (v1)
RE_SSH_FAIL = re.compile(r"(Failed password|authentication failure|Invalid user)", re.IGNORECASE)
RE_SSH_ACCEPT = re.compile(r"(Accepted password|Accepted publickey)", re.IGNORECASE)
RE_SUDO = re.compile(r"\bsudo\b", re.IGNORECASE)


def utc_ts() -> str:
    return datetime.utcnow().isoformat() + "Z"


def load_state(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {"cursor": None}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {"cursor": None}


def save_state(path: Path, state: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state))


def run_journalctl(unit: Optional[str], cursor: Optional[str], since: Optional[str], limit: int) -> Dict[str, Any]:
    """
    Returns dict with keys: entries (list), new_cursor (str|None)
    Uses journalctl JSON output and advances cursor using __CURSOR.
    """
    cmd: List[str] = ["journalctl", "--output=json", "--no-pager", f"-n{limit}"]

    if unit:
        cmd += ["-u", unit]

    if cursor:
        cmd += ["--after-cursor", cursor]
    elif since:
        cmd += ["--since", since]

    proc = subprocess.run(cmd, text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "journalctl failed")

    entries: List[Dict[str, Any]] = []
    new_cursor: Optional[str] = None

    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            entries.append(obj)
            c = obj.get("__CURSOR")
            if isinstance(c, str):
                new_cursor = c
        except Exception:
            continue

    return {"entries": entries, "new_cursor": new_cursor}


def extract_message(e: Dict[str, Any]) -> str:
    msg = e.get("MESSAGE")
    if isinstance(msg, str):
        return msg
    return json.dumps(e)


def detect_events(entries: List[Dict[str, Any]], unit: str) -> int:
    """
    Emits normalized alerts for relevant auth/security signals.
    Returns count emitted.
    """
    count = 0

    for e in entries:
        msg = extract_message(e)
        msg_l = msg.lower()

        host = e.get("_HOSTNAME")
        pid = e.get("_PID")
        ident = e.get("SYSLOG_IDENTIFIER") or unit

        if RE_SSH_FAIL.search(msg):
            emit_alert(
                event_type="ssh_auth_failed",
                severity="medium",
                source="auth",
                summary="SSH authentication failure detected",
                details={
                    "unit": unit,
                    "identifier": ident,
                    "pid": pid,
                    "host": host,
                    "message": msg,
                },
                alert_log=ALERT_LOG,
                tags=["ssh", "auth", "failed_login"],
            )
            count += 1

        elif RE_SSH_ACCEPT.search(msg):
            emit_alert(
                event_type="ssh_auth_success",
                severity="low",
                source="auth",
                summary="SSH login success detected",
                details={
                    "unit": unit,
                    "identifier": ident,
                    "pid": pid,
                    "host": host,
                    "message": msg,
                },
                alert_log=ALERT_LOG,
                tags=["ssh", "auth", "login_success"],
            )
            count += 1

        elif RE_SUDO.search(msg) and "sudo:" in msg_l:
            emit_alert(
                event_type="sudo_used",
                severity="medium",
                source="auth",
                summary="Sudo command usage detected",
                details={
                    "unit": unit,
                    "identifier": ident,
                    "pid": pid,
                    "host": host,
                    "message": msg,
                },
                alert_log=ALERT_LOG,
                tags=["sudo", "privilege"],
            )
            count += 1

    return count


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--unit", default="sshd", help="systemd unit to read (default: sshd)")
    ap.add_argument("--state-file", default=str(DEFAULT_STATE_FILE), help="state file to store journal cursor")
    ap.add_argument("--since", default="10 minutes ago", help="used only on first run when no cursor exists")
    ap.add_argument("--limit", type=int, default=200, help="max journal lines per run")
    ap.add_argument("--once", action="store_true", help="run once and exit")
    ap.add_argument("--interval", type=int, default=10, help="seconds between runs")
    args = ap.parse_args()

    Path("logs").mkdir(exist_ok=True)

    state_path = Path(args.state_file)

    while True:
        state = load_state(state_path)
        cursor = state.get("cursor")

        res = run_journalctl(unit=args.unit, cursor=cursor, since=args.since, limit=args.limit)
        entries = res["entries"]
        new_cursor = res["new_cursor"]

        emitted = detect_events(entries, args.unit)

        # advance cursor even if no events (prevents reprocessing)
        if new_cursor:
            save_state(state_path, {"cursor": new_cursor, "ts": utc_ts()})

        print(
            json.dumps(
                {
                    "ts": utc_ts(),
                    "component": "auth_detector",
                    "unit": args.unit,
                    "entries_read": len(entries),
                    "alerts_emitted": emitted,
                    "cursor_set": bool(new_cursor),
                }
            )
        )

        if args.once:
            break

        import time
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
