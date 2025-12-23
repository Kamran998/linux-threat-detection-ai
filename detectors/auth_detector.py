#!/usr/bin/env python3
import argparse
import json
import re
import subprocess
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List, Deque, Tuple, Set

from engine.alerts import emit_alert

STATE_DIR = Path("state")
DEFAULT_STATE_FILE = STATE_DIR / "auth.state.json"
ALERT_LOG = "logs/alerts.log"

# --- SSH patterns ---
RE_SSH_FAIL = re.compile(r"(Failed password|authentication failure|Invalid user)", re.IGNORECASE)
RE_SSH_ACCEPT = re.compile(r"(Accepted password|Accepted publickey)", re.IGNORECASE)

RE_FROM_IP = re.compile(r"\bfrom\s+([0-9a-fA-F\.:]+)\b")
RE_FAIL_USER = re.compile(r"Failed password for (?:invalid user )?(\S+)\s+from\s+", re.IGNORECASE)

# --- Privileged / account management signals ---
USER_MGMT_WORDS = ("useradd", "usermod", "userdel", "passwd", "chage")
RE_USER_MGMT_MSG = re.compile(r"\b(useradd|usermod|userdel|passwd|chage)\b", re.IGNORECASE)
RE_SUDOERS = re.compile(r"(/etc/sudoers\b|/etc/sudoers\.d/)", re.IGNORECASE)

# Classic sudo command log:
# "sudo:  kamran : TTY=pts/0 ; PWD=/home/kamran ; USER=root ; COMMAND=/usr/bin/id"
RE_SUDO_CMDLINE = re.compile(r"^sudo:\s*(?P<user>\S+)\s*:\s*(?P<rest>.*)", re.IGNORECASE)
RE_SUDO_COMMAND = re.compile(r"\bCOMMAND=(.*)$", re.IGNORECASE)

# PAM sudo session lines (these are not the command itself):
# "pam_unix(sudo:session): session opened for user root(uid=0) by kamran(uid=1000)"
RE_PAM_SUDO_SESSION = re.compile(r"pam_unix\(sudo:session\):\s*session\s+(opened|closed)", re.IGNORECASE)
RE_PAM_BY_USER = re.compile(r"\bby\s+(\S+)\(uid=", re.IGNORECASE)


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


def _entry_epoch_seconds(e: Dict[str, Any]) -> float:
    ts_us = e.get("__REALTIME_TIMESTAMP") or e.get("_SOURCE_REALTIME_TIMESTAMP")
    try:
        if isinstance(ts_us, str) and ts_us.isdigit():
            return int(ts_us) / 1_000_000.0
    except Exception:
        pass
    return time.time()


def run_journalctl(unit: Optional[str], cursor: Optional[str], since: Optional[str], limit: int) -> Dict[str, Any]:
    cmd: List[str] = ["journalctl", "-q", "-o", "json", "--no-pager", "-n", str(limit)]

    # Only pass -u when unit is a real non-empty string
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

    return {"entries": entries, "new_cursor": new_cursor, "stderr": (proc.stderr or "").strip()}


def extract_message(e: Dict[str, Any]) -> str:
    msg = e.get("MESSAGE")
    if isinstance(msg, str):
        return msg
    return json.dumps(e)


# ---------------- Brute force tracker ----------------
class BruteForceTracker:
    def __init__(self, threshold: int = 5, window_sec: int = 120, cooldown_sec: int = 300):
        self.threshold = threshold
        self.window_sec = window_sec
        self.cooldown_sec = cooldown_sec

        self.fail_times: Dict[str, Deque[float]] = defaultdict(deque)
        self.usernames: Dict[str, Set[str]] = defaultdict(set)
        self.sample_msgs: Dict[str, Deque[str]] = defaultdict(lambda: deque(maxlen=5))
        self.last_alert_ts: Dict[str, float] = {}

    def observe_failure(self, ip: str, ts: float, username: Optional[str], message: str) -> bool:
        dq = self.fail_times[ip]
        dq.append(ts)
        if username:
            self.usernames[ip].add(username)
        self.sample_msgs[ip].append(message)

        cutoff = ts - self.window_sec
        while dq and dq[0] < cutoff:
            dq.popleft()

        last = self.last_alert_ts.get(ip, 0.0)
        if (ts - last) < self.cooldown_sec:
            return False

        if len(dq) >= self.threshold:
            self.last_alert_ts[ip] = ts
            return True

        return False

    def snapshot(self, ip: str) -> Dict[str, Any]:
        return {
            "ip": ip,
            "failure_count": len(self.fail_times.get(ip, [])),
            "window_sec": self.window_sec,
            "threshold": self.threshold,
            "usernames_seen": sorted(self.usernames.get(ip, set())),
            "sample_messages": list(self.sample_msgs.get(ip, [])),
        }


BF_TRACKER = BruteForceTracker(threshold=5, window_sec=120, cooldown_sec=300)


def _parse_ip_and_user(msg: str) -> Tuple[Optional[str], Optional[str]]:
    ip = None
    user = None

    m_ip = RE_FROM_IP.search(msg)
    if m_ip:
        ip = m_ip.group(1)

    m_user = RE_FAIL_USER.search(msg)
    if m_user:
        user = m_user.group(1)

    return ip, user


def _is_user_mgmt_event(ident: str, msg: str) -> bool:
    ident_l = (ident or "").lower()
    if ident_l in USER_MGMT_WORDS:
        return True
    # sometimes identifier looks like "useradd" already, or message contains it
    if any(w in ident_l for w in USER_MGMT_WORDS):
        return True
    if RE_USER_MGMT_MSG.search(msg):
        return True
    return False


def detect_events(entries: List[Dict[str, Any]], unit: str) -> int:
    count = 0

    for e in entries:
        msg = extract_message(e)
        msg_l = msg.lower()

        host = e.get("_HOSTNAME")
        pid = e.get("_PID")
        ident = e.get("SYSLOG_IDENTIFIER") or (unit or "")
        ts_epoch = _entry_epoch_seconds(e)

        # --- SSH failures ---
        if RE_SSH_FAIL.search(msg):
            ip, user = _parse_ip_and_user(msg)

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
                    "ip": ip or "",
                    "username": user or "",
                    "message": msg,
                },
                alert_log=ALERT_LOG,
                tags=["ssh", "auth", "failed_login"],
            )
            count += 1

            if ip:
                should_alert = BF_TRACKER.observe_failure(ip=ip, ts=ts_epoch, username=user, message=msg)
                if should_alert:
                    snap = BF_TRACKER.snapshot(ip)
                    emit_alert(
                        event_type="ssh_bruteforce_suspected",
                        severity="high",
                        source="auth",
                        summary="Possible SSH brute-force activity detected",
                        details={
                            "unit": unit,
                            "host": host,
                            "ip": snap["ip"],
                            "failure_count": snap["failure_count"],
                            "window_sec": snap["window_sec"],
                            "threshold": snap["threshold"],
                            "usernames_seen": snap["usernames_seen"],
                            "sample_messages": snap["sample_messages"],
                        },
                        alert_log=ALERT_LOG,
                        tags=["ssh", "auth", "bruteforce_suspected"],
                    )
                    count += 1

        # --- SSH success ---
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

        # --- Classic sudo command line (best signal; includes COMMAND=...) ---
        elif msg_l.startswith("sudo:"):
            m = RE_SUDO_CMDLINE.search(msg)
            actor = ""
            command = ""
            if m:
                actor = m.groupdict().get("user") or ""
                rest = m.groupdict().get("rest") or ""
                m2 = RE_SUDO_COMMAND.search(rest)
                if m2:
                    command = (m2.group(1) or "").strip()

            emit_alert(
                event_type="sudo_used",
                severity="medium",
                source="auth",
                summary="Sudo command execution detected",
                details={
                    "unit": unit,
                    "identifier": ident,
                    "pid": pid,
                    "host": host,
                    "actor": actor,
                    "command": command,
                    "message": msg,
                },
                alert_log=ALERT_LOG,
                tags=["sudo", "privilege", "command_exec"],
            )
            count += 1

        # --- PAM sudo session open/close (lower signal; no command) ---
        elif RE_PAM_SUDO_SESSION.search(msg):
            by_user = ""
            m = RE_PAM_BY_USER.search(msg)
            if m:
                by_user = m.group(1)

            emit_alert(
                event_type="sudo_session",
                severity="low",
                source="auth",
                summary="Sudo session open/close detected",
                details={
                    "unit": unit,
                    "identifier": ident,
                    "pid": pid,
                    "host": host,
                    "actor": by_user,
                    "message": msg,
                },
                alert_log=ALERT_LOG,
                tags=["sudo", "privilege", "session"],
            )
            count += 1

        # --- User/account management ---
        elif _is_user_mgmt_event(ident, msg):
            emit_alert(
                event_type="account_change",
                severity="high",
                source="auth",
                summary="User/account management activity detected",
                details={
                    "unit": unit,
                    "identifier": ident,
                    "pid": pid,
                    "host": host,
                    "message": msg,
                },
                alert_log=ALERT_LOG,
                tags=["account", "user_mgmt", "privilege"],
            )
            count += 1

        # --- Sudoers modification indicators ---
        elif RE_SUDOERS.search(msg):
            emit_alert(
                event_type="sudoers_modified",
                severity="high",
                source="auth",
                summary="Possible sudoers configuration change detected",
                details={
                    "unit": unit,
                    "identifier": ident,
                    "pid": pid,
                    "host": host,
                    "message": msg,
                },
                alert_log=ALERT_LOG,
                tags=["sudoers", "privilege", "config_change"],
            )
            count += 1

    return count


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--unit", default="sshd",
                    help="systemd unit to read (default: sshd). Use empty string to read all logs.")
    ap.add_argument("--state-file", default=str(DEFAULT_STATE_FILE), help="state file to store journal cursor")
    ap.add_argument("--since", default="10 minutes ago", help="used only on first run when no cursor exists")
    ap.add_argument("--limit", type=int, default=200, help="max journal lines per run")
    ap.add_argument("--once", action="store_true", help="run once and exit")
    ap.add_argument("--interval", type=int, default=10, help="seconds between runs")

    ap.add_argument("--bf-threshold", type=int, default=5)
    ap.add_argument("--bf-window", type=int, default=120)
    ap.add_argument("--bf-cooldown", type=int, default=300)

    args = ap.parse_args()

    BF_TRACKER.threshold = args.bf_threshold
    BF_TRACKER.window_sec = args.bf_window
    BF_TRACKER.cooldown_sec = args.bf_cooldown

    Path("logs").mkdir(exist_ok=True)
    state_path = Path(args.state_file)

    # Treat "" as None for journalctl -u
    unit = args.unit.strip() if isinstance(args.unit, str) else args.unit
    if unit == "":
        unit = None

    while True:
        state = load_state(state_path)
        cursor = state.get("cursor")

        res = run_journalctl(unit=unit, cursor=cursor, since=args.since, limit=args.limit)
        entries = res["entries"]
        new_cursor = res["new_cursor"]

        emitted = detect_events(entries, unit or "")

        if new_cursor:
            save_state(state_path, {"cursor": new_cursor, "ts": utc_ts()})

        print(json.dumps({
            "ts": utc_ts(),
            "component": "auth_detector",
            "unit": (unit or ""),
            "entries_read": len(entries),
            "alerts_emitted": emitted,
            "cursor_set": bool(new_cursor),
            "stderr": res.get("stderr", ""),
            "bf": {
                "threshold": BF_TRACKER.threshold,
                "window_sec": BF_TRACKER.window_sec,
                "cooldown_sec": BF_TRACKER.cooldown_sec,
            }
        }))

        if args.once:
            break

        time.sleep(args.interval)


if __name__ == "__main__":
    main()
