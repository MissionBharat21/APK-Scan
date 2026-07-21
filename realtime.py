"""realtime.py - Real-time network intrusion / C2 signal detection for a package."""
import json
import os
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Deque, Dict, List, Optional, Set, Tuple

TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
    "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
    "07": "CLOSE", "08": "CLOSE_WAIT", "0A": "LISTEN",
}


@dataclass
class ConnectionEvent:
    timestamp: float
    local_port: int
    remote_ip: str
    remote_port: int
    state: str


@dataclass
class Alert:
    timestamp: str
    severity: str
    kind: str
    message: str
    details: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return self.__dict__


class ConnectionReader:
    def __init__(self, uid: Optional[str]) -> None:
        self.uid = uid

    def read(self) -> List[ConnectionEvent]:
        if not self.uid:
            return []
        events = []
        now = time.time()
        for proto_file in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(proto_file, "r") as f:
                    lines = f.readlines()[1:]
            except (OSError, PermissionError):
                continue
            for line in lines:
                parts = line.split()
                if len(parts) < 8 or parts[7] != self.uid:
                    continue
                local, remote = parts[1], parts[2]
                state = TCP_STATES.get(parts[3], parts[3])
                local_port = int(local.split(":")[1], 16)
                remote_ip_hex, remote_port_hex = remote.split(":")
                remote_port = int(remote_port_hex, 16)
                remote_ip = self._parse_ip(remote_ip_hex)
                events.append(ConnectionEvent(now, local_port, remote_ip, remote_port, state))
        return events

    @staticmethod
    def _parse_ip(ip_hex: str) -> str:
        try:
            if len(ip_hex) == 8:
                return ".".join(str(int(ip_hex[i:i + 2], 16)) for i in (6, 4, 2, 0))
            return ip_hex
        except ValueError:
            return ip_hex


class RealtimeGuard:
    BEACON_WINDOW = 30 * 60
    BEACON_MIN_HITS = 4
    BEACON_JITTER_TOLERANCE = 0.25
    BURST_WINDOW = 60
    BURST_THRESHOLD = 8

    def __init__(self, package: str, uid: str, store_dir: str = "reports/monitor") -> None:
        self.package = package
        self.uid = uid
        self.reader = ConnectionReader(uid)
        self.store_dir = store_dir
        os.makedirs(store_dir, exist_ok=True)
        self.log_path = os.path.join(store_dir, f"{package}_realtime.jsonl")
        self.contact_history: Dict[Tuple[str, int], Deque[float]] = defaultdict(lambda: deque(maxlen=50))
        self.known_listen_ports: Set[int] = set()
        self.recent_new_ips: Deque[Tuple[str, float]] = deque()
        self.alerted_beacons: Set[Tuple[str, int]] = set()

    def _log_alert(self, alert: Alert) -> None:
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert.to_dict()) + "\n")

    def _check_listening(self, events: List[ConnectionEvent]) -> List[Alert]:
        alerts = []
        for ev in events:
            if ev.state == "LISTEN" and ev.local_port not in self.known_listen_ports:
                self.known_listen_ports.add(ev.local_port)
                alerts.append(Alert(
                    timestamp=datetime.now().isoformat(), severity="critical", kind="listening_socket",
                    message=f"App opened a LISTENING socket on port {ev.local_port} "
                             f"— possible backdoor/remote access capability",
                    details={"port": ev.local_port},
                ))
        return alerts

    def _check_beaconing(self, events: List[ConnectionEvent]) -> List[Alert]:
        alerts = []
        now = time.time()
        for ev in events:
            if ev.state != "ESTABLISHED" or not ev.remote_ip or ev.remote_ip == "0.0.0.0":
                continue
            key = (ev.remote_ip, ev.remote_port)
            hist = self.contact_history[key]
            if not hist or now - hist[-1] > 2:
                hist.append(now)
            recent = [t for t in hist if now - t <= self.BEACON_WINDOW]
            if len(recent) < self.BEACON_MIN_HITS or key in self.alerted_beacons:
                continue
            intervals = [recent[i + 1] - recent[i] for i in range(len(recent) - 1)]
            if not intervals:
                continue
            avg = sum(intervals) / len(intervals)
            if avg <= 0:
                continue
            variance_ok = all(abs(i - avg) / avg <= self.BEACON_JITTER_TOLERANCE for i in intervals)
            if variance_ok:
                self.alerted_beacons.add(key)
                alerts.append(Alert(
                    timestamp=datetime.now().isoformat(), severity="critical", kind="beaconing",
                    message=f"Regular beaconing detected to {ev.remote_ip}:{ev.remote_port} "
                             f"(~{avg:.0f}s interval, {len(recent)} contacts) — classic C2 check-in pattern",
                    details={"ip": ev.remote_ip, "port": ev.remote_port, "avg_interval_s": round(avg, 1)},
                ))
        return alerts

    def _check_burst(self, events: List[ConnectionEvent]) -> List[Alert]:
        alerts = []
        now = time.time()
        current_ips = {ev.remote_ip for ev in events if ev.state == "ESTABLISHED" and ev.remote_ip not in ("", "0.0.0.0")}
        for ip in current_ips:
            if not any(ip == seen_ip for seen_ip, _ in self.recent_new_ips):
                self.recent_new_ips.append((ip, now))
        while self.recent_new_ips and now - self.recent_new_ips[0][1] > self.BURST_WINDOW:
            self.recent_new_ips.popleft()
        if len(self.recent_new_ips) >= self.BURST_THRESHOLD:
            ips = sorted({ip for ip, _ in self.recent_new_ips})
            alerts.append(Alert(
                timestamp=datetime.now().isoformat(), severity="warning", kind="connection_burst",
                message=f"{len(ips)} distinct remote hosts contacted within {self.BURST_WINDOW}s "
                         f"— possible scanning, payload staging, or data exfiltration burst",
                details={"ips": ips},
            ))
            self.recent_new_ips.clear()
        return alerts

    def poll(self) -> List[Alert]:
        events = self.reader.read()
        alerts: List[Alert] = []
        alerts += self._check_listening(events)
        alerts += self._check_beaconing(events)
        alerts += self._check_burst(events)
        for a in alerts:
            self._log_alert(a)
        return alerts
