"""monitor.py - Background behavioral monitoring for installed apps."""
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set

SUSPICIOUS_LOG_KEYWORDS = [
    "su", "root", "magisk", "DexClassLoader", "exec(", "chmod 777",
    "AccessibilityService", "overlay", "install_referrer", "device_admin",
]


def _run(cmd: List[str], timeout: int = 10) -> Optional[str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout if result.returncode == 0 else None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


@dataclass
class BehaviorSnapshot:
    timestamp: str
    package: str
    permissions: List[str] = field(default_factory=list)
    apk_path: Optional[str] = None
    apk_sha256: Optional[str] = None
    uid: Optional[str] = None
    remote_ips: List[str] = field(default_factory=list)
    suspicious_log_hits: List[str] = field(default_factory=list)
    capabilities_used: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return self.__dict__


class DeviceInspector:
    def __init__(self, package: str) -> None:
        self.package = package

    def get_installed_apk_path(self) -> Optional[str]:
        out = _run(["pm", "path", self.package])
        if not out:
            return None
        m = re.search(r"package:(.+)", out)
        return m.group(1).strip() if m else None

    def get_apk_sha256(self, apk_path: str) -> Optional[str]:
        if not apk_path or not os.path.isfile(apk_path):
            return None
        import hashlib
        h = hashlib.sha256()
        try:
            with open(apk_path, "rb") as f:
                for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return None

    def get_granted_permissions(self) -> List[str]:
        out = _run(["dumpsys", "package", self.package])
        if not out:
            return []
        perms = set()
        for line in out.splitlines():
            line = line.strip()
            if "granted=true" in line:
                m = re.match(r"([\w\.]+):\s+granted=true", line)
                if m:
                    perms.add(m.group(1))
            if line.startswith("android.permission.") and ":" not in line:
                perms.add(line)
        return sorted(perms)

    def get_uid(self) -> Optional[str]:
        out = _run(["dumpsys", "package", self.package])
        if not out:
            return None
        m = re.search(r"userId=(\d+)", out)
        return m.group(1) if m else None

    def get_remote_connections(self, uid: Optional[str]) -> List[str]:
        if not uid:
            return []
        ips: Set[str] = set()
        for proto_file in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(proto_file, "r") as f:
                    lines = f.readlines()[1:]
            except (OSError, PermissionError):
                continue
            for line in lines:
                parts = line.split()
                if len(parts) < 8 or parts[7] != uid:
                    continue
                remote = parts[2]
                ip_hex = remote.split(":")[0]
                try:
                    if len(ip_hex) == 8:
                        ip = ".".join(str(int(ip_hex[i:i + 2], 16)) for i in (6, 4, 2, 0))
                        if ip != "0.0.0.0":
                            ips.add(ip)
                except ValueError:
                    continue
        return sorted(ips)

    def scan_recent_logcat(self, lines: int = 500) -> List[str]:
        out = _run(["logcat", "-d", "-t", str(lines)])
        if not out:
            return []
        hits = set()
        lowered = out.lower()
        for kw in SUSPICIOUS_LOG_KEYWORDS:
            if kw.lower() in lowered and self.package.lower() in lowered:
                hits.add(kw)
        return sorted(hits)

    def snapshot(self) -> BehaviorSnapshot:
        apk_path = self.get_installed_apk_path()
        uid = self.get_uid()
        capabilities = []

        perms = self.get_granted_permissions()
        if perms:
            capabilities.append("permissions")

        apk_hash = self.get_apk_sha256(apk_path) if apk_path else None
        if apk_hash:
            capabilities.append("apk_hash")

        remote_ips = self.get_remote_connections(uid)
        if remote_ips:
            capabilities.append("network")

        log_hits = self.scan_recent_logcat()
        if log_hits:
            capabilities.append("logcat")

        return BehaviorSnapshot(
            timestamp=datetime.now().isoformat(), package=self.package,
            permissions=perms, apk_path=apk_path, apk_sha256=apk_hash, uid=uid,
            remote_ips=remote_ips, suspicious_log_hits=log_hits, capabilities_used=capabilities,
        )


class BehaviorHistory:
    def __init__(self, package: str, store_dir: str = "reports/monitor") -> None:
        self.package = package
        self.store_dir = store_dir
        os.makedirs(self.store_dir, exist_ok=True)
        self.path = os.path.join(self.store_dir, f"{package}.json")

    def load(self) -> List[Dict]:
        if not os.path.isfile(self.path):
            return []
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return []

    def append(self, snapshot: BehaviorSnapshot) -> None:
        history = self.load()
        history.append(snapshot.to_dict())
        history = history[-200:]
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)

    def diff_latest(self, snapshot: BehaviorSnapshot) -> Dict:
        history = self.load()
        if not history:
            return {"is_baseline": True, "changes": []}

        prev = history[-1]
        changes = []

        new_perms = set(snapshot.permissions) - set(prev.get("permissions", []))
        if new_perms:
            changes.append(f"New permissions granted: {', '.join(sorted(new_perms))}")

        if prev.get("apk_sha256") and snapshot.apk_sha256 and prev["apk_sha256"] != snapshot.apk_sha256:
            changes.append("APK file on disk has changed since last check (update or tampering)")

        new_ips = set(snapshot.remote_ips) - set(prev.get("remote_ips", []))
        if new_ips:
            changes.append(f"New remote IP destinations observed: {', '.join(sorted(new_ips))}")

        new_log_hits = set(snapshot.suspicious_log_hits) - set(prev.get("suspicious_log_hits", []))
        if new_log_hits:
            changes.append(f"New suspicious log activity: {', '.join(sorted(new_log_hits))}")

        return {"is_baseline": False, "changes": changes}
