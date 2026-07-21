"""cert_blocklist.py - Local blocklist of known-bad certificate fingerprints
and a lightweight trust allowlist for watch/guard, to cut false-positive noise.
"""
import json
import os
from typing import Dict, List, Set


class CertBlocklist:
    """Tracks certificate fingerprints (serial+subject hash) seen across scans
    and lets the user manually mark ones as known-bad."""

    def __init__(self, path: str = "cert_blocklist.json") -> None:
        self.path = path
        self._data = self._load()

    def _load(self) -> Dict:
        if os.path.isfile(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return {"blocked": [], "seen": {}}

    def _save(self) -> None:
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2)

    @staticmethod
    def fingerprint(cert_info: Dict) -> str:
        subject = cert_info.get("subject", "")
        serial = cert_info.get("serial_number", "")
        return f"{subject}|{serial}"

    def is_blocked(self, cert_info: Dict) -> bool:
        return self.fingerprint(cert_info) in self._data.get("blocked", [])

    def record_seen(self, cert_info: Dict, package_name: str) -> int:
        """Track how many distinct packages share this cert. Returns the count."""
        fp = self.fingerprint(cert_info)
        seen = self._data.setdefault("seen", {})
        packages = set(seen.get(fp, []))
        packages.add(package_name)
        seen[fp] = sorted(packages)
        self._save()
        return len(packages)

    def block(self, cert_info: Dict) -> None:
        fp = self.fingerprint(cert_info)
        if fp not in self._data["blocked"]:
            self._data["blocked"].append(fp)
            self._save()


class TrustAllowlist:
    """Packages/SHA256s the user has explicitly trusted, to silence watch/guard noise."""

    def __init__(self, path: str = "allowlist.json") -> None:
        self.path = path
        self._data = self._load()

    def _load(self) -> Dict:
        if os.path.isfile(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return {"packages": [], "sha256": []}

    def _save(self) -> None:
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2)

    def is_trusted_package(self, package: str) -> bool:
        return package in self._data.get("packages", [])

    def is_trusted_hash(self, sha256: str) -> bool:
        return sha256 in self._data.get("sha256", [])

    def add_package(self, package: str) -> None:
        if package not in self._data["packages"]:
            self._data["packages"].append(package)
            self._save()

    def add_hash(self, sha256: str) -> None:
        if sha256 not in self._data["sha256"]:
            self._data["sha256"].append(sha256)
            self._save()

    def list_trusted(self) -> Dict:
        return self._data
