"""alert_throttle.py - Cooldown/dedup logic so watch/guard don't spam repeat alerts."""
import json
import os
import time
from typing import Dict, Optional


class AlertThrottle:
    """Tracks last-fired time per (package, alert_kind) key and suppresses repeats
    within a cooldown window."""

    def __init__(self, cooldown_seconds: int = 1800, path: str = "reports/monitor/throttle_state.json") -> None:
        self.cooldown_seconds = cooldown_seconds
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._state = self._load()

    def _load(self) -> Dict[str, float]:
        if os.path.isfile(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def _save(self) -> None:
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._state, f, indent=2)

    def should_fire(self, package: str, kind: str) -> bool:
        key = f"{package}:{kind}"
        last = self._state.get(key)
        now = time.time()
        if last is None or (now - last) >= self.cooldown_seconds:
            self._state[key] = now
            self._save()
            return True
        return False
