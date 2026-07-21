"""signatures.py - YARA-based signature scanning for APK Sentinel."""
import os
from typing import Dict, List, Optional

try:
    import yara
except ImportError:
    yara = None  # yara-python not installed; module degrades gracefully


class SignatureScanner:
    """Compiles and runs YARA rules against an APK's file contents."""

    def __init__(self, rules_dir: str = "rules") -> None:
        self.rules_dir = rules_dir
        self.rules = None
        self.available = False
        self.load_error: Optional[str] = None
        self._compile()

    def _compile(self) -> None:
        if yara is None:
            self.load_error = "yara-python is not installed"
            return
        if not os.path.isdir(self.rules_dir):
            self.load_error = f"Rules directory not found: {self.rules_dir}"
            return

        rule_files = {}
        for fname in os.listdir(self.rules_dir):
            if fname.endswith((".yar", ".yara")):
                key = os.path.splitext(fname)[0]
                rule_files[key] = os.path.join(self.rules_dir, fname)

        if not rule_files:
            self.load_error = f"No .yar/.yara files found in {self.rules_dir}"
            return

        try:
            self.rules = yara.compile(filepaths=rule_files)
            self.available = True
        except yara.Error as exc:
            self.load_error = f"Failed to compile YARA rules: {exc}"

    def scan_file(self, apk_path: str) -> Dict:
        """Scan the whole APK file (zip container) for YARA matches."""
        if not self.available:
            return {"available": False, "reason": self.load_error, "matches": []}

        try:
            matches = self.rules.match(apk_path, timeout=30)
        except yara.Error as exc:
            return {"available": False, "reason": f"YARA match error: {exc}", "matches": []}

        results = []
        for m in matches:
            results.append({
                "rule": m.rule,
                "description": m.meta.get("description", ""),
                "severity": m.meta.get("severity", "low"),
                "matched_strings": sorted({s.identifier for s in m.strings}) if hasattr(m, "strings") else [],
            })

        return {"available": True, "reason": None, "matches": results}

    @staticmethod
    def severity_score(matches: List[Dict]) -> int:
        """Map YARA severity meta to a 0-25 contribution for the risk engine."""
        weight = {"high": 10, "medium": 6, "low": 3}
        score = sum(weight.get(m.get("severity", "low"), 3) for m in matches)
        return min(25, score)
