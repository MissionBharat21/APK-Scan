"""risk.py - Malware risk scoring engine."""
from typing import Dict, Tuple


class RiskEngine:
    """Combines analysis signals into a 0-100 risk score with a LOW/MEDIUM/HIGH label."""

    def __init__(self, analysis: Dict) -> None:
        self.analysis = analysis

    def calculate(self) -> Tuple[int, str, Dict[str, int]]:
        breakdown: Dict[str, int] = {}

        dangerous_count = self.analysis.get("permissions", {}).get("dangerous_count", 0)
        breakdown["dangerous_permissions"] = min(20, dangerous_count * 2)

        combos = len(self.analysis.get("permissions", {}).get("suspicious_combinations", []))
        breakdown["suspicious_combinations"] = min(20, combos * 10)

        sus_strings = len(self.analysis.get("strings", {}).get("suspicious_strings", []))
        breakdown["suspicious_strings"] = min(15, sus_strings * 2)

        obf = self.analysis.get("obfuscation", {})
        breakdown["obfuscation"] = int(min(10, (obf.get("confidence", 0) / 100) * 10))

        cert = self.analysis.get("certificate", {})
        cert_score = 0
        if not cert.get("signed", True):
            cert_score = 8
        elif cert.get("self_signed"):
            cert_score = 4
        if self.analysis.get("cert_blocklisted"):
            cert_score = 15
        elif self.analysis.get("cert_shared_count", 0) > 3:
            cert_score = max(cert_score, 6)
        breakdown["certificate"] = min(15, cert_score)

        network_indicators = (
            len(self.analysis.get("strings", {}).get("ip_addresses", []))
            + len(self.analysis.get("strings", {}).get("urls", []))
        )
        breakdown["network_indicators"] = min(5, network_indicators // 3)

        yara_matches = self.analysis.get("yara", {}).get("matches", [])
        breakdown["yara_signatures"] = self._yara_score(yara_matches)

        manifest_flags = self.analysis.get("manifest_flags", {}).get("flags", [])
        breakdown["manifest_flags"] = self._manifest_score(manifest_flags)

        total = max(0, min(100, sum(breakdown.values())))

        if total >= 70:
            status = "HIGH RISK"
        elif total >= 35:
            status = "MEDIUM RISK"
        else:
            status = "LOW RISK"

        return total, status, breakdown

    @staticmethod
    def _yara_score(matches) -> int:
        weight = {"high": 8, "medium": 5, "low": 2}
        return min(20, sum(weight.get(m.get("severity", "low"), 2) for m in matches))

    @staticmethod
    def _manifest_score(flags) -> int:
        weight = {"high": 5, "medium": 3, "low": 1}
        return min(10, sum(weight.get(f.get("severity", "low"), 1) for f in flags))
