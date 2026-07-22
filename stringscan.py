"""stringscan.py - String extraction & suspicious pattern detection."""
import re
import zipfile
from typing import Dict, List, Set

URL_REGEX = re.compile(rb"https?://[^\s\"'<>]{4,256}")
IP_REGEX = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
DOMAIN_REGEX = re.compile(
    rb"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    rb"(?:com|net|org|info|biz|xyz|top|club|ru|cn|io|me|tk|cc|co|app|online)\b"
)

SUSPICIOUS_STRINGS: List[str] = [
    "Runtime.exec",
    "su",
    "root",
    "magisk",
    "shell",
    "accessibility",
    "overlay",
    "install package",
    "dynamic loading",
    "DexClassLoader",
    "reflection",
    "PathClassLoader",
    "getRuntime",
    "chmod",
    "/system/bin",
    "busybox",
    "supersu",
]


class StringScanner:
    """Scans an APK's entries for suspicious strings, URLs, IPs and domains."""

    MAX_ENTRY_SIZE = 15 * 1024 * 1024

    def __init__(self, apk_path: str) -> None:
        self.apk_path = apk_path

    def _iter_readable_entries(self):
        with zipfile.ZipFile(self.apk_path, "r") as z:
            for info in z.infolist():
                if info.file_size == 0 or info.file_size > self.MAX_ENTRY_SIZE:
                    continue
                relevant = (
                    info.filename.endswith((".dex", ".xml", ".so", ".json", ".txt", ".properties"))
                    or "assets/" in info.filename
                    or "res/" in info.filename
                )
                if not relevant:
                    continue
                try:
                    yield info.filename, z.read(info.filename)
                except (zipfile.BadZipFile, RuntimeError, KeyError):
                    continue

    def scan(self) -> Dict:
        found_strings: Set[str] = set()
        urls: Set[str] = set()
        ips: Set[str] = set()
        domains: Set[str] = set()

        for _name, data in self._iter_readable_entries():
            lowered = data.lower()
            for s in SUSPICIOUS_STRINGS:
                if s.lower().encode() in lowered:
                    found_strings.add(s)

            urls.update(m.decode(errors="ignore") for m in URL_REGEX.findall(data))
            ips.update(m.decode(errors="ignore") for m in IP_REGEX.findall(data))
            domains.update(m.decode(errors="ignore") for m in DOMAIN_REGEX.findall(data))

        url_hosts = set()
        for u in urls:
            m = re.match(r"https?://([^/:\"'<> ]+)", u)
            if m:
                url_hosts.add(m.group(1))
        domains -= url_hosts

        return {
            "suspicious_strings": sorted(found_strings),
            "urls": sorted(urls)[:200],
            "ip_addresses": sorted(ips)[:200],
            "domains": sorted(domains)[:200],
        }

    def detect_obfuscation(self, dex_class_names: List[str]) -> Dict:
        """Heuristic obfuscation detection based on class/package name length."""
        if not dex_class_names:
            return {"obfuscated": False, "confidence": 0, "reason": "No class data available"}

        total = len(dex_class_names)
        short_names = 0
        short_pkgs = 0

        for name in dex_class_names:
            cleaned = name.strip(";").lstrip("L")
            simple = cleaned.rsplit("/", 1)[-1]
            if len(simple) <= 2:
                short_names += 1
            parts = cleaned.split("/")
            if any(len(p) <= 2 for p in parts[:-1] if p):
                short_pkgs += 1

        short_ratio = short_names / total
        pkg_ratio = short_pkgs / total
        score = int(min(100, (short_ratio * 0.7 + pkg_ratio * 0.3) * 100))
        obfuscated = score >= 40

        reason = (
            f"{short_ratio:.0%} of classes have very short (<=2 char) names, "
            f"{pkg_ratio:.0%} sit in short-named packages"
        )
        return {"obfuscated": obfuscated, "confidence": score, "reason": reason}
