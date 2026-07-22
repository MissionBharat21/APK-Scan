"""report.py - Report generation (JSON, HTML, TXT, CSV) for APK Sentinel."""
import csv
import json
import os
from datetime import datetime
from typing import Dict


class ReportGenerator:
    """Generates scan reports in multiple formats."""

    def __init__(self, data: Dict, output_dir: str = "reports") -> None:
        self.data = data
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def _base_name(self) -> str:
        pkg = self.data.get("basic_info", {}).get("package_name", "unknown").replace(".", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{pkg}_{ts}"

    def to_json(self) -> str:
        path = os.path.join(self.output_dir, f"{self._base_name()}_report.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, default=str)
        return path

    def to_txt(self) -> str:
        d = self.data
        basic = d.get("basic_info", {})
        perms = d.get("permissions", {})
        strings = d.get("strings", {})
        risk = d.get("risk", {})
        cert = d.get("certificate", {})

        lines = [
            "=" * 50,
            "APK Sentinel Report",
            "=" * 50,
            f"Generated: {datetime.now().isoformat()}",
            "",
            f"Package:        {basic.get('package_name')}",
            f"Version:        {basic.get('version_name')} ({basic.get('version_code')})",
            f"Min SDK:        {basic.get('min_sdk')}",
            f"Target SDK:     {basic.get('target_sdk')}",
            f"File Size:      {basic.get('file_size_human')}",
            "",
            f"SHA256:         {d.get('hashes', {}).get('sha256')}",
            f"MD5:            {d.get('hashes', {}).get('md5')}",
            f"SHA1:           {d.get('hashes', {}).get('sha1')}",
            "",
            f"Certificate Signed:  {cert.get('signed')}",
            f"Certificate Subject: {cert.get('subject', 'N/A')}",
            f"Self-Signed:         {cert.get('self_signed', 'N/A')}",
            "",
            f"Total Permissions:      {perms.get('total_permissions')}",
            f"Dangerous Permissions:  {perms.get('dangerous_count')}",
        ]
        lines += [f"    - {p}" for p in perms.get("dangerous_permissions", [])]
        lines += ["", "Suspicious Combinations:"]
        lines += [f"    - {c}" for c in perms.get("suspicious_combinations", [])]
        lines += [
            "",
            f"Native Libraries: {len(d.get('native_libraries', []))}",
            f"DEX Count:        {d.get('dex_count')}",
            "",
            "Suspicious Strings Found:",
        ]
        lines += [f"    - {s}" for s in strings.get("suspicious_strings", [])]
        lines += ["", f"URLs Found:     {len(strings.get('urls', []))}"]
        lines += [f"    - {u}" for u in strings.get("urls", [])[:20]]
        lines += [f"IPs Found:      {len(strings.get('ip_addresses', []))}"]
        lines += [f"    - {ip}" for ip in strings.get("ip_addresses", [])[:20]]
        lines += [f"Domains Found:  {len(strings.get('domains', []))}", ""]

        obf = d.get("obfuscation", {})
        lines += [
            f"Obfuscation Detected: {obf.get('obfuscated')} (confidence {obf.get('confidence')}%)",
            "",
            f"Risk Score: {risk.get('score')}/100",
            f"Status:     {risk.get('status')}",
            "=" * 50,
        ]

        path = os.path.join(self.output_dir, f"{self._base_name()}_report.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return path

    def to_html(self) -> str:
        d = self.data
        basic = d.get("basic_info", {})
        perms = d.get("permissions", {})
        strings = d.get("strings", {})
        risk = d.get("risk", {})
        cert = d.get("certificate", {})
        components = d.get("components", {})

        status = risk.get("status", "LOW RISK")
        color = {"HIGH RISK": "#e74c3c", "MEDIUM RISK": "#f39c12", "LOW RISK": "#2ecc71"}.get(status, "#2ecc71")

        def _list_html(items):
            if not items:
                return "<li><em>None</em></li>"
            return "".join(f"<li>{self._esc(i)}</li>" for i in items)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>APK Sentinel Report - {self._esc(basic.get('package_name', ''))}</title>
<style>
  body {{ font-family:'Segoe UI',Arial,sans-serif; background:#0f1117; color:#e6e6e6; margin:0; padding:2rem; }}
  .container {{ max-width:900px; margin:0 auto; }}
  h1 {{ color:#4fc3f7; }}
  .card {{ background:#171a21; border-radius:8px; padding:1.25rem 1.5rem; margin-bottom:1.25rem; box-shadow:0 2px 6px rgba(0,0,0,0.4); }}
  .badge {{ display:inline-block; padding:0.4rem 1rem; border-radius:20px; font-weight:bold; background:{color}; color:#111; }}
  table {{ width:100%; border-collapse:collapse; }}
  td, th {{ padding:0.4rem 0.6rem; text-align:left; border-bottom:1px solid #2a2e38; }}
  ul {{ margin:0.3rem 0 0 1rem; padding:0; }}
  .score {{ font-size:2rem; font-weight:bold; color:{color}; }}
</style>
</head>
<body>
<div class="container">
  <h1>APK Sentinel Report</h1>
  <div class="card">
    <span class="badge">{self._esc(status)}</span>
    <div class="score">Risk Score: {risk.get('score')}/100</div>
  </div>
  <div class="card">
    <h2>App Information</h2>
    <table>
      <tr><th>Package</th><td>{self._esc(basic.get('package_name'))}</td></tr>
      <tr><th>Version</th><td>{self._esc(str(basic.get('version_name')))} ({self._esc(str(basic.get('version_code')))})</td></tr>
      <tr><th>Min SDK</th><td>{self._esc(str(basic.get('min_sdk')))}</td></tr>
      <tr><th>Target SDK</th><td>{self._esc(str(basic.get('target_sdk')))}</td></tr>
      <tr><th>File Size</th><td>{self._esc(basic.get('file_size_human'))}</td></tr>
      <tr><th>SHA256</th><td>{self._esc(d.get('hashes', {}).get('sha256'))}</td></tr>
      <tr><th>MD5</th><td>{self._esc(d.get('hashes', {}).get('md5'))}</td></tr>
      <tr><th>SHA1</th><td>{self._esc(d.get('hashes', {}).get('sha1'))}</td></tr>
    </table>
  </div>
  <div class="card">
    <h2>Certificate</h2>
    <table>
      <tr><th>Signed</th><td>{cert.get('signed')}</td></tr>
      <tr><th>Subject</th><td>{self._esc(cert.get('subject', 'N/A'))}</td></tr>
      <tr><th>Self-Signed</th><td>{cert.get('self_signed', 'N/A')}</td></tr>
    </table>
  </div>
  <div class="card">
    <h2>Permissions ({perms.get('total_permissions')} total, {perms.get('dangerous_count')} dangerous)</h2>
    <ul>{_list_html(perms.get('dangerous_permissions', []))}</ul>
    <h3>Suspicious Combinations</h3>
    <ul>{_list_html(perms.get('suspicious_combinations', []))}</ul>
  </div>
  <div class="card">
    <h2>Components</h2>
    <p>Activities: {len(components.get('activities', []))} | Services: {len(components.get('services', []))} |
       Receivers: {len(components.get('receivers', []))} | Providers: {len(components.get('providers', []))}</p>
  </div>
  <div class="card">
    <h2>Native Libraries ({len(d.get('native_libraries', []))}) / DEX Count ({d.get('dex_count')})</h2>
    <ul>{_list_html(d.get('native_libraries', []))}</ul>
  </div>
  <div class="card">
    <h2>Suspicious Strings</h2>
    <ul>{_list_html(strings.get('suspicious_strings', []))}</ul>
  </div>
  <div class="card">
    <h2>Network Indicators</h2>
    <h3>URLs ({len(strings.get('urls', []))})</h3>
    <ul>{_list_html(strings.get('urls', [])[:50])}</ul>
    <h3>IP Addresses ({len(strings.get('ip_addresses', []))})</h3>
    <ul>{_list_html(strings.get('ip_addresses', [])[:50])}</ul>
    <h3>Domains ({len(strings.get('domains', []))})</h3>
    <ul>{_list_html(strings.get('domains', [])[:50])}</ul>
  </div>
  <div class="card">
    <h2>Obfuscation</h2>
    <p>Detected: {d.get('obfuscation', {}).get('obfuscated')} (confidence {d.get('obfuscation', {}).get('confidence')}%)</p>
    <p>{self._esc(d.get('obfuscation', {}).get('reason', ''))}</p>
  </div>
</div>
</body>
</html>"""

        path = os.path.join(self.output_dir, f"{self._base_name()}_report.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path

    def to_csv(self) -> str:
        path = os.path.join(self.output_dir, "scan_summary.csv")
        basic = self.data.get("basic_info", {})
        risk = self.data.get("risk", {})
        perms = self.data.get("permissions", {})

        row = {
            "package_name": basic.get("package_name"),
            "version_name": basic.get("version_name"),
            "sha256": self.data.get("hashes", {}).get("sha256"),
            "dangerous_permissions": perms.get("dangerous_count"),
            "dex_count": self.data.get("dex_count"),
            "native_libraries": len(self.data.get("native_libraries", [])),
            "obfuscated": self.data.get("obfuscation", {}).get("obfuscated"),
            "risk_score": risk.get("score"),
            "status": risk.get("status"),
            "scanned_at": datetime.now().isoformat(),
        }

        file_exists = os.path.isfile(path)
        with open(path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(row.keys()))
            if not file_exists:
                writer.writeheader()
            writer.writerow(row)
        return path

    @staticmethod
    def _esc(value) -> str:
        if value is None:
            return ""
        return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
