"""notifier.py - Auto-generates and dispatches alert messages on detection."""
import json
import smtplib
import subprocess
from dataclasses import dataclass
from datetime import datetime
from email.mime.text import MIMEText
from typing import Dict, List

import requests


@dataclass
class AlertMessage:
    title: str
    body: str
    severity: str
    package: str
    timestamp: str

    def as_plain_text(self) -> str:
        return f"[{self.severity.upper()}] {self.title}\n{self.body}\nTime: {self.timestamp}"

    def as_dict(self) -> Dict:
        return {
            "title": self.title, "body": self.body, "severity": self.severity,
            "package": self.package, "timestamp": self.timestamp,
        }


class MessageBuilder:
    SEVERITY_EMOJI = {"critical": "🚨", "warning": "⚠️", "info": "ℹ️"}

    @staticmethod
    def from_behavior_change(package: str, changes: List[str]) -> AlertMessage:
        emoji = MessageBuilder.SEVERITY_EMOJI["warning"]
        title = f"{emoji} APK Sentinel: Behavior change in {package}"
        body = "\n".join(
            [f"App '{package}' has changed behavior since it was last checked.",
             "This can indicate a delayed-payload or trust-abuse pattern.", "",
             "Changes detected:"] + [f"  • {c}" for c in changes]
        )
        return AlertMessage(title, body, "warning", package, datetime.now().isoformat())

    @staticmethod
    def from_realtime_alert(package: str, kind: str, severity: str, detail_message: str) -> AlertMessage:
        emoji = MessageBuilder.SEVERITY_EMOJI.get(severity, "ℹ️")
        titles = {
            "listening_socket": f"{emoji} APK Sentinel: Possible backdoor in {package}",
            "beaconing": f"{emoji} APK Sentinel: C2 beaconing pattern in {package}",
            "connection_burst": f"{emoji} APK Sentinel: Connection burst from {package}",
        }
        title = titles.get(kind, f"{emoji} APK Sentinel: Alert for {package}")
        return AlertMessage(title, detail_message, severity, package, datetime.now().isoformat())

    @staticmethod
    def from_scan_result(package: str, risk_score: int, status: str, top_reasons: List[str]) -> AlertMessage:
        severity = "critical" if status == "HIGH RISK" else "warning"
        emoji = MessageBuilder.SEVERITY_EMOJI[severity]
        title = f"{emoji} APK Sentinel: {status} - {package}"
        body_lines = [f"Static scan risk score: {risk_score}/100 ({status})", ""]
        if top_reasons:
            body_lines.append("Key factors:")
            body_lines += [f"  • {r}" for r in top_reasons]
        return AlertMessage(title, "\n".join(body_lines), severity, package, datetime.now().isoformat())

    @staticmethod
    def test_message() -> AlertMessage:
        return AlertMessage(
            title="🧪 APK Sentinel: Test Alert",
            body="This is a test alert to verify your configured channels are working.",
            severity="info", package="test.package",
            timestamp=datetime.now().isoformat(),
        )


class AlertDispatcher:
    def __init__(self, config: Dict, logger) -> None:
        self.config = config.get("alerts", {})
        self.logger = logger

    def dispatch(self, message: AlertMessage) -> Dict[str, bool]:
        results: Dict[str, bool] = {}
        if self.config.get("termux_notify", False):
            results["termux_notify"] = self._send_termux_notify(message)
        if self.config.get("termux_sms", {}).get("enabled", False):
            results["termux_sms"] = self._send_termux_sms(message)
        if self.config.get("telegram", {}).get("enabled", False):
            results["telegram"] = self._send_telegram(message)
        if self.config.get("email", {}).get("enabled", False):
            results["email"] = self._send_email(message)
        if self.config.get("webhook", {}).get("enabled", False):
            results["webhook"] = self._send_webhook(message)
        self._append_local_log(message)
        return results

    def _send_termux_notify(self, message: AlertMessage) -> bool:
        try:
            subprocess.run(
                ["termux-notification", "--title", message.title,
                 "--content", message.body, "--priority", "high"],
                capture_output=True, timeout=5,
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            self.logger.warning(f"termux-notification failed: {exc}")
            return False

    def _send_termux_sms(self, message: AlertMessage) -> bool:
        number = self.config.get("termux_sms", {}).get("number")
        if not number:
            self.logger.warning("termux_sms enabled but no 'number' configured")
            return False
        try:
            subprocess.run(
                ["termux-sms-send", "-n", number, message.as_plain_text()[:1500]],
                capture_output=True, timeout=15,
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            self.logger.warning(f"termux-sms-send failed: {exc}")
            return False

    def _send_telegram(self, message: AlertMessage) -> bool:
        cfg = self.config.get("telegram", {})
        token, chat_id = cfg.get("bot_token"), cfg.get("chat_id")
        if not token or not chat_id:
            self.logger.warning("telegram enabled but bot_token/chat_id missing")
            return False
        try:
            resp = requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat_id, "text": message.as_plain_text()}, timeout=10,
            )
            return resp.status_code == 200
        except requests.RequestException as exc:
            self.logger.warning(f"telegram send failed: {exc}")
            return False

    def _send_email(self, message: AlertMessage) -> bool:
        cfg = self.config.get("email", {})
        required = ("smtp_host", "smtp_port", "username", "password", "to_address")
        if not all(cfg.get(k) for k in required):
            self.logger.warning("email enabled but SMTP config incomplete")
            return False
        try:
            msg = MIMEText(message.body)
            msg["Subject"] = message.title
            msg["From"] = cfg.get("from_address", cfg["username"])
            msg["To"] = cfg["to_address"]
            with smtplib.SMTP(cfg["smtp_host"], int(cfg["smtp_port"]), timeout=15) as server:
                server.starttls()
                server.login(cfg["username"], cfg["password"])
                server.sendmail(msg["From"], [cfg["to_address"]], msg.as_string())
            return True
        except (smtplib.SMTPException, OSError) as exc:
            self.logger.warning(f"email send failed: {exc}")
            return False

    def _send_webhook(self, message: AlertMessage) -> bool:
        cfg = self.config.get("webhook", {})
        url = cfg.get("url")
        if not url:
            self.logger.warning("webhook enabled but no url configured")
            return False
        style = cfg.get("style", "generic")
        if style == "discord":
            payload = {"content": message.as_plain_text()}
        elif style == "slack":
            payload = {"text": message.as_plain_text()}
        else:
            payload = message.as_dict()
        try:
            resp = requests.post(url, json=payload, timeout=10)
            return resp.status_code < 300
        except requests.RequestException as exc:
            self.logger.warning(f"webhook send failed: {exc}")
            return False

    def _append_local_log(self, message: AlertMessage) -> None:
        try:
            with open("alerts.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(message.as_dict()) + "\n")
        except OSError as exc:
            self.logger.warning(f"could not write alerts.jsonl: {exc}")
