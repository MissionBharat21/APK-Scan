"""permissions.py - Android permission analysis for APK Sentinel."""
from typing import Dict, List, Set, Tuple

DANGEROUS_PERMISSIONS: Set[str] = {
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.CALL_PHONE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.DELETE_PACKAGES",
    "android.permission.WRITE_SETTINGS",
    "android.permission.WRITE_SECURE_SETTINGS",
    "android.permission.DISABLE_KEYGUARD",
    "android.permission.GET_ACCOUNTS",
    "android.permission.AUTHENTICATE_ACCOUNTS",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.BIND_VPN_SERVICE",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.READ_LOGS",
}

SUSPICIOUS_COMBINATIONS: List[Tuple[Set[str], str]] = [
    (
        {"android.permission.READ_SMS", "android.permission.INTERNET"},
        "Can read SMS and exfiltrate over network (SMS stealer pattern)",
    ),
    (
        {"android.permission.RECEIVE_SMS", "android.permission.SEND_SMS", "android.permission.INTERNET"},
        "Can intercept/send SMS and reach the network (OTP/2FA interception pattern)",
    ),
    (
        {"android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE"},
        "Overlay + Accessibility Service (classic banking trojan / phishing overlay pattern)",
    ),
    (
        {"android.permission.RECORD_AUDIO", "android.permission.INTERNET"},
        "Can record audio and exfiltrate over network (surveillance pattern)",
    ),
    (
        {"android.permission.CAMERA", "android.permission.INTERNET", "android.permission.ACCESS_FINE_LOCATION"},
        "Camera + location + network access (surveillance/spyware pattern)",
    ),
    (
        {"android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.INTERNET"},
        "Can download and silently install other APKs (dropper pattern)",
    ),
    (
        {"android.permission.READ_CONTACTS", "android.permission.INTERNET"},
        "Can exfiltrate the contact list over network",
    ),
    (
        {"android.permission.BIND_DEVICE_ADMIN", "android.permission.DISABLE_KEYGUARD"},
        "Device admin + keyguard disable (ransomware/lockscreen abuse pattern)",
    ),
]


class PermissionAnalyzer:
    """Analyzes a list of Android permissions for risk indicators."""

    def __init__(self, permission_list: List[str]) -> None:
        self.permissions: Set[str] = set(permission_list)

    def get_dangerous(self) -> List[str]:
        return sorted(self.permissions & DANGEROUS_PERMISSIONS)

    def get_suspicious_combinations(self) -> List[str]:
        found = []
        for combo, description in SUSPICIOUS_COMBINATIONS:
            if combo.issubset(self.permissions):
                found.append(description)
        return found

    def summary(self) -> Dict:
        return {
            "total_permissions": len(self.permissions),
            "dangerous_permissions": self.get_dangerous(),
            "dangerous_count": len(self.get_dangerous()),
            "suspicious_combinations": self.get_suspicious_combinations(),
        }
