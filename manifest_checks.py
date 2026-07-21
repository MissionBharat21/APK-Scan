"""manifest_checks.py - AndroidManifest.xml red-flag detection."""
from typing import Dict, List

try:
    from androguard.core.bytecodes.apk import APK
except ImportError:
    from androguard.core.apk import APK  # type: ignore


class ManifestChecker:
    """Flags risky manifest configuration independent of permissions."""

    IMPERSONATION_TARGETS = [
        "whatsapp", "facebook", "instagram", "google", "gmail", "paypal",
        "netflix", "amazon", "bank", "chase", "wellsfargo", "playstore",
    ]

    def __init__(self, apk: "APK", package_name: str, app_name: str) -> None:
        self.apk = apk
        self.package_name = (package_name or "").lower()
        self.app_name = (app_name or "").lower()

    def check_all(self) -> Dict:
        flags: List[Dict] = []

        if self._is_debuggable():
            flags.append({
                "flag": "debuggable",
                "severity": "medium",
                "detail": "android:debuggable=\"true\" is set — should never ship in production",
            })

        if self._allows_backup() and self._has_sensitive_permissions():
            flags.append({
                "flag": "backup_with_sensitive_perms",
                "severity": "medium",
                "detail": "android:allowBackup=\"true\" combined with sensitive permissions "
                           "can let backed-up app data be extracted",
            })

        if self._allows_cleartext():
            flags.append({
                "flag": "cleartext_traffic",
                "severity": "low",
                "detail": "android:usesCleartextTraffic=\"true\" — network traffic may be unencrypted",
            })

        exported = self._unprotected_exported_components()
        if exported:
            flags.append({
                "flag": "unprotected_exported_components",
                "severity": "medium",
                "detail": f"{len(exported)} exported component(s) without a permission guard: "
                          f"{', '.join(exported[:5])}",
            })

        impersonation = self._check_impersonation()
        if impersonation:
            flags.append({
                "flag": "possible_impersonation",
                "severity": "high",
                "detail": f"Package/app name closely resembles a known brand: {impersonation}",
            })

        return {
            "flags": flags,
            "flag_count": len(flags),
        }

    def _is_debuggable(self) -> bool:
        try:
            app_attrs = self.apk.get_element("application", "debuggable")
            return str(app_attrs).lower() == "true"
        except Exception:
            return False

    def _allows_backup(self) -> bool:
        try:
            val = self.apk.get_element("application", "allowBackup")
            return val is None or str(val).lower() == "true"  # defaults to true
        except Exception:
            return False

    def _allows_cleartext(self) -> bool:
        try:
            val = self.apk.get_element("application", "usesCleartextTraffic")
            return str(val).lower() == "true"
        except Exception:
            return False

    def _has_sensitive_permissions(self) -> bool:
        sensitive = {
            "android.permission.READ_SMS", "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG", "android.permission.ACCESS_FINE_LOCATION",
        }
        try:
            return bool(sensitive & set(self.apk.get_permissions()))
        except Exception:
            return False

    def _unprotected_exported_components(self) -> List[str]:
        unprotected = []
        try:
            for tag in ("activity", "service", "receiver", "provider"):
                for node in self.apk.get_android_manifest_xml().getElementsByTagName(tag):
                    exported = node.getAttributeNS(
                        "http://schemas.android.com/apk/res/android", "exported"
                    )
                    permission = node.getAttributeNS(
                        "http://schemas.android.com/apk/res/android", "permission"
                    )
                    name = node.getAttributeNS(
                        "http://schemas.android.com/apk/res/android", "name"
                    )
                    if exported == "true" and not permission:
                        unprotected.append(name or "unnamed")
        except Exception:
            pass
        return unprotected

    def _check_impersonation(self) -> str:
        for target in self.IMPERSONATION_TARGETS:
            in_pkg = target in self.package_name
            in_app_name = target in self.app_name
            exact_pkg_family = self.package_name.startswith(f"com.{target}") or self.package_name == target
            if (in_pkg or in_app_name) and not exact_pkg_family:
                return target
        return ""
