"""analyzer.py - Core APK analysis using androguard."""
import os
from typing import Dict, List

try:
    from androguard.core.bytecodes.apk import APK
except ImportError:
    from androguard.core.apk import APK  # type: ignore

from manifest_checks import ManifestChecker


class APKAnalysisError(Exception):
    """Raised when an APK cannot be parsed or is corrupted/invalid."""


class APKAnalyzer:
    """Wraps androguard to extract structural information from an APK."""

    def __init__(self, apk_path: str) -> None:
        if not os.path.isfile(apk_path):
            raise APKAnalysisError(f"File not found: {apk_path}")
        if os.path.getsize(apk_path) == 0:
            raise APKAnalysisError(f"File is empty: {apk_path}")

        self.apk_path = apk_path
        try:
            self.apk = APK(apk_path)
        except Exception as exc:
            raise APKAnalysisError(f"Failed to parse APK (corrupted or invalid): {exc}") from exc

        if not self.apk.is_valid_APK():
            raise APKAnalysisError("File is not a valid APK (missing AndroidManifest.xml)")

    def get_basic_info(self) -> Dict:
        size = os.path.getsize(self.apk_path)
        return {
            "package_name": self.apk.get_package() or "Unknown",
            "version_name": self.apk.get_androidversion_name() or "Unknown",
            "version_code": self.apk.get_androidversion_code() or "Unknown",
            "min_sdk": self.apk.get_min_sdk_version() or "Unknown",
            "target_sdk": self.apk.get_target_sdk_version() or "Unknown",
            "max_sdk": self.apk.get_max_sdk_version() or "Unknown",
            "file_size_bytes": size,
            "file_size_human": self._human_size(size),
            "app_name": self.apk.get_app_name() or "Unknown",
        }

    def get_permissions(self) -> List[str]:
        try:
            return list(self.apk.get_permissions())
        except Exception:
            return []

    def get_components(self) -> Dict[str, List[str]]:
        return {
            "activities": self._safe_list(self.apk.get_activities),
            "services": self._safe_list(self.apk.get_services),
            "receivers": self._safe_list(self.apk.get_receivers),
            "providers": self._safe_list(self.apk.get_providers),
        }

    def get_native_libraries(self) -> List[str]:
        try:
            return sorted({f for f in self.apk.get_files() if f.startswith("lib/") and f.endswith(".so")})
        except Exception:
            return []

    def get_dex_count(self) -> int:
        try:
            return len([f for f in self.apk.get_files() if f.endswith(".dex")])
        except Exception:
            return 0

    def get_dex_class_names(self) -> List[str]:
        try:
            from androguard.misc import AnalyzeAPK
            _, dex_list, _ = AnalyzeAPK(self.apk_path)
            dexes = dex_list if isinstance(dex_list, list) else [dex_list]
            names = []
            for d in dexes:
                names.extend(c.get_name() for c in d.get_classes())
            return names
        except Exception:
            return []

    def get_certificate_info(self) -> Dict:
        try:
            certs = self.apk.get_certificates()
            if not certs:
                return {"signed": False, "details": "No certificate found (unsigned APK)"}

            cert = certs[0]
            subject = str(cert.subject)
            issuer = str(cert.issuer)
            sig_algo = "Unknown"
            if hasattr(cert, "signature_algorithm_oid"):
                sig_algo = cert.signature_algorithm_oid._name

            return {
                "signed": True,
                "subject": subject,
                "issuer": issuer,
                "serial_number": str(cert.serial_number),
                "valid_from": str(cert.not_valid_before),
                "valid_to": str(cert.not_valid_after),
                "signature_algorithm": sig_algo,
                "self_signed": subject == issuer,
            }
        except Exception as exc:
            return {"signed": False, "details": f"Could not parse certificate: {exc}"}

    def get_manifest_flags(self, basic_info: Dict) -> Dict:
        try:
            checker = ManifestChecker(self.apk, basic_info.get("package_name", ""), basic_info.get("app_name", ""))
            return checker.check_all()
        except Exception:
            return {"flags": [], "flag_count": 0}

    @staticmethod
    def _safe_list(getter) -> List[str]:
        try:
            return list(getter())
        except Exception:
            return []

    @staticmethod
    def _human_size(size_bytes: int) -> str:
        size = float(size_bytes)
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"
