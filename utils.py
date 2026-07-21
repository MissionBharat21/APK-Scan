"""utils.py - Shared utilities: logging, config, validation, discovery."""
import json
import logging
import os
from typing import Dict, List, Optional

DEFAULT_CONFIG: Dict = {
    "reports_dir": "reports",
    "max_file_size_gb": 3,
    "log_file": "apk_sentinel.log",
    "log_level": "INFO",
    "offline_mode": False,
    "watch_interval_seconds": 3600,
    "guard_interval_seconds": 10,
    "alert_cooldown_seconds": 1800,
    "yara": {"rules_dir": "rules"},
    "alerts": {
        "termux_notify": False,
        "termux_sms": {"enabled": False, "number": ""},
        "telegram": {"enabled": False, "bot_token": "", "chat_id": ""},
        "email": {
            "enabled": False, "smtp_host": "smtp.gmail.com", "smtp_port": 587,
            "username": "", "password": "", "from_address": "", "to_address": "",
        },
        "webhook": {"enabled": False, "url": "", "style": "generic"},
    },
}


def setup_logging(log_file: str = "apk_sentinel.log", level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("apk_sentinel")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    if not logger.handlers:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(fh)
    return logger


def load_config(config_path: str = "config.json") -> Dict:
    config = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    if os.path.isfile(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                user_config = json.load(f)
            _deep_merge(config, user_config)
        except (json.JSONDecodeError, OSError):
            pass
    return config


def _deep_merge(base: Dict, override: Dict) -> None:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def validate_apk_file(filepath: str, max_size_gb: float = 3.0) -> Optional[str]:
    if not os.path.exists(filepath):
        return f"File does not exist: {filepath}"
    if not os.path.isfile(filepath):
        return f"Not a file: {filepath}"
    if not filepath.lower().endswith(".apk"):
        return f"Not an .apk file: {filepath}"
    if os.path.getsize(filepath) == 0:
        return f"File is empty: {filepath}"

    size_gb = os.path.getsize(filepath) / (1024 ** 3)
    if size_gb > max_size_gb:
        return f"File exceeds max size of {max_size_gb}GB ({size_gb:.2f}GB)"

    return None


def find_apks_in_folder(folder: str) -> List[str]:
    apks = []
    for root, _dirs, files in os.walk(folder):
        for fname in files:
            if fname.lower().endswith(".apk"):
                apks.append(os.path.join(root, fname))
    return apks
