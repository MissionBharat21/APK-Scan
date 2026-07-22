"""hashes.py - Hash calculation utilities for APK Sentinel."""
import hashlib
from typing import Dict


class HashCalculator:
    """Calculates SHA256, MD5 and SHA1 hashes for a file, memory-efficiently."""

    CHUNK_SIZE = 8 * 1024 * 1024  # 8MB chunks, safe for files up to several GB

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath

    def calculate_all(self) -> Dict[str, str]:
        """Calculate SHA256, MD5 and SHA1 in a single streaming pass."""
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()

        with open(self.filepath, "rb") as f:
            while True:
                chunk = f.read(self.CHUNK_SIZE)
                if not chunk:
                    break
                sha256.update(chunk)
                md5.update(chunk)
                sha1.update(chunk)

        return {
            "sha256": sha256.hexdigest(),
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
        }
