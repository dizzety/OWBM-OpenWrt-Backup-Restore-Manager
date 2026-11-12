"""OPKG (OpenWrt <= 23.x and apk-less builds) inventory parser.

The status file at /usr/lib/opkg/status uses Debian-like paragraphs:
``Package:``, ``Version:``, ``Architecture:``, ``Status: install user installed``.
"""

from __future__ import annotations

from typing import Dict, List

STATUS_PATH = "/usr/lib/opkg/status"
WORLD_PATH = "/etc/opkg/user-installed"
CONF_DIR = "/etc/opkg"

from .apk import PackageEntry  # shared shape


def parse_status(lines: List[str]) -> List[PackageEntry]:
    entries: List[PackageEntry] = []
    current: Dict[str, str] = {}

    def flush() -> None:
        if not current.get("Package"):
            return
        status = current.get("Status", "")
        if "installed" not in status or "not-installed" in status:
            return
        entries.append(
            PackageEntry(
                name=current["Package"],
                version=current.get("Version", ""),
                arch=current.get("Architecture", ""),
                description=current.get("Description", ""),
            )
        )

    for line in lines:
        if not line.strip():
            flush()
            current = {}
            continue
        if line.startswith(" ") or line.startswith("\t"):
            continue  # continuation of a multi-line field such as Description
        key, sep, value = line.partition(":")
        if sep:
            current.setdefault(key.strip(), value.strip())
    flush()
    entries.sort(key=lambda item: item.name)
    return entries


def parse_conf_files(lines: List[str]) -> List[str]:
    """Extract ``src`` repository lines from /etc/opkg/*.conf."""
    result: List[str] = []
    for line in lines:
        text = line.strip()
        if text.startswith(("src ", "src/", "src-gz ")):
            result.append(text)
    return result
