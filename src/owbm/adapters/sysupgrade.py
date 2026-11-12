"""sysupgrade capability detection.

``sysupgrade -b`` is the native OpenWrt config backup and ``sysupgrade -r``
restores it. Both are preferred over hand-rolled copying because they know the
device's own list of files to keep (/lib/upgrade/keep.d and friends).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

_SHORT_BACKUP = re.compile(r"(?:^|\s)-b(?:[\s,]|$)|--create-backup|--backup", re.MULTILINE)
_SHORT_RESTORE = re.compile(r"(?:^|\s)-r(?:[\s,]|$)|--restore-backup|--restore", re.MULTILINE)


@dataclass(frozen=True)
class SysupgradeInfo:
    path: str = ""
    available: bool = False
    supports_backup: bool = False
    supports_restore: bool = False
    notes: tuple = ()

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "available": self.available,
            "supports_backup": self.supports_backup,
            "supports_restore": self.supports_restore,
            "notes": list(self.notes),
        }


def analyze(path: str, help_lines: List[str]) -> SysupgradeInfo:
    """Derive flags from the binary path and its usage text.

    OpenWrt's sysupgrade always supports -b/-r; if the usage text cannot be read
    we still assume support but record it as an unverified note, which the
    restore planner treats as a warning rather than a blocker.
    """
    if not path:
        return SysupgradeInfo(
            available=False,
            notes=("Утилита sysupgrade не найдена: нативная резервная копия конфигурации недоступна.",),
        )
    notes: List[str] = []
    text = "\n".join(help_lines)
    if not help_lines:
        notes.append("Справка sysupgrade недоступна; поддержка -b/-r принята по умолчанию.")
    supports_backup = True
    supports_restore = True
    if help_lines:
        if not _SHORT_BACKUP.search(text):
            supports_backup = False
        if not _SHORT_RESTORE.search(text):
            supports_restore = False
    return SysupgradeInfo(
        path=path,
        available=True,
        supports_backup=supports_backup,
        supports_restore=supports_restore,
        notes=tuple(notes),
    )
