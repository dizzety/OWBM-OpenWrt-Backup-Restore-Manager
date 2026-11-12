"""Filesystem classification.

The point is to answer two questions without guessing: does this filesystem
survive a reboot, and can OWBM write to it.
"""

from __future__ import annotations

PERSISTENT_WRITABLE = frozenset(
    {"ext2", "ext3", "ext4", "f2fs", "xfs", "btrfs", "ubifs", "jffs2", "vfat", "exfat", "ntfs", "ntfs3"}
)
PERSISTENT_READONLY = frozenset({"squashfs", "cramfs", "erofs", "iso9660"})
RAM_BACKED = frozenset({"tmpfs", "ramfs"})
PSEUDO = frozenset(
    {
        "proc",
        "sysfs",
        "devtmpfs",
        "devpts",
        "cgroup",
        "cgroup2",
        "debugfs",
        "tracefs",
        "securityfs",
        "pstore",
        "bpf",
        "configfs",
        "fusectl",
        "mqueue",
        "hugetlbfs",
        "autofs",
        "efivarfs",
        "binfmt_misc",
        "rpc_pipefs",
        "nsfs",
    }
)

_DESCRIPTIONS = {
    "squashfs": "сжатый образ только для чтения (squashfs)",
    "ext4": "журналируемая ФС (ext4)",
    "ext3": "журналируемая ФС (ext3)",
    "ext2": "ФС ext2",
    "f2fs": "flash-friendly ФС (f2fs)",
    "ubifs": "ФС для NAND (ubifs)",
    "jffs2": "ФС для NAND (jffs2)",
    "overlay": "объединённая ФС (OverlayFS)",
    "tmpfs": "в оперативной памяти (tmpfs)",
    "ramfs": "в оперативной памяти (ramfs)",
    "vfat": "FAT (vfat)",
    "exfat": "exFAT",
    "ntfs": "NTFS",
    "xfs": "XFS",
    "btrfs": "btrfs",
}


def is_persistent(fstype: str) -> bool:
    return fstype in PERSISTENT_WRITABLE


def is_ram(fstype: str) -> bool:
    return fstype in RAM_BACKED


def is_pseudo(fstype: str) -> bool:
    return fstype in PSEUDO


def classify(fstype: str) -> str:
    if fstype in PSEUDO:
        return "pseudo"
    if fstype == "overlay":
        return "overlay"
    if fstype in RAM_BACKED:
        return "ram"
    if fstype in PERSISTENT_READONLY:
        return "readonly"
    if fstype in PERSISTENT_WRITABLE:
        return "persistent"
    return "unknown"


def describe(fstype: str) -> str:
    return _DESCRIPTIONS.get(fstype, f"неизвестный тип ФС ({fstype or 'пусто'})")
