"""Filesystem classification.

The point is to answer two questions without guessing: does this filesystem
survive a reboot, and can OWBM write to it.
"""

from __future__ import annotations

from .. import i18n

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

_DESCRIPTION_KEYS = {
    "squashfs": "fs.squashfs",
    "ext4": "fs.ext4",
    "ext3": "fs.ext3",
    "ext2": "fs.ext2",
    "f2fs": "fs.f2fs",
    "ubifs": "fs.ubifs",
    "jffs2": "fs.jffs2",
    "overlay": "fs.overlay",
    "tmpfs": "fs.tmpfs",
    "ramfs": "fs.ramfs",
    "vfat": "fs.vfat",
    "exfat": "fs.exfat",
    "ntfs": "fs.ntfs",
    "ntfs3": "fs.ntfs",
    "xfs": "fs.xfs",
    "btrfs": "fs.btrfs",
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
    key = _DESCRIPTION_KEYS.get(fstype)
    if key:
        return i18n.tr(key)
    return i18n.tr("fs.unknown", fstype=fstype or i18n.tr("fs.empty"))
