"""Parser for /proc/self/mountinfo.

Format (Linux): ``id parent major:minor root mountpoint options optional... - fstype source superopts``
Paths use octal escapes (``\\040`` for space and so on).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional

_ESCAPE_RE = re.compile(r"\\([0-7]{3})")


def unescape(text: str) -> str:
    return _ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 8)), text)


@dataclass(frozen=True)
class MountEntry:
    mount_id: int
    parent_id: int
    dev: str
    root: str
    mountpoint: str
    options: str
    fstype: str
    source: str
    super_options: str

    @property
    def writable(self) -> bool:
        return "rw" in self.options.split(",")

    def super_option_map(self) -> Dict[str, str]:
        result: Dict[str, str] = {}
        for item in self.super_options.split(","):
            if not item:
                continue
            key, sep, value = item.partition("=")
            result[key] = value if sep else ""
        return result


def parse_line(line: str) -> Optional[MountEntry]:
    parts = line.split(" ")
    if "-" not in parts:
        return None
    split_at = parts.index("-")
    if split_at < 6 or len(parts) < split_at + 3:
        return None
    left = parts[:split_at]
    right = parts[split_at + 1 :]
    try:
        mount_id = int(left[0])
        parent_id = int(left[1])
    except ValueError:
        return None
    return MountEntry(
        mount_id=mount_id,
        parent_id=parent_id,
        dev=left[2],
        root=unescape(left[3]),
        mountpoint=unescape(left[4]),
        options=left[5],
        fstype=right[0],
        source=unescape(right[1]),
        super_options=" ".join(right[2:]),
    )


def parse(lines: List[str]) -> List[MountEntry]:
    result: List[MountEntry] = []
    for line in lines:
        entry = parse_line(line)
        if entry is not None:
            result.append(entry)
    return result


def by_mountpoint(mounts: List[MountEntry], mountpoint: str) -> Optional[MountEntry]:
    best: Optional[MountEntry] = None
    for entry in mounts:
        if entry.mountpoint == mountpoint:
            best = entry
    return best


def mount_for_path(mounts: List[MountEntry], path: str) -> Optional[MountEntry]:
    """Deepest mount whose mountpoint is a prefix of ``path``."""
    best: Optional[MountEntry] = None
    best_len = -1
    for entry in mounts:
        point = entry.mountpoint
        if point == "/" or path == point or path.startswith(point.rstrip("/") + "/"):
            if len(point) > best_len:
                best = entry
                best_len = len(point)
    return best


def root_mount(mounts: List[MountEntry]) -> Optional[MountEntry]:
    return by_mountpoint(mounts, "/")


def overlay_mount(mounts: List[MountEntry]) -> Optional[MountEntry]:
    """Return the overlay mount backing ``/``, if any."""
    root = by_mountpoint(mounts, "/")
    if root is not None and root.fstype == "overlay":
        return root
    for entry in mounts:
        if entry.fstype == "overlay":
            return entry
    return None


def overlay_dirs(mount: MountEntry) -> Dict[str, object]:
    options = mount.super_option_map()
    lower = options.get("lowerdir")
    return {
        "upperdir": options.get("upperdir") or None,
        "workdir": options.get("workdir") or None,
        "lowerdirs": [item for item in (lower or "").split(":") if item],
    }
