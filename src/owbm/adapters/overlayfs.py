"""OverlayFS specifics: upper layer location and whiteout path validation.

OverlayFS marks "deleted from the lower layer" with a character device 0:0 in
the upper layer. Such objects cannot be stored in a portable tar, so OWBM
records their paths and replays the deletions at restore time.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional

from . import mountinfo
from .mountinfo import MountEntry

WHITEOUT_MAJOR = 0
WHITEOUT_MINOR = 0


@dataclass(frozen=True)
class OverlayLayout:
    mountpoint: str
    upperdir: Optional[str]
    workdir: Optional[str]
    lowerdirs: tuple

    @property
    def has_upper(self) -> bool:
        return bool(self.upperdir)


def layout(mount: Optional[MountEntry]) -> Optional[OverlayLayout]:
    if mount is None or mount.fstype != "overlay":
        return None
    dirs = mountinfo.overlay_dirs(mount)
    return OverlayLayout(
        mountpoint=mount.mountpoint,
        upperdir=dirs["upperdir"],  # type: ignore[arg-type]
        workdir=dirs["workdir"],  # type: ignore[arg-type]
        lowerdirs=tuple(dirs["lowerdirs"]),  # type: ignore[arg-type]
    )


def is_whiteout(mode_char: str, major: int, minor: int) -> bool:
    return mode_char == "c" and major == WHITEOUT_MAJOR and minor == WHITEOUT_MINOR


def path_problem(path: str) -> Optional[str]:
    """Return a reason if the relative path is unsafe, else None."""
    if not path:
        return "пустой путь"
    if path.startswith("/"):
        return "абсолютный путь"
    if "\x00" in path or "\r" in path or "\n" in path or "\t" in path:
        return "управляющий символ в пути"
    if len(path) > 4096:
        return "слишком длинный путь"
    normalized = path
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized in (".", ""):
        return "пустой путь"
    parts = normalized.split("/")
    if any(part == ".." for part in parts):
        return "выход за пределы каталога"
    if any(part == "" for part in parts):
        return "пустой компонент пути"
    return None


def validate_whiteout_paths(paths: Iterable[str]) -> List[str]:
    """Return a list of human-readable problems (empty means safe)."""
    problems: List[str] = []
    seen = set()
    for raw in paths:
        path = raw.strip()
        if not path:
            problems.append("пустая строка в списке whiteout")
            continue
        reason = path_problem(path)
        if reason:
            problems.append(f"{path}: {reason}")
            continue
        if path in seen:
            problems.append(f"{path}: повторяющийся путь")
            continue
        seen.add(path)
    return problems
