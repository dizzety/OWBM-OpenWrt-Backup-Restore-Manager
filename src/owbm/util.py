"""Small shared utilities: names, sizes, atomic publish, clock sanity."""

from __future__ import annotations

import errno
import hashlib
import os
import re
import shutil
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, Optional

from .errors import OwbmError, fail

_SAFE_RE = re.compile(r"[^a-z0-9._-]+")


def safe_component(value: str, *, maxlen: int = 40, fallback: str = "device") -> str:
    """Reduce arbitrary text to a filesystem-, shell- and URL-safe component."""
    text = (value or "").strip().lower()
    text = _SAFE_RE.sub("-", text)
    text = text.strip("-._")
    text = text[:maxlen].strip("-._")
    return text or fallback


def utc_stamp(moment: Optional[datetime] = None) -> str:
    """UTC timestamp used in archive names: 2026-11-09T091500Z (sortable)."""
    moment = moment or datetime.now(timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")


def iso_utc(moment: Optional[datetime] = None) -> str:
    moment = moment or datetime.now(timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def human_size(size: int) -> str:
    value = float(max(0, size))
    for unit in ("Б", "КиБ", "МиБ", "ГиБ", "ТиБ"):
        if value < 1024 or unit == "ТиБ":
            if unit == "Б":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} ТиБ"


def parse_size(text: str) -> int:
    """Parse '512K', '10M', '2G', '1024' into bytes."""
    match = re.fullmatch(r"\s*(\d+)\s*([KkMmGgTt]?)[Bb]?\s*", text or "")
    if not match:
        raise fail("OWBM-E-CFG-002", key="размер", reason=f"ожидалось число с суффиксом K/M/G, получено {text!r}")
    value = int(match.group(1))
    factor = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}
    return value * factor[match.group(2).lower()]


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(chunk)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def sha256_stream(stream) -> str:
    digest = hashlib.sha256()
    for block in iter(lambda: stream.read(1 << 20), b""):
        digest.update(block)
    return digest.hexdigest()


def ensure_dir(path: Path, mode: int = 0o700) -> Path:
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    try:
        current = stat.S_IMODE(path.stat().st_mode)
        if current & 0o077:
            os.chmod(path, mode)
    except OSError:
        pass
    return path


def fsync_dir(path: Path) -> None:
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def atomic_publish(tmp: Path, final: Path, mode: int = 0o600) -> None:
    """Publish ``tmp`` as ``final`` without ever overwriting an existing file.

    Uses link(2) so the target appears atomically and creation fails if the name
    is taken. On filesystems without hard links (vfat/NTFS) falls back to a
    guarded rename, which is still non-destructive.
    """
    tmp = Path(tmp)
    final = Path(final)
    os.chmod(tmp, mode)
    try:
        os.link(tmp, final)
    except FileExistsError:
        raise fail("OWBM-E-STO-002", path=str(final))
    except OSError as exc:
        if exc.errno in (errno.EXDEV, errno.EPERM, errno.EOPNOTSUPP, errno.EMLINK, errno.ENOTSUP):
            if final.exists():
                raise fail("OWBM-E-STO-002", path=str(final))
            os.rename(tmp, final)
            os.chmod(final, mode)
            fsync_dir(final.parent)
            return
        raise
    os.unlink(tmp)
    fsync_dir(final.parent)


def free_bytes(path: Path) -> int:
    usage = shutil.disk_usage(str(path))
    return usage.free


def which(name: str) -> Optional[str]:
    return shutil.which(name)


def require_tools(names: list[str], *, code: str = "OWBM-E-SSH-001") -> None:
    if not names:
        return
    if len(names) == 1:
        if not which(names[0]):
            raise fail(code, tool=names[0], host="—", port="—")
        return
    missing = [n for n in names if not which(n)]
    if missing:
        raise fail(code, tool=missing[0], host="—", port="—")


def clock_sanity(moment: Optional[datetime] = None) -> Optional[str]:
    """Return a human warning if the local clock looks implausible."""
    moment = moment or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    if moment.year < 2020:
        return (
            "Часы компьютера показывают дату раньше 2020 года. "
            "Имя архива станет неверным; проверьте системное время."
        )
    if moment > datetime.now(timezone.utc) + timedelta(days=1):
        return (
            "Часы компьютера показывают дату в будущем. "
            "Сортировка архивов по дате будет неточной; проверьте системное время."
        )
    return None


def iter_files(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            yield Path(dirpath) / name


def is_secret_name(name: str) -> bool:
    lowered = name.lower()
    markers = ("password", "passwd", "psk", "secret", "token", "private", "authorized_keys", "shadow")
    return any(marker in lowered for marker in markers)


def looks_like_address(value: str) -> bool:
    """Heuristic: is this a host/IP rather than a profile name?"""
    if not value:
        return False
    if value.startswith(("-", ".")) or " " in value:
        return False
    if re.fullmatch(r"[0-9.]+", value) or re.fullmatch(r"[0-9a-fA-F:]+", value):
        return True
    return "." in value or ":" in value


def platform_summary() -> str:
    return f"{sys.platform} python{sys.version_info.major}.{sys.version_info.minor}"
