"""Backup storage: unique names, no overwrites, honest listings.

Layout::

    <root>/2026/11/2026-11-09T091500Z_<label>_<uuid8>.owbm
    <root>/pre-restore/2026/11/....owbm
    <root>/.owbm-tmp/            # candidates and the lock live here

Nothing in this module ever deletes a published archive. Temp candidates older
than a day are removed on the next operation.
"""

from __future__ import annotations

import contextlib
import errno
import os
import shutil
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional

from . import archive
from .errors import fail
from .log import redact
from .util import atomic_publish, ensure_dir, free_bytes, parse_iso, safe_component, utc_stamp

SUFFIX = ".owbm"
TMP_DIRNAME = ".owbm-tmp"
PRE_RESTORE_DIRNAME = "pre-restore"
LOCK_NAME = "lock"
STALE_LOCK_SECONDS = 6 * 3600
STALE_TMP_SECONDS = 24 * 3600


@dataclass
class ArchiveInfo:
    path: Path
    name: str
    size: int
    mtime: float
    manifest: Optional[dict] = None
    error: Optional[str] = None
    mode: str = "backup"

    @property
    def valid(self) -> bool:
        return self.manifest is not None and self.error is None

    @property
    def created_utc(self) -> str:
        if self.manifest:
            return str(self.manifest.get("created_utc", ""))
        return datetime.fromtimestamp(self.mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    @property
    def sort_key(self) -> str:
        return self.created_utc or ""

    @property
    def device_label(self) -> str:
        if not self.manifest:
            return "?"
        device = self.manifest.get("device") or {}
        return str(device.get("label") or device.get("board_id") or device.get("hostname") or "?")

    @property
    def release(self) -> str:
        device = (self.manifest or {}).get("device") or {}
        return str(device.get("release") or "")

    @property
    def arch(self) -> str:
        device = (self.manifest or {}).get("device") or {}
        return str(device.get("arch") or "")

    @property
    def status(self) -> str:
        completeness = (self.manifest or {}).get("completeness") or {}
        return str(completeness.get("status") or "unknown")

    @property
    def components(self) -> List[str]:
        return [str(item.get("id")) for item in (self.manifest or {}).get("components") or []]

    @property
    def archive_id(self) -> str:
        return str((self.manifest or {}).get("archive_id") or "")


class ArchiveStore:
    def __init__(self, root: Path, *, logger=None) -> None:
        self.root = Path(root).expanduser()
        self.logger = logger

    # -- basics ------------------------------------------------------------
    def ensure(self) -> "ArchiveStore":
        try:
            ensure_dir(self.root, 0o700)
        except OSError as exc:
            raise fail("OWBM-E-STO-003", path=str(self.root))
        if not os.access(self.root, os.W_OK):
            raise fail("OWBM-E-STO-003", path=str(self.root))
        return self

    @property
    def tmp_dir(self) -> Path:
        return ensure_dir(self.root / TMP_DIRNAME, 0o700)

    def free_bytes(self) -> int:
        return free_bytes(self.root)

    def require_space(self, need: int) -> None:
        available = self.free_bytes()
        if available < need:
            from .util import human_size

            raise fail(
                "OWBM-E-STO-001",
                path=str(self.root),
                free=human_size(available),
                need=human_size(need),
            )

    # -- naming ------------------------------------------------------------
    def new_path(self, label: str, *, moment: Optional[datetime] = None, mode: str = "backup") -> Path:
        moment = moment or datetime.now(timezone.utc)
        stamp = utc_stamp(moment)
        slug = safe_component(label, maxlen=40)
        base = self.root
        if mode == "pre-restore":
            base = base / PRE_RESTORE_DIRNAME
        directory = base / moment.strftime("%Y") / moment.strftime("%m")
        ensure_dir(directory, 0o700)
        for _attempt in range(64):
            candidate = directory / f"{stamp}_{slug}_{uuid.uuid4().hex[:8]}{SUFFIX}"
            if not candidate.exists():
                return candidate
        raise fail("OWBM-E-STO-002", path=str(directory))

    def publish(self, candidate: Path, final: Path) -> Path:
        atomic_publish(candidate, final, mode=0o600)
        return final

    # -- locking -----------------------------------------------------------
    @contextlib.contextmanager
    def lock(self, timeout: int = 30) -> Iterator[None]:
        tmp = self.tmp_dir
        path = tmp / LOCK_NAME
        deadline = time.monotonic() + max(0, timeout)
        while True:
            try:
                fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                if self._lock_is_stale(path):
                    try:
                        path.unlink()
                    except OSError:
                        pass
                    continue
                if time.monotonic() >= deadline:
                    pid = self._lock_pid(path)
                    raise fail("OWBM-E-STO-004", path=str(self.root), pid=pid, lock=str(path))
                time.sleep(0.2)
                continue
            except OSError as exc:
                raise fail("OWBM-E-STO-003", path=str(tmp))
            try:
                os.write(fd, f"{os.getpid()} {int(time.time())}\n".encode())
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                yield
            finally:
                try:
                    path.unlink()
                except OSError:
                    pass
            return

    @staticmethod
    def _lock_pid(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8").split()[0]
        except (OSError, IndexError):
            return "?"

    def _lock_is_stale(self, path: Path) -> bool:
        try:
            age = time.time() - path.stat().st_mtime
        except OSError:
            return False
        if age > STALE_LOCK_SECONDS:
            return True
        try:
            pid = int(path.read_text(encoding="utf-8").split()[0])
        except (OSError, ValueError, IndexError):
            return age > 60
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        return False

    # -- housekeeping ------------------------------------------------------
    def cleanup_temp(self, max_age: int = STALE_TMP_SECONDS) -> List[Path]:
        removed: List[Path] = []
        tmp = self.root / TMP_DIRNAME
        if not tmp.is_dir():
            return removed
        now = time.time()
        for entry in tmp.iterdir():
            if entry.name == LOCK_NAME:
                continue
            try:
                age = now - entry.stat().st_mtime
            except OSError:
                continue
            if age < max_age:
                continue
            try:
                if entry.is_dir():
                    shutil.rmtree(entry, ignore_errors=True)
                else:
                    entry.unlink()
                removed.append(entry)
            except OSError:
                continue
        return removed

    # -- listing -----------------------------------------------------------
    def iter_archives(self) -> Iterator[Path]:
        if not self.root.is_dir():
            return
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(name for name in dirnames if name != TMP_DIRNAME)
            for name in sorted(filenames):
                if name.endswith(SUFFIX) or name.endswith(SUFFIX + ".age") or name.endswith(SUFFIX + ".gpg"):
                    yield Path(dirpath) / name

    def list(self) -> List[ArchiveInfo]:
        items: List[ArchiveInfo] = []
        for path in self.iter_archives():
            try:
                stat = path.stat()
            except OSError:
                continue
            info = ArchiveInfo(path=path, name=path.name, size=stat.st_size, mtime=stat.st_mtime)
            info.mode = "pre-restore" if PRE_RESTORE_DIRNAME in path.parts else "backup"
            if path.name.endswith(".age") or path.name.endswith(".gpg"):
                info.error = "зашифрованный архив: содержимое не индексируется"
            else:
                try:
                    data = archive.read_manifest(path)
                    info.manifest = data
                except Exception as exc:  # noqa: BLE001 - listing must never crash
                    info.error = redact(str(exc))
            items.append(info)
        items.sort(key=lambda item: (item.sort_key, item.mtime), reverse=True)
        return items

    def find(self, name: str) -> Optional[ArchiveInfo]:
        for item in self.list():
            if item.name == name:
                return item
        return None

    def latest(self) -> Optional[ArchiveInfo]:
        for item in self.list():
            if item.valid and item.mode == "backup":
                return item
        return None

    def stats(self) -> Dict[str, int]:
        items = self.list()
        return {
            "count": len(items),
            "valid": sum(1 for item in items if item.valid),
            "bytes": sum(item.size for item in items),
        }
