"""The .owbm container: a ZIP64 archive with a pinned, validated layout.

Why ZIP and not tar: the central directory lives at the end, so an interrupted
write is physically unreadable as a valid archive; single members can be read
without extracting everything (archive listing is cheap); every member carries a
CRC32; and Python's stdlib handles it on any Linux without external tools.

Payloads inside stay ``tar.gz`` because that is what the device can produce and
what selective restore needs to unpack piecewise.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import stat
import struct
import tarfile
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from . import MAX_READABLE_FORMAT_VERSION, FORMAT_VERSION
from .errors import OwbmError, fail
from .util import sha256_file

MANIFEST_NAME = "manifest.json"
CHECKSUMS_NAME = "checksums/SHA256SUMS"
FIXED_DATE = (1980, 1, 1, 0, 0, 0)
MAX_MEMBER_NAME = 512
MAX_MANIFEST_BYTES = 2 * 1024**2
MAX_CHECKSUMS_BYTES = 8 * 1024**2
MAX_METADATA_MEMBER_BYTES = 8 * 1024**2
MAX_ARCHIVE_MEMBERS = 50_000
MAX_CENTRAL_DIRECTORY_BYTES = 64 * 1024**2
MAX_TOTAL_UNCOMPRESSED = 64 * 1024**3
MAX_TAR_MEMBERS = 100_000
MAX_TAR_PATH_BYTES = 16 * 1024**2
MAX_TAR_MEMBER_NAME_BYTES = 4096
MAX_TAR_PATH_DEPTH = 64
MAX_TAR_UNCOMPRESSED_BYTES = 64 * 1024**3
MAX_TAR_STREAM_BYTES = MAX_TAR_UNCOMPRESSED_BYTES + 128 * 1024**2
_SAFE_NAME = None


class BoundedTarInfo(tarfile.TarInfo):
    """Reject oversized extended tar headers before tarfile reads them whole."""

    MAX_EXTENDED_HEADER_BYTES = 1024 * 1024
    MAX_EXTENDED_HEADER_COUNT = 10_000
    MAX_EXTENDED_HEADER_TOTAL_BYTES = 16 * 1024**2

    def _account_extended_header(self, tar, kind: str) -> None:
        count = getattr(tar, "_owbm_extended_header_count", 0) + 1
        total = getattr(tar, "_owbm_extended_header_bytes", 0) + self._block(self.size)
        if self.size > self.MAX_EXTENDED_HEADER_BYTES:
            raise tarfile.ReadError(f"{kind} tar header exceeds 1 MiB")
        if count > self.MAX_EXTENDED_HEADER_COUNT:
            raise tarfile.ReadError("too many extended tar headers")
        if total > self.MAX_EXTENDED_HEADER_TOTAL_BYTES:
            raise tarfile.ReadError("extended tar headers exceed 16 MiB in total")
        tar._owbm_extended_header_count = count
        tar._owbm_extended_header_bytes = total

    def _proc_pax(self, tar):
        self._account_extended_header(tar, "PAX")
        return super()._proc_pax(tar)

    def _proc_gnulong(self, tar):
        self._account_extended_header(tar, "GNU long-name")
        return super()._proc_gnulong(tar)


class _BoundedTarReader:
    """Count decompressed bytes while keeping gzip reads bounded."""

    def __init__(self, source, limit: int) -> None:
        self.source = source
        self.limit = limit
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = self.limit - self.bytes_read + 1
        if size == 0:
            return b""
        remaining = self.limit - self.bytes_read
        data = self.source.read(min(size, remaining + 1))
        if len(data) > remaining:
            raise tarfile.ReadError("decompressed tar stream exceeds safety limit")
        self.bytes_read += len(data)
        return data


@contextmanager
def open_tar_gz(path: Optional[Path] = None, *, fileobj=None):
    """Open gzip-compressed tar in streaming mode with bounded decompression."""
    if (path is None) == (fileobj is None):
        raise ValueError("provide exactly one of path or fileobj")
    source = gzip.open(path, "rb") if fileobj is None else gzip.GzipFile(fileobj=fileobj, mode="rb")
    bounded = _BoundedTarReader(source, MAX_TAR_STREAM_BYTES)
    try:
        with tarfile.open(fileobj=bounded, mode="r|", tarinfo=BoundedTarInfo) as tf:
            yield tf
        while bounded.read(64 * 1024):
            pass
    finally:
        source.close()


def bounded_tar_members(tf) -> Iterator[tarfile.TarInfo]:
    """Yield visible tar entries within aggregate count, path, and size limits."""
    count = 0
    total = 0
    path_bytes = 0
    for member in tf:
        count += 1
        total += max(member.size, 0)
        name_bytes = len(member.name.encode("utf-8", "replace"))
        path_bytes += name_bytes
        if name_bytes > MAX_TAR_MEMBER_NAME_BYTES:
            raise fail("OWBM-E-CHK-002", reason="имя элемента вложенного tar превышает 4 КиБ")
        if member.name.count("/") > MAX_TAR_PATH_DEPTH:
            raise fail("OWBM-E-CHK-002", reason="путь вложенного tar слишком глубоко вложен")
        if count > MAX_TAR_MEMBERS:
            raise fail("OWBM-E-CHK-002", reason="слишком много элементов во вложенном tar")
        if total > MAX_TAR_UNCOMPRESSED_BYTES:
            raise fail("OWBM-E-CHK-002", reason="вложенный tar превышает предел распаковки 64 ГиБ")
        if path_bytes > MAX_TAR_PATH_BYTES:
            raise fail("OWBM-E-CHK-002", reason="имена элементов во вложенном tar превышают предел 16 МиБ")
        yield member


def _zip_index_limits(path: Path) -> None:
    """Scan central-directory records before ZipFile materializes ZipInfo objects."""
    path = Path(path)
    file_size = path.stat().st_size
    tail_size = min(file_size, 22 + 65535)
    if tail_size < 22:
        raise zipfile.BadZipFile("not a ZIP file")
    with path.open("rb") as handle:
        handle.seek(file_size - tail_size)
        tail = handle.read(tail_size)
        offset = tail.rfind(b"PK\x05\x06")
        if offset < 0 or offset + 22 > len(tail):
            raise zipfile.BadZipFile("ZIP end record not found")
        comment_length = struct.unpack_from("<H", tail, offset + 20)[0]
        if offset + 22 + comment_length != len(tail):
            raise zipfile.BadZipFile("invalid ZIP end record")
        eocd_abs = file_size - tail_size + offset
        disk_entries, entries = struct.unpack_from("<HH", tail, offset + 8)
        central_size, central_offset = struct.unpack_from("<II", tail, offset + 12)
        central_end = eocd_abs
        locator_offset = offset - 20
        has_zip64_locator = (
            locator_offset >= 0 and tail[locator_offset:locator_offset + 4] == b"PK\x06\x07"
        )
        if (
            disk_entries == 0xFFFF or entries == 0xFFFF
            or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF
            or has_zip64_locator
        ):
            if not has_zip64_locator:
                raise zipfile.BadZipFile("ZIP64 locator not found")
            zip64_offset = struct.unpack_from("<Q", tail, locator_offset + 8)[0]
            locator_abs = file_size - tail_size + locator_offset
            fixed_start = locator_abs - 56
            if fixed_start < 0:
                raise zipfile.BadZipFile("truncated ZIP64 end record")
            handle.seek(zip64_offset)
            record = handle.read(56)
            record_start = zip64_offset
            if (len(record) < 56 or record[:4] != b"PK\x06\x06") and zip64_offset != fixed_start:
                # ZIP64 offsets in self-extracting archives may be relative to the ZIP data.
                handle.seek(fixed_start)
                record = handle.read(56)
                record_start = fixed_start
            if len(record) < 56 or record[:4] != b"PK\x06\x06":
                raise zipfile.BadZipFile("invalid ZIP64 end record")
            record_size = struct.unpack_from("<Q", record, 4)[0]
            if record_size < 44 or record_start + 12 + record_size != locator_abs:
                raise zipfile.BadZipFile("invalid ZIP64 end record size")
            entries = struct.unpack_from("<Q", record, 32)[0]
            central_size = struct.unpack_from("<Q", record, 40)[0]
            central_end = record_start
    if central_size > MAX_CENTRAL_DIRECTORY_BYTES:
        raise fail("OWBM-E-CHK-002", reason="индекс элементов архива превышает 64 МиБ")
    central_start = central_end - central_size
    if central_start < 0 or central_end > file_size:
        raise zipfile.BadZipFile("invalid central-directory bounds")

    actual_entries = 0
    remaining = central_size
    with path.open("rb") as handle:
        handle.seek(central_start)
        while remaining:
            if remaining < 4:
                raise zipfile.BadZipFile("truncated central-directory record")
            signature = handle.read(4)
            if signature == b"PK\x01\x02":
                if remaining < 46:
                    raise zipfile.BadZipFile("truncated central-directory entry")
                fixed = signature + handle.read(42)
                if len(fixed) != 46:
                    raise zipfile.BadZipFile("truncated central-directory entry")
                name_length, extra_length, comment_length = struct.unpack_from("<HHH", fixed, 28)
                if name_length > MAX_MEMBER_NAME:
                    raise fail("OWBM-E-CHK-003", path="<слишком длинное имя элемента>")
                record_length = 46 + name_length + extra_length + comment_length
                if record_length > remaining:
                    raise zipfile.BadZipFile("central-directory entry exceeds directory bounds")
                handle.seek(name_length + extra_length + comment_length, os.SEEK_CUR)
                remaining -= record_length
                actual_entries += 1
                if actual_entries > MAX_ARCHIVE_MEMBERS:
                    raise fail(
                        "OWBM-E-CHK-002",
                        reason=f"в архиве слишком много элементов (> {MAX_ARCHIVE_MEMBERS})",
                    )
            elif signature == b"PK\x05\x05":
                if remaining < 6:
                    raise zipfile.BadZipFile("truncated central-directory signature")
                size_bytes = handle.read(2)
                if len(size_bytes) != 2:
                    raise zipfile.BadZipFile("truncated central-directory signature")
                signature_size = struct.unpack("<H", size_bytes)[0]
                record_length = 6 + signature_size
                if record_length > remaining:
                    raise zipfile.BadZipFile("central-directory signature exceeds directory bounds")
                handle.seek(signature_size, os.SEEK_CUR)
                remaining -= record_length
            else:
                raise zipfile.BadZipFile("invalid central-directory record")
    if actual_entries != entries:
        raise zipfile.BadZipFile("central-directory entry count mismatch")


def open_zip(path: Path) -> zipfile.ZipFile:
    """Open an archive only after bounding central-directory memory use."""
    _zip_index_limits(Path(path))
    return zipfile.ZipFile(path)


@dataclass
class Member:
    name: str
    source: Optional[Path] = None
    data: Optional[bytes] = None
    compress: bool = False

    def __post_init__(self) -> None:
        if (self.source is None) == (self.data is None):
            raise ValueError("member needs exactly one of source/data")

    @property
    def size(self) -> int:
        if self.data is not None:
            return len(self.data)
        return Path(self.source).stat().st_size  # type: ignore[arg-type]

    def sha256(self) -> str:
        if self.data is not None:
            return hashlib.sha256(self.data).hexdigest()
        return sha256_file(Path(self.source))  # type: ignore[arg-type]


@dataclass
class Issue:
    code: str
    detail: str

    def __str__(self) -> str:
        return f"{self.code}: {self.detail}"


@dataclass
class VerifyReport:
    path: Path
    ok: bool = True
    issues: List[Issue] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    manifest: Optional[dict] = None
    members: int = 0
    payload_bytes: int = 0
    checksums_verified: int = 0

    def add(self, code: str, detail: str) -> None:
        self.issues.append(Issue(code, detail))
        self.ok = False

    def raise_first(self) -> None:
        if self.issues:
            issue = self.issues[0]
            context = {"reason": issue.detail}
            if issue.code == "OWBM-E-CHK-003":
                context = {"path": issue.detail}
            elif issue.code == "OWBM-E-CHK-004":
                kind, _, path = issue.detail.partition(": ")
                context = {"path": path or issue.detail, "kind": kind}
            elif issue.code == "OWBM-E-ARC-001":
                context = {"path": issue.detail}
            elif issue.code == "OWBM-E-CHK-001":
                context = {"member": issue.detail}
            elif issue.code == "OWBM-E-FMT-001":
                parts = issue.detail.split()
                context = {
                    "version": parts[0] if parts else "?",
                    "supported": parts[-1] if len(parts) > 1 else str(MAX_READABLE_FORMAT_VERSION),
                }
            raise OwbmError(issue.code, **context)


def check_member_name(name: str) -> Optional[str]:
    """Return a reason if the archive member name is unsafe, else None."""
    if not name:
        return "пустое имя"
    if len(name) > MAX_MEMBER_NAME:
        return "слишком длинное имя"
    if name.startswith("/") or name.startswith("\\"):
        return "абсолютный путь"
    if "\\" in name:
        return "обратный слэш в пути"
    if "\x00" in name or "\n" in name or "\r" in name or "\t" in name:
        return "управляющий символ в имени"
    parts = name.rstrip("/").split("/")
    if any(part in ("", ".", "..") for part in parts):
        return "недопустимый компонент пути"
    if parts[0] == "checksums" and len(parts) > 2:
        return "недопустимая глубина в checksums"
    return None


def _is_regular(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    kind = stat.S_IFMT(mode)
    return kind in (0, stat.S_IFREG)


def write_archive(path: Path, members: Iterable[Member], *, compresslevel: int = 6) -> Dict[str, str]:
    """Write members in order, then the checksum list. Returns {name: sha256}."""
    path = Path(path)
    checksums: Dict[str, str] = {}
    names = set()
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=compresslevel, allowZip64=True) as zf:
        for member in members:
            reason = check_member_name(member.name)
            if reason:
                raise fail("OWBM-E-CHK-003", path=member.name)
            if member.name in names:
                raise fail("OWBM-E-CHK-002", reason=f"повторяющееся имя элемента {member.name}")
            names.add(member.name)
            info = zipfile.ZipInfo(member.name, date_time=FIXED_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED if member.compress else zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            if member.data is not None:
                zf.writestr(info, member.data)
            else:
                with open(member.source, "rb") as src, zf.open(info, "w") as dst:  # type: ignore[arg-type]
                    shutil.copyfileobj(src, dst, 1 << 20)
            checksums[member.name] = member.sha256()
        lines = "".join(f"{digest}  {name}\n" for name, digest in sorted(checksums.items()))
        zf.writestr(CHECKSUMS_NAME, lines)
    return checksums


def _read_member_bounded(zf: zipfile.ZipFile, name: str, limit: int) -> bytes:
    """Read a small metadata member without trusting its declared size."""
    info = zf.getinfo(name)
    if info.file_size > limit:
        raise fail("OWBM-E-CHK-002", reason=f"элемент {name} превышает предел {limit} байт")
    with zf.open(info) as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise fail("OWBM-E-CHK-002", reason=f"элемент {name} превышает предел {limit} байт")
    return data


def read_manifest(path: Path) -> dict:
    """Read only a size-bounded manifest without extracting payloads."""
    path = Path(path)
    try:
        with open_zip(path) as zf:
            raw = _read_member_bounded(zf, MANIFEST_NAME, MAX_MANIFEST_BYTES)
    except KeyError:
        raise fail("OWBM-E-ARC-001", path=str(path))
    except (zipfile.BadZipFile, OSError) as exc:
        raise fail("OWBM-E-ARC-001", path=str(path), reason=str(exc))
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise fail("OWBM-E-CHK-002", reason="manifest.json не является корректным JSON")
    if not isinstance(data, dict):
        raise fail("OWBM-E-CHK-002", reason="manifest.json имеет неверную структуру")
    return data


def _parse_checksums(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            raise fail("OWBM-E-CHK-002", reason="строка SHA256SUMS имеет неверный формат")
        digest, name = parts[0], parts[1].lstrip("*").strip()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise fail("OWBM-E-CHK-002", reason="неверная контрольная сумма в SHA256SUMS")
        result[name] = digest
    return result


def verify_archive(path: Path, *, deep: bool = True, expect_format: int = FORMAT_VERSION) -> VerifyReport:
    """Full structural and checksum verification, without extracting anything."""
    path = Path(path)
    report = VerifyReport(path=path)
    if not path.is_file():
        report.add("OWBM-E-ARC-001", "файл не найден")
        return report
    if path.stat().st_size == 0:
        report.add("OWBM-E-ARC-001", "файл пуст")
        return report

    try:
        zf = open_zip(path)
    except OwbmError as exc:
        report.add(exc.code, exc.why)
        return report
    except (zipfile.BadZipFile, OSError) as exc:
        report.add("OWBM-E-ARC-001", f"контейнер не читается ({exc})")
        return report

    with zf:
        infos = zf.infolist()
        report.members = len(infos)
        names: List[str] = []
        for info in infos:
            reason = check_member_name(info.filename)
            if reason:
                report.add("OWBM-E-CHK-003", f"{reason}: {info.filename}")
                continue
            if not _is_regular(info):
                report.add("OWBM-E-CHK-004", f"не обычный файл: {info.filename}")
            names.append(info.filename)
        if len(set(names)) != len(names):
            report.add("OWBM-E-CHK-002", "повторяющиеся имена элементов")
        if report.issues:
            return report

        total = sum(info.file_size for info in infos)
        if total > MAX_TOTAL_UNCOMPRESSED:
            report.add("OWBM-E-CHK-002", f"суммарный объём распаковки превышает предел ({total} байт)")
            return report

        if MANIFEST_NAME not in names:
            report.add("OWBM-E-ARC-001", "отсутствует manifest.json")
            return report

        try:
            manifest_raw = _read_member_bounded(zf, MANIFEST_NAME, MAX_MANIFEST_BYTES)
            manifest = json.loads(manifest_raw.decode("utf-8"))
        except OwbmError as exc:
            report.add(exc.code, exc.why)
            return report
        except (UnicodeDecodeError, ValueError):
            report.add("OWBM-E-CHK-002", "manifest.json не является корректным JSON")
            return report
        if not isinstance(manifest, dict):
            report.add("OWBM-E-CHK-002", "manifest.json имеет неверную структуру")
            return report
        report.manifest = manifest

        version = manifest.get("format_version")
        if not isinstance(version, int) or version < 1:
            report.add("OWBM-E-CHK-002", "в манифесте нет корректной версии формата")
            return report
        if manifest.get("format") != "owbm":
            report.add("OWBM-E-ARC-001", "манифест принадлежит другому формату")
            return report
        supported = min(MAX_READABLE_FORMAT_VERSION, max(expect_format, 1))
        if version > supported:
            report.add("OWBM-E-FMT-001", f"{version} {supported}")
            return report

        if CHECKSUMS_NAME not in names:
            report.add("OWBM-E-CHK-002", "отсутствует checksums/SHA256SUMS")
            return report
        try:
            checksum_raw = _read_member_bounded(zf, CHECKSUMS_NAME, MAX_CHECKSUMS_BYTES)
            checksums = _parse_checksums(checksum_raw.decode("utf-8"))
        except OwbmError as exc:
            report.add(exc.code, exc.why)
            return report
        except UnicodeDecodeError:
            report.add("OWBM-E-CHK-002", "checksums/SHA256SUMS не читается")
            return report

        covered = set(checksums) | {CHECKSUMS_NAME}
        missing = [name for name in names if name not in covered]
        if missing:
            report.add("OWBM-E-CHK-002", f"элемент без контрольной суммы: {missing[0]}")
        unknown = [name for name in checksums if name not in names]
        if unknown:
            report.add("OWBM-E-CHK-002", f"контрольная сумма для отсутствующего элемента: {unknown[0]}")

        if not deep:
            return report

        for name in names:
            if name == CHECKSUMS_NAME:
                continue
            expected = checksums.get(name)
            if not expected:
                continue
            digest = hashlib.sha256()
            with zf.open(name) as handle:
                for block in iter(lambda: handle.read(1 << 20), b""):
                    digest.update(block)
            if digest.hexdigest() != expected:
                report.add("OWBM-E-CHK-001", name)
            else:
                report.checksums_verified += 1
            if name.startswith("payload/"):
                report.payload_bytes += zf.getinfo(name).file_size
    return report


def extract_member(path: Path, name: str, dest: Path) -> Path:
    """Extract a single member into ``dest`` (must be a dedicated directory)."""
    path = Path(path)
    dest = Path(dest)
    reason = check_member_name(name)
    if reason:
        raise fail("OWBM-E-CHK-003", path=name)
    target = dest / name
    target.parent.mkdir(parents=True, exist_ok=True)
    with open_zip(path) as zf:
        with zf.open(name) as src, open(target, "wb") as dst:
            shutil.copyfileobj(src, dst, 1 << 20)
    return target


def read_member(path: Path, name: str) -> bytes:
    """Read a small metadata member; large payloads must be streamed/extracted."""
    reason = check_member_name(name)
    if reason:
        raise fail("OWBM-E-CHK-003", path=name)
    try:
        with open_zip(path) as zf:
            return _read_member_bounded(zf, name, MAX_METADATA_MEMBER_BYTES)
    except KeyError:
        raise fail("OWBM-E-CHK-002", reason=f"в архиве нет элемента {name}")
    except (zipfile.BadZipFile, OSError) as exc:
        raise fail("OWBM-E-ARC-001", path=str(path), reason=str(exc))
