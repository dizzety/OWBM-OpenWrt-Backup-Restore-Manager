"""Collectors: run one read-only remote script per category, stream the result.

Every payload is inspected before it is accepted: the tar must be readable, must
contain only regular files and safe relative paths. A payload that fails this
check aborts the backup instead of being published.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .. import archive
from ..discovery import DevicePassport
from ..errors import fail
from ..remote import BODY_MARKER, ProbeResult, build_script, stream_framed
from ..util import human_size

SAFE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9+._:~-]{0,99}\Z")

_PRELUDE = """set -u
PATH="/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
PATH="${OWBM_PATH_PREPEND:+${OWBM_PATH_PREPEND}:}${PATH}"
R="${OWBM_ROOT:-}"
"""


PACKAGE_CACHE_DIR = "/tmp/owbm-apk-cache"
MAX_TAR_MEMBERS = archive.MAX_TAR_MEMBERS
MAX_TAR_PATH_BYTES = archive.MAX_TAR_PATH_BYTES
MAX_TAR_UNCOMPRESSED_BYTES = archive.MAX_TAR_UNCOMPRESSED_BYTES
MAX_PACKAGE_CHUNK_UNCOMPRESSED_BYTES = 512 * 1024**2
MAX_PACKAGE_CHUNK_STREAM_BYTES = MAX_PACKAGE_CHUNK_UNCOMPRESSED_BYTES + 16 * 1024**2
MAX_PACKAGE_STAGING_BYTES = 2 * 1024**3
MAX_PACKAGE_STAGING_MEMBERS = 100_000
MAX_PACKAGE_STAGING_PATHS = 100_000
EXTRACT_DISK_RESERVE_BYTES = 64 * 1024**2
EXTRACT_INODE_RESERVE = 1024


@dataclass
class ExtractionBudget:
    max_members: int = MAX_TAR_MEMBERS
    max_paths: int = MAX_TAR_MEMBERS
    max_uncompressed_bytes: int = MAX_TAR_UNCOMPRESSED_BYTES
    members: int = 0
    paths: int = 0
    uncompressed_bytes: int = 0


def _drop_package_cache(client) -> None:
    """Remove the temporary index cache from the device; ignore failures."""
    script = _PRELUDE + 'rm -rf "$R' + PACKAGE_CACHE_DIR + '" 2>/dev/null || true\nprintf \'CLEAN=1\\n\'\n'
    try:
        client.run(script, timeout=30, allow_failure=True)
    except Exception:  # noqa: BLE001 - cleanup must never break a backup
        pass


@dataclass
class Collected:
    component_id: str
    path: Path
    members: int = 0
    uncompressed: int = 0
    excluded: Tuple[Dict[str, str], ...] = ()
    notes: str = ""
    extra: Dict[str, object] = field(default_factory=dict)


def inspect_tar(path: Path) -> Tuple[int, int]:
    """Count members and uncompressed size; reject unsafe payloads.

    Symlinks are legitimate in an overlay snapshot (busybox applets), so they are
    allowed — but a later member must never be written *through* a symlinked
    directory, which is the classic tar escape.
    """
    members = 0
    total = 0
    path_bytes = 0
    names: List[str] = []
    links: List[str] = []
    try:
        with archive.open_tar_gz(path) as tf:
            for member in archive.bounded_tar_members(tf):
                members += 1
                if members > MAX_TAR_MEMBERS:
                    raise fail("OWBM-E-CHK-002", reason="слишком много элементов во вложенном tar")
                path_bytes += len(member.name.encode("utf-8", "replace"))
                if path_bytes > MAX_TAR_PATH_BYTES:
                    raise fail("OWBM-E-CHK-002", reason="имена элементов во вложенном tar превышают предел 16 МиБ")
                total += max(member.size, 0)
                if total > MAX_TAR_UNCOMPRESSED_BYTES:
                    raise fail("OWBM-E-CHK-002", reason="вложенный tar превышает предел распаковки 64 ГиБ")
                name = member.name
                if name.startswith("/"):
                    raise fail("OWBM-E-CHK-003", path=name)
                parts = [part for part in name.split("/") if part not in ("", ".")]
                if any(part == ".." for part in parts):
                    raise fail("OWBM-E-CHK-003", path=name)
                if member.isfile() or member.isdir():
                    pass
                elif member.issym():
                    links.append("/".join(parts))
                else:
                    raise fail("OWBM-E-CHK-004", path=name, kind="специальный файл или жёсткая ссылка")
                names.append("/".join(parts))
    except tarfile.TarError as exc:
        raise fail("OWBM-E-CHK-002", reason=f"поток с устройства не является корректным tar.gz ({exc})")
    except OSError as exc:
        raise fail("OWBM-E-CHK-002", reason=f"не удалось прочитать поток с устройства ({exc})")
    if members == 0:
        raise fail("OWBM-E-CHK-002", reason="поток с устройства пуст")
    link_set = set(links)
    for name in names:
        parts = name.split("/")
        for index in range(1, len(parts)):
            if "/".join(parts[:index]) in link_set:
                raise fail("OWBM-E-CHK-003", path=name)
    return members, total


def extract_tar_safely(
    path: Path,
    dest: Path,
    *,
    max_uncompressed_bytes: int = MAX_TAR_UNCOMPRESSED_BYTES,
    budget: Optional[ExtractionBudget] = None,
) -> int:
    """Extract a payload within TAR, path-count, disk-space, and size limits."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    budget = budget or ExtractionBudget()
    members = 0
    extracted_files = 0
    total = 0
    path_bytes = 0
    with archive.open_tar_gz(path) as tf:
        for member in archive.bounded_tar_members(tf):
            members += 1
            path_bytes += len(member.name.encode("utf-8", "replace"))
            member_bytes = max(member.size, 0)
            total += member_bytes
            budget.members += 1
            budget.uncompressed_bytes += member_bytes
            if (
                members > MAX_TAR_MEMBERS or budget.members > budget.max_members
                or path_bytes > MAX_TAR_PATH_BYTES
            ):
                raise fail("OWBM-E-CHK-002", reason="вложенный tar превышает лимит элементов или имён")
            if (
                total > min(max_uncompressed_bytes, MAX_TAR_UNCOMPRESSED_BYTES)
                or budget.uncompressed_bytes > budget.max_uncompressed_bytes
            ):
                raise fail("OWBM-E-CHK-002", reason="вложенный tar превышает предел распаковки")
            name = member.name
            while name.startswith("./"):
                name = name[2:]
            if not name or name in (".", "./"):
                continue
            if name.startswith("/") or ".." in Path(name).parts:
                raise fail("OWBM-E-CHK-003", path=member.name)
            if not (member.isfile() or member.isdir()):
                raise fail("OWBM-E-CHK-004", path=member.name, kind="специальный файл или ссылка")
            target = dest / name
            try:
                target.parent.relative_to(dest)
            except ValueError:
                raise fail("OWBM-E-CHK-003", path=member.name)
            missing_parents = []
            parent = target.parent
            while parent != dest and not parent.exists():
                missing_parents.append(parent)
                parent = parent.parent
            target_existed = target.exists()
            new_paths = len(missing_parents) + (0 if target_existed else 1)
            if budget.paths + new_paths > budget.max_paths:
                raise fail("OWBM-E-CHK-002", reason="распаковка создаёт слишком много путей")
            try:
                free = shutil.disk_usage(dest).free
                stats = os.statvfs(dest)
            except OSError as exc:
                raise fail("OWBM-E-CHK-002", reason=f"не удалось проверить локальное место ({exc})")
            available_inodes = getattr(stats, "f_favail", stats.f_ffree)
            block_size = max(getattr(stats, "f_frsize", 0), 4096)
            required_bytes = member_bytes + new_paths * block_size
            if required_bytes and free - required_bytes < EXTRACT_DISK_RESERVE_BYTES:
                raise fail("OWBM-E-CHK-002", reason="недостаточно места для безопасной распаковки")
            if new_paths and available_inodes - new_paths < EXTRACT_INODE_RESERVE:
                raise fail("OWBM-E-CHK-002", reason="недостаточно свободных inode для безопасной распаковки")
            target.parent.mkdir(parents=True, exist_ok=True)
            budget.paths += len(missing_parents)
            if member.isdir():
                if not target_existed:
                    target.mkdir(exist_ok=True)
                    budget.paths += 1
                continue
            source = tf.extractfile(member)
            if source is None:
                continue
            with open(target, "wb") as out:
                for block in iter(lambda: source.read(1 << 20), b""):
                    out.write(block)
            os.chmod(target, 0o600)
            if not target_existed:
                budget.paths += 1
            extracted_files += 1
    return extracted_files


def repack_dir(source: Path, dest: Path) -> Tuple[int, int]:
    """Create a deterministic tar.gz from a directory tree."""
    source = Path(source)
    dest = Path(dest)
    members = 0
    total = 0
    with tarfile.open(dest, "w:gz", compresslevel=6) as tf:
        for dirpath, dirnames, filenames in os.walk(source):
            dirnames.sort()
            for name in sorted(filenames):
                path = Path(dirpath) / name
                if not path.is_file():
                    continue
                arcname = "./" + str(path.relative_to(source)).replace(os.sep, "/")
                info = tarfile.TarInfo(arcname)
                info.size = path.stat().st_size
                info.mtime = 0
                info.mode = 0o600
                info.uid = 0
                info.gid = 0
                info.uname = "root"
                info.gname = "root"
                with open(path, "rb") as handle:
                    tf.addfile(info, handle)
                members += 1
                total += info.size
    return members, total


# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------
CONFIG_SCRIPT = _PRELUDE + """
D=$(mktemp -d "${TMPDIR:-/tmp}/owbm-cfg.XXXXXX") || { printf 'ERROR=mktemp\\n' >&2; exit 5; }
trap 'rm -rf -- "$D"' EXIT INT TERM HUP
if command -v sysupgrade >/dev/null 2>&1; then
  if sysupgrade -b "$D/config.tar.gz" >/dev/null 2>&1 && [ -s "$D/config.tar.gz" ]; then
    printf 'METHOD=sysupgrade\\n'
    printf 'SIZE=%s\\n' "$(wc -c < "$D/config.tar.gz" | tr -d ' ')"
""" + f'    printf \'%s\\n\' "{BODY_MARKER}"\n' + """    cat "$D/config.tar.gz"
    exit 0
  fi
fi
if [ -d "$R/etc/config" ]; then
  printf 'METHOD=fallback\\n'
""" + f'  printf \'%s\\n\' "{BODY_MARKER}"\n' + """  tar -czf - -C "$R/etc" config 2>/dev/null
  exit 0
fi
printf 'ERROR=no-configuration\\n' >&2
exit 6
"""


def collect_configuration(client, dest: Path, passport: DevicePassport, logger=None) -> Collected:
    header, size = stream_framed(client, CONFIG_SCRIPT, dest)
    method = header.one("METHOD", "unknown")
    members, uncompressed = inspect_tar(dest)
    notes = (
        "Нативная резервная копия OpenWrt (sysupgrade -b)."
        if method == "sysupgrade"
        else "Конфигурация собрана вручную из /etc/config: sysupgrade -b недоступен."
    )
    if method != "sysupgrade":
        logger and logger.warn("sysupgrade -b недоступен — конфигурация собрана вручную.")
    return Collected(
        component_id="configuration",
        path=dest,
        members=members,
        uncompressed=uncompressed,
        notes=notes,
        extra={"method": method},
    )


# --------------------------------------------------------------------------
# overlay
# --------------------------------------------------------------------------
OVERLAY_SCRIPT = _PRELUDE + """
U="${R}__UPPERDIR__"
[ -d "$U" ] || { printf 'ERROR=no-upper %s\\n' "$U" >&2; exit 7; }
D=$(mktemp -d "${TMPDIR:-/tmp}/owbm-ovl.XXXXXX") || { printf 'ERROR=mktemp\\n' >&2; exit 5; }
trap 'rm -rf -- "$D"' EXIT INT TERM HUP
NL='
'
bad=$(find "$U" \\( -name "*${NL}*" -o -name "*$(printf '\\t')*" -o -name "*$(printf '\\r')*" \\) -print 2>/dev/null | head -n 1)
if [ -n "$bad" ]; then
  printf 'ERROR=unsupported-filename %s\\n' "$bad" >&2
  exit 15
fi
find "$U" ! -type d ! -type f ! -type l ! -type c -print > "$D/special" 2>/dev/null || true
if [ -s "$D/special" ]; then
  printf 'UNSUPPORTED=%s\\n' "$(head -n 1 "$D/special")"
  printf 'ERROR=special-files\\n' >&2
  exit 8
fi
find "$U" -type c -print > "$D/chars" 2>/dev/null || true
: > "$D/exclude"
: > "$D/whiteouts"
while IFS= read -r p; do
  [ -n "$p" ] || continue
  case "$p" in
    "$U"/*) rel="${p#"$U"/}" ;;
    *) printf 'ERROR=bad-path %s\\n' "$p" >&2; exit 10 ;;
  esac
  case "$rel" in
    ''|/*|../*|*/../*|*/..|.|*/./*|*/.) printf 'ERROR=unsafe-path %s\\n' "$rel" >&2; exit 11 ;;
  esac
  case "$rel" in
    *'*'*|*'?'*|*'['*|*'\\\\'*) printf 'ERROR=unrepresentable %s\\n' "$rel" >&2; exit 12 ;;
  esac
  line="$(ls -ln "$U/$rel" 2>/dev/null)" || { printf 'ERROR=stat %s\\n' "$rel" >&2; exit 13; }
  if printf '%s\\n' "$line" | awk 'NR==1 && $1 ~ /^c/ && $5 == "0," && $6 == "0" { ok=1 } END { exit !ok }'; then
    printf '%s\\n' "./$rel" >> "$D/exclude"
    printf '%s\\n' "$rel" >> "$D/whiteouts"
  else
    printf 'ERROR=special-device %s\\n' "$rel" >&2
    exit 14
  fi
done < "$D/chars"
while IFS= read -r w; do printf 'WHITEOUT=%s\\n' "$w"; done < "$D/whiteouts"
printf 'UPPER=%s\\n' "$U"
""" + f'printf \'%s\\n\' "{BODY_MARKER}"\n' + """tar -czf - -C "$U" -X "$D/exclude" . 2>/dev/null
"""


def collect_overlay(client, dest: Path, upperdir: str, logger=None) -> Collected:
    if not upperdir.startswith("/") or ".." in upperdir.split("/"):
        raise fail("OWBM-E-CHK-002", reason=f"некорректный путь верхнего слоя: {upperdir}")
    script = OVERLAY_SCRIPT.replace("__UPPERDIR__", upperdir)
    header, _size = stream_framed(client, script, dest)
    whiteouts = header.all("WHITEOUT")
    members, uncompressed = inspect_tar(dest)
    excluded = tuple({"path_pattern": item, "reason": "whiteout OverlayFS: удаление из нижнего слоя"} for item in whiteouts)
    return Collected(
        component_id="overlay_upper",
        path=dest,
        members=members,
        uncompressed=uncompressed,
        excluded=excluded,
        notes=f"верхний слой OverlayFS {upperdir}; whiteout-удалений: {len(whiteouts)}",
        extra={"whiteouts": whiteouts, "upperdir": upperdir},
    )


# --------------------------------------------------------------------------
# root filesystem (devices without OverlayFS)
# --------------------------------------------------------------------------
ROOTFS_EXCLUDES = (
    "./proc",
    "./sys",
    "./dev",
    "./tmp",
    "./run",
    "./overlay",
    "./boot",
    "./mnt",
    "./media",
    "./var/run",
    "./var/lock",
    "./var/log",
    "./etc/board.json",
)

ROOTFS_TEMPLATE = _PRELUDE + (
    "D=$(mktemp -d \"${TMPDIR:-/tmp}/owbm-root.XXXXXX\") || { echo 'ERROR=mktemp' >&2; exit 5; }\n"
    "trap 'rm -rf -- \"$D\"' EXIT INT TERM HUP\n"
    "cd \"$R/\" || { echo 'ERROR=no-root' >&2; exit 7; }\n"
    "cat > \"$D/exclude\" <<'OWBM_PATTERNS'\n"
    "__PATTERNS__\n"
    "OWBM_PATTERNS\n"
    "echo \"PATTERNS=$(wc -l < \"$D/exclude\" | tr -d ' ')\"\n"
    "echo '__OWBM_BODY__'\n"
    "tar -czf - -X \"$D/exclude\" . 2>/dev/null\n"
)


def rootfs_patterns(passport: DevicePassport) -> List[str]:
    """Exclusion patterns: standard pseudo paths plus every detected mount point."""
    result: List[str] = []
    seen = set()

    def add(relative: str) -> None:
        if relative in seen:
            return
        seen.add(relative)
        result.append(relative)
        result.append(relative + "/*")

    for item in ROOTFS_EXCLUDES:
        add(item)
    for mount in passport.storage.mounts:
        point = mount.mountpoint
        if not point or point == "/":
            continue
        relative = "./" + point.strip("/")
        if any(char in relative for char in "*?["):
            continue
        add(relative)
    return result


def collect_rootfs(client, dest: Path, passport: DevicePassport, logger=None) -> Collected:
    """Full copy of the root filesystem for devices that live without OverlayFS.

    Other filesystems are never crossed: every detected mount point is excluded
    by pattern. Special files are rejected later by ``inspect_tar`` instead of
    being archived, because busybox tar cannot filter them.
    """
    patterns = rootfs_patterns(passport)
    script = ROOTFS_TEMPLATE.replace("__PATTERNS__", "\n".join(patterns))
    header, _size = stream_framed(client, script, dest)
    members, uncompressed = inspect_tar(dest)
    return Collected(
        component_id="rootfs",
        path=dest,
        members=members,
        uncompressed=uncompressed,
        notes=(
            "корневая ФС целиком (без /proc, /sys, /dev, /tmp, /boot, журналов "
            "и других точек монтирования)"
        ),
        extra={"excluded": patterns},
    )


# --------------------------------------------------------------------------
# packages
# --------------------------------------------------------------------------
PACKAGES_SCRIPT_APK = _PRELUDE + """
C="$R__CACHE__"
D=$(mktemp -d "${TMPDIR:-/tmp}/owbm-pkg.XXXXXX") || { printf 'ERROR=mktemp\\n' >&2; exit 5; }
trap 'rm -rf -- "$D"' EXIT INT TERM HUP
mkdir -p "$D/one" "$D/pkg" "$C" || exit 6
if [ "__UPDATE__" = "1" ]; then
  if apk --cache-dir "$C" update >/dev/null 2>&1; then
    printf 'INDEX=ok\\n'
  else
    printf 'INDEX=fail\\n'
  fi
fi
fetch_apk() {
  pkg="$1"; ver="$2"
  rm -f "$D/one"/*.apk 2>/dev/null || true
  if apk --cache-dir "$C" fetch -o "$D/one" "$pkg=$ver" >/dev/null 2>&1; then
    for f in "$D/one"/*.apk; do
      [ -s "$f" ] || continue
      mv "$f" "$D/pkg/" && printf 'PKG=exact %s %s\\n' "$pkg" "$ver"
      return 0
    done
  fi
  rm -f "$D/one"/*.apk 2>/dev/null || true
  if apk --cache-dir "$C" fetch -o "$D/one" "$pkg" >/dev/null 2>&1; then
    for f in "$D/one"/*.apk; do
      [ -s "$f" ] || continue
      got="${f##*/}"; got="${got#"$pkg-"}"; got="${got%.apk}"
      mv "$f" "$D/pkg/"
      if [ "$got" = "$ver" ]; then
        printf 'PKG=exact %s %s\\n' "$pkg" "$ver"
      else
        printf 'PKG=fallback %s %s\\n' "$pkg" "$got"
      fi
      return 0
    done
  fi
  printf 'PKG=unavailable %s %s\\n' "$pkg" "$ver"
  return 0
}
for entry in __ENTRIES__; do
  fetch_apk "${entry%%,*}" "${entry#*,}"
done
""" + f'printf \'%s\\n\' "{BODY_MARKER}"\n' + """tar -czf - -C "$D/pkg" . 2>/dev/null
"""

PACKAGES_SCRIPT_OPKG = _PRELUDE + """
D=$(mktemp -d "${TMPDIR:-/tmp}/owbm-pkg.XXXXXX") || { printf 'ERROR=mktemp\\n' >&2; exit 5; }
trap 'rm -rf -- "$D"' EXIT INT TERM HUP
mkdir -p "$D/one" "$D/pkg" || exit 6
fetch_opkg() {
  pkg="$1"; ver="$2"
  rm -rf "$D/one"; mkdir -p "$D/one" || return 1
  if ( cd "$D/one" && opkg download "$pkg" >/dev/null 2>&1 ); then
    for f in "$D/one"/*.ipk; do
      [ -s "$f" ] || continue
      mv "$f" "$D/pkg/" && printf 'PKG=fallback %s %s\\n' "$pkg" "$ver"
      return 0
    done
  fi
  printf 'PKG=unavailable %s %s\\n' "$pkg" "$ver"
  return 0
}
for entry in __ENTRIES__; do
  fetch_opkg "${entry%%,*}" "${entry#*,}"
done
""" + f'printf \'%s\\n\' "{BODY_MARKER}"\n' + """tar -czf - -C "$D/pkg" . 2>/dev/null
"""


def _chunk(items: Sequence[Tuple[str, str]], size: int) -> List[List[Tuple[str, str]]]:
    step = max(1, size)
    return [list(items[index : index + step]) for index in range(0, len(items), step)]


def _package_name_for_file(filename: str, names: Sequence[str]) -> Optional[str]:
    """Resolve a package archive name by the longest valid package-name prefix."""
    stem = Path(filename).name
    for suffix in (".apk", ".ipk"):
        if stem.endswith(suffix):
            stem = stem[:-len(suffix)]
            break
    matches = [name for name in names if stem.startswith(name + "-") or stem.startswith(name + "_")]
    return max(matches, key=len) if matches else None


def collect_packages(
    client,
    workdir: Path,
    passport: DevicePassport,
    *,
    chunk_size: int = 25,
    logger=None,
) -> Tuple[Optional[Collected], List[Dict[str, str]]]:
    """Fetch package archives in bounded chunks; never fail the whole backup."""
    manager = passport.packages.manager
    entries = [(item.name, item.version) for item in passport.packages.installed]
    safe_entries = [(name, version) for name, version in entries if SAFE_TOKEN.match(name) and SAFE_TOKEN.match(version)]
    rejected = [name for name, _ in entries if name not in {item[0] for item in safe_entries}]
    status: Dict[str, Dict[str, str]] = {
        item.name: {
            "name": item.name,
            "version": item.version,
            "arch": item.arch,
            "status": "unavailable",
            "file": "",
        }
        for item in passport.packages.installed
    }
    if manager not in ("apk", "opkg") or not safe_entries:
        return None, list(status.values())

    staging = Path(workdir) / "packages"
    staging.mkdir(parents=True, exist_ok=True)
    template = PACKAGES_SCRIPT_APK if manager == "apk" else PACKAGES_SCRIPT_OPKG
    chunk_file = Path(workdir) / "chunk.tar.gz"
    fetched = 0
    budget = ExtractionBudget(
        max_members=MAX_PACKAGE_STAGING_MEMBERS,
        max_paths=MAX_PACKAGE_STAGING_PATHS,
        max_uncompressed_bytes=MAX_PACKAGE_STAGING_BYTES,
    )
    index_state = "not-needed"
    groups = _chunk(safe_entries, chunk_size)
    for index, group in enumerate(groups, start=1):
        remaining_stage = MAX_PACKAGE_STAGING_BYTES - budget.uncompressed_bytes
        if (
            remaining_stage <= 0
            or budget.members >= budget.max_members
            or budget.paths >= budget.max_paths
        ):
            if logger:
                logger.warn("Достигнут предел локальной распаковки пакетов; оставшиеся пачки пропущены.")
            break
        literals = " ".join("'" + f"{name},{version}" + "'" for name, version in group)
        script = template.replace("__ENTRIES__", literals)
        script = script.replace("__CACHE__", PACKAGE_CACHE_DIR)
        script = script.replace("__UPDATE__", "1" if index == 1 else "0")
        header, _ = stream_framed(
            client, script, chunk_file, max_body_bytes=MAX_PACKAGE_CHUNK_STREAM_BYTES
        )
        if header.has("INDEX"):
            index_state = header.one("INDEX")
        added = extract_tar_safely(
            chunk_file,
            staging,
            max_uncompressed_bytes=min(MAX_PACKAGE_CHUNK_UNCOMPRESSED_BYTES, remaining_stage),
            budget=budget,
        )
        fetched += added
        for line in header.all("PKG"):
            parts = line.split()
            if len(parts) < 2:
                continue
            state, name = parts[0], parts[1]
            version = parts[2] if len(parts) > 2 else ""
            if name in status:
                status[name]["status"] = state
            else:
                status[name] = {"name": name, "version": version, "status": state, "file": ""}
        if logger:
            logger.debug(
                f"пакеты: пачка {index}, получено файлов {added}, всего {fetched}"
            )
        chunk_file.unlink(missing_ok=True)
    _drop_package_cache(client)

    package_names = list(status)
    for entry in staging.rglob("*"):
        if not entry.is_file():
            continue
        name = _package_name_for_file(entry.name, package_names)
        if name is not None:
            status[name]["file"] = str(entry.relative_to(staging))

    if fetched == 0:
        if logger:
            reason = (
                "не удалось обновить индекс пакетов (нет доступа к репозиториям?)"
                if index_state == "fail"
                else "репозитории не вернули ни одного пакета"
            )
            logger.warn(f"Бинарные пакеты получить не удалось: {reason}.")
        return None, list(status.values())

    payload = Path(workdir) / "packages-binaries.tar.gz"
    members, uncompressed = repack_dir(staging, payload)
    exact = sum(1 for item in status.values() if item["status"] == "exact")
    fallback = sum(1 for item in status.values() if item["status"] == "fallback")
    unavailable = sum(1 for item in status.values() if item["status"] == "unavailable")
    if logger:
        logger.info(
            f"Пакеты: точных {exact}, из текущих репозиториев {fallback}, недоступных {unavailable}"
        )
    collected = Collected(
        component_id="packages_binaries",
        path=payload,
        members=members,
        uncompressed=uncompressed,
        notes=f"точных версий: {exact}, из репозиториев: {fallback}, недоступно: {unavailable}",
        extra={"exact": exact, "fallback": fallback, "unavailable": unavailable, "rejected": rejected},
    )
    return collected, list(status.values())


# --------------------------------------------------------------------------
# user data and system state
# --------------------------------------------------------------------------
def _validated_paths(paths: Sequence[str]) -> List[str]:
    result: List[str] = []
    for raw in paths:
        path = str(raw)
        if "\\" in path or any(ord(char) < 0x20 or ord(char) == 0x7F for char in path):
            raise fail(
                "OWBM-E-CFG-002",
                key="user_data_paths",
                reason="управляющие символы и обратная косая черта в путях не поддерживаются",
            )
        path = path.strip()
        if not path.startswith("/"):
            raise fail("OWBM-E-CFG-002", key="user_data_paths", reason=f"нужен абсолютный путь: {path}")
        parts = [part for part in path.split("/") if part]
        if not parts or any(part == ".." for part in parts):
            raise fail("OWBM-E-CFG-002", key="user_data_paths", reason=f"недопустимый путь: {path}")
        if path in ("/", "/rom", "/proc", "/sys", "/dev", "/tmp"):
            raise fail("OWBM-E-CFG-002", key="user_data_paths", reason=f"нельзя сохранять служебный каталог: {path}")
        result.append("/" + "/".join(parts))
    return result


def collect_paths(client, dest: Path, paths: Sequence[str], *, component_id: str, title: str, logger=None) -> Optional[Collected]:
    wanted = _validated_paths(paths)
    if not wanted:
        return None
    literals = " ".join(shlex.quote(path) for path in wanted)
    script = (
        _PRELUDE
        + "D=$(mktemp -d \"${TMPDIR:-/tmp}/owbm-data.XXXXXX\") || exit 5\n"
        + "trap 'rm -rf -- \"$D\"' EXIT INT TERM HUP\n"
        + ": > \"$D/list\"\n"
        + f"for p in {literals}; do\n"
        + '  [ -e "$R$p" ] || continue\n'
        + '  printf \'./%s\\n\' "${p#/}" >> "$D/list"\n'
        + "done\n"
        + 'if [ -s "$D/list" ]; then\n'
        + '  printf \'FOUND=1\\n\'\n'
        + f'  printf \'%s\\n\' "{BODY_MARKER}"\n'
        + '  tar -czf - -C "$R/" -T "$D/list" 2>/dev/null\n'
        + 'else\n'
        + '  printf \'FOUND=0\\n\'\n'
        + f'  printf \'%s\\n\' "{BODY_MARKER}"\n'
        + '  tar -czf - -C "$D" -T /dev/null 2>/dev/null || printf \'\'\n'
        + 'fi\n'
    )
    header, _size = stream_framed(client, script, dest)
    if header.one("FOUND", "0") != "1":
        return None
    members, uncompressed = inspect_tar(dest)
    return Collected(
        component_id=component_id,
        path=dest,
        members=members,
        uncompressed=uncompressed,
        notes=f"{title}: {', '.join(wanted)}",
    )


def collect_user_data(client, dest: Path, paths: Sequence[str], logger=None) -> Optional[Collected]:
    return collect_paths(client, dest, paths, component_id="user_data", title="пользовательские каталоги", logger=logger)


SYSTEM_STATE_PATHS = (
    "/etc/rc.local",
    "/etc/crontabs/root",
    "/etc/dropbear/authorized_keys",
    "/etc/sysupgrade.conf",
    "/etc/uci-defaults",
    "/etc/hotplug.d",
    "/etc/profile.d",
    "/etc/init.d/owbm",
)


def collect_system_state(client, dest: Path, logger=None) -> Optional[Collected]:
    return collect_paths(
        client, dest, SYSTEM_STATE_PATHS, component_id="system_state", title="службы и скрипты", logger=logger
    )
