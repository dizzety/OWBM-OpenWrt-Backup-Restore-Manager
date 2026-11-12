"""Migration: reproduce a device on another device from its archive.

Nothing here knows about a particular router, network, address or file name.
Everything is derived at run time from two sources:

* the archive manifest and inventory (what the source device was),
* the target passport (what the target device is) plus the target's own
  ``/etc/config`` listing read over SSH.

The default policy is deliberately conservative: packages are installed by name
from the *target's* repositories, configuration files that the target already
has are kept (they belong to the target's hardware), and files the target does
not have are copied from the archive. ``--replace-config`` flips that for a
faithful clone, with a warning that connectivity may require manual repair.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import shlex
import shutil
import tarfile
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from . import archive, manifest as manifest_mod
from .discovery import DevicePassport, discover
from .errors import OwbmError, fail
from .manifest import Manifest
from .remote import build_script, send_file
from .util import human_size

PKG_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9+._-]{0,99}\Z")
CONFIG_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
CONFIG_PREFIX = "etc/config/"
PACKAGE_LOG = "/tmp/owbm-migrate-packages.log"


ELF_MAGIC = b"\x7fELF"
FILE_PAYLOAD_IDS = ("overlay_upper", "rootfs")
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_CONFIG_FILE_BYTES = 8 * 1024 * 1024
MAX_CONFIG_TOTAL_BYTES = 32 * 1024 * 1024
MAX_CONFIG_ARCHIVE_MEMBERS = 10000
MAX_PACKAGE_BYTES = 128 * 1024 * 1024
MAX_PACKAGE_BUNDLE_BYTES = 512 * 1024 * 1024
MAX_PACKAGE_ARCHIVE_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
MAX_PACKAGE_ARCHIVE_MEMBERS = 50000
NOARCH_VALUES = {"all", "noarch"}


@dataclass
class MigrateOptions:
    install_packages: bool = True
    copy_files: bool = True
    replace_existing_config: bool = False
    reload: bool = False
    dry_run: bool = False


@dataclass
class MigratePlan:
    packages_install: List[str] = field(default_factory=list)
    packages_present: List[str] = field(default_factory=list)
    packages_unavailable: List[str] = field(default_factory=list)
    packages_archive_install: List[str] = field(default_factory=list)
    packages_archive_incompatible: List[str] = field(default_factory=list)
    packages_foreign_arch: List[str] = field(default_factory=list)
    configs_copy: List[str] = field(default_factory=list)
    configs_kept: List[str] = field(default_factory=list)
    files_copy: List[str] = field(default_factory=list)
    files_skipped_binary: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    install_packages_enabled: bool = True
    target_identity: Dict[str, str] = field(default_factory=dict, repr=False)

    def as_dict(self) -> Dict[str, object]:
        return {
            "packages_install": self.packages_install,
            "packages_present": self.packages_present,
            "packages_unavailable": self.packages_unavailable,
            "packages_archive_install": self.packages_archive_install,
            "packages_archive_incompatible": self.packages_archive_incompatible,
            "packages_foreign_arch": self.packages_foreign_arch,
            "configs_copy": self.configs_copy,
            "configs_kept": self.configs_kept,
            "files_copy": self.files_copy,
            "files_skipped_binary": self.files_skipped_binary,
            "warnings": self.warnings,
            "install_packages_enabled": self.install_packages_enabled,
        }

    def describe(self) -> List[str]:
        if self.install_packages_enabled:
            package_summary = (
                f"  пакетов: из репозиториев установить {len(self.packages_install)}, "
                f"из архива {len(self.packages_archive_install)}, "
                f"уже есть {len(self.packages_present)}, "
                f"недоступно {len(self.packages_unavailable)}, "
                f"пакетных файлов пропущено {len(self.packages_archive_incompatible)}"
            )
        else:
            package_summary = (
                f"  пакетов: установка отключена; доступны из репозиториев {len(self.packages_install)}, "
                f"из архива {len(self.packages_archive_install)}, "
                f"уже есть {len(self.packages_present)}, "
                f"недоступно {len(self.packages_unavailable)}, "
                f"пакетных файлов пропущено {len(self.packages_archive_incompatible)}"
            )
        lines = [
            package_summary,
            f"  конфигов: скопировать {len(self.configs_copy)}, "
            f"оставить свои {len(self.configs_kept)}",
            f"  файлов приложений: скопировать {len(self.files_copy)}, "
            f"пропущено бинарников {len(self.files_skipped_binary)}",
        ]
        return lines


@dataclass
class MigrateResult:
    plan: MigratePlan
    installed: List[str] = field(default_factory=list)
    install_failed: List[str] = field(default_factory=list)
    installed_from_archive: List[str] = field(default_factory=list)
    archive_install_failed: List[str] = field(default_factory=list)
    configs_written: List[str] = field(default_factory=list)
    files_written: List[str] = field(default_factory=list)
    messages: List[str] = field(default_factory=list)
    ok: bool = True

    def as_dict(self) -> Dict[str, object]:
        return {
            "ok": self.ok,
            "installed": self.installed,
            "install_failed": self.install_failed,
            "installed_from_archive": self.installed_from_archive,
            "archive_install_failed": self.archive_install_failed,
            "configs_written": self.configs_written,
            "files_written": len(self.files_written),
            "messages": self.messages,
            "plan": self.plan.as_dict(),
        }


# --------------------------------------------------------------------------
# data collection
# --------------------------------------------------------------------------
def source_packages(manifest_data: Dict[str, object]) -> List[str]:
    """Package names from the archive inventory (no versions, no guessing)."""
    inventory = manifest_data.get("inventory") or {}
    packages = inventory.get("packages") if isinstance(inventory, dict) else None
    path = packages.get("path") if isinstance(packages, dict) else None
    return [str(path or "")] if path else []


def source_package_inventory(archive_path: Path) -> Tuple[str, str, List[Dict[str, str]]]:
    """Read package names, manager and per-package architecture from an archive."""
    raw = archive.read_member(archive_path, "inventory/packages.json")
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        return "", "", []
    records = []
    seen = set()
    for entry in data.get("entries", []):
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name", "")).strip()
        if not name or not PKG_NAME_RE.match(name) or name in seen:
            continue
        seen.add(name)
        records.append({
            "name": name,
            "arch": str(entry.get("arch", "")).strip(),
            "file": str(entry.get("file", "")).strip(),
            "status": str(entry.get("status", "")).strip(),
        })
    return str(data.get("manager", "")), str(data.get("arch", "")), records


def read_source_packages(archive_path: Path) -> List[str]:
    """Package names from the archive inventory (compatibility helper)."""
    _manager, _arch, records = source_package_inventory(archive_path)
    return [entry["name"] for entry in records]


def _normalise_member_name(name: str) -> str:
    while name.startswith("./"):
        name = name[2:]
    return name


def _bounded_tar_members(tf):
    total = 0
    for count, member in enumerate(archive.bounded_tar_members(tf), start=1):
        if count > MAX_PACKAGE_ARCHIVE_MEMBERS:
            raise fail("OWBM-E-CHK-002", reason="слишком много элементов в packages_binaries")
        if member.size < 0:
            raise fail("OWBM-E-CHK-002", reason="отрицательный размер элемента packages_binaries")
        total += member.size
        if total > MAX_PACKAGE_ARCHIVE_UNCOMPRESSED_BYTES:
            raise fail("OWBM-E-CHK-002", reason="packages_binaries превышает лимит распаковки 1 GiB")
        yield member


def _passport_identity(passport: DevicePassport) -> Dict[str, str]:
    return {
        "board_id": str(passport.identity.board_id or ""),
        "board_name": str(passport.identity.board_name or ""),
        "model": str(passport.identity.model or ""),
        "hostname": str(passport.identity.hostname or ""),
        "revision": str(passport.identity.revision or ""),
        "arch": str(passport.identity.arch or ""),
        "target": str(passport.identity.target or ""),
        "release": str(passport.identity.release or ""),
        "kernel_release": str(passport.identity.kernel_release or ""),
        "package_manager": str(passport.packages.manager or ""),
        "package_arch": str(passport.packages.arch or ""),
    }


def _package_arch_matches(package_arch: str, source_arch: str, target_arch: str) -> bool:
    """Only allow exact package-architecture matches or explicitly portable packages."""
    package_arch = (package_arch or source_arch).strip().lower()
    target_arch = (target_arch or "").strip().lower()
    if package_arch in NOARCH_VALUES:
        return True
    return bool(package_arch and target_arch and package_arch == target_arch)


def _archive_package_files(
    archive_path: Path,
    parsed: Manifest,
    records: Sequence[Dict[str, str]],
    *,
    source_manager: str,
    source_arch: str,
    source_release: str,
    source_target: str,
    target_manager: str,
    target_arch: str,
    target_release: str,
    target_target: str,
) -> Tuple[Dict[str, Tuple[str, int]], List[str]]:
    """Return filenames and sizes for package artifacts safe for the target."""
    component = parsed.component("packages_binaries")
    if component is None:
        return {}, []
    suffix = {"apk": ".apk", "opkg": ".ipk"}.get(source_manager)
    if not suffix:
        return {}, []

    expected: Dict[str, Dict[str, str]] = {}
    for record in records:
        filename = _normalise_member_name(record.get("file", ""))
        if filename and filename.endswith(suffix):
            expected[filename] = record

    if not expected:
        return {}, []

    candidates: Dict[str, Tuple[str, int]] = {}
    incompatible: List[str] = []
    seen = set()
    with archive.open_zip(archive_path) as zf:
        with zf.open(component.path) as component_file:
            with archive.open_tar_gz(fileobj=component_file) as tf:
                for member in _bounded_tar_members(tf):
                    filename = _normalise_member_name(member.name)
                    record = expected.get(filename)
                    if record is None:
                        continue
                    if filename in seen:
                        candidates.pop(record["name"], None)
                        incompatible.append(record["name"])
                        continue
                    seen.add(filename)
                    if not member.isfile() or member.size <= 0 or member.size > MAX_PACKAGE_BYTES:
                        incompatible.append(record["name"])
                        continue
                    package_arch = record.get("arch", "") or source_arch
                    package_name = record["name"].lower()
                    forbidden = (
                        package_name == "kernel"
                        or package_name.startswith(("kernel-", "kmod-"))
                        or "firmware" in package_name
                    )
                    portable = package_arch.strip().lower() in NOARCH_VALUES
                    exact_platform = bool(
                        source_release and target_release and source_release == target_release
                        and source_target and target_target and source_target == target_target
                    )
                    compatible = (
                        source_manager == target_manager
                        and not forbidden
                        and _package_arch_matches(package_arch, source_arch, target_arch)
                        and (portable or exact_platform)
                    )
                    if not compatible:
                        incompatible.append(record["name"])
                        continue
                    candidates[record["name"]] = (filename, member.size)
    return candidates, sorted(set(incompatible))


def source_configs(archive_path: Path) -> Dict[str, bytes]:
    """Read configuration files from the payload with strict memory bounds."""
    result: Dict[str, bytes] = {}
    total_bytes = 0
    tar_total = 0
    path_bytes = 0
    with archive.open_zip(archive_path) as zf:
        try:
            payload = zf.open("payload/configuration.tar.gz")
        except KeyError:
            raise fail("OWBM-E-CHK-002", reason="в архиве нет configuration payload")
        with payload, archive.open_tar_gz(fileobj=payload) as tf:
            for count, member in enumerate(archive.bounded_tar_members(tf), start=1):
                path_bytes += len(member.name.encode("utf-8", "replace"))
                tar_total += max(member.size, 0)
                if count > MAX_CONFIG_ARCHIVE_MEMBERS:
                    raise fail("OWBM-E-CHK-002", reason="слишком много элементов в архиве конфигурации")
                if path_bytes > archive.MAX_TAR_PATH_BYTES:
                    raise fail("OWBM-E-CHK-002", reason="имена элементов конфигурации превышают предел 16 МиБ")
                if tar_total > archive.MAX_TAR_UNCOMPRESSED_BYTES:
                    raise fail("OWBM-E-CHK-002", reason="вложенный tar конфигурации превышает 64 ГиБ")
                if not member.isfile():
                    continue
                name = member.name
                while name.startswith("./"):
                    name = name[2:]
                if not name or name.startswith("/") or ".." in Path(name).parts:
                    continue
                if member.size < 0 or member.size > MAX_CONFIG_FILE_BYTES:
                    raise fail("OWBM-E-CHK-002", reason="файл конфигурации превышает предел 8 МиБ")
                if total_bytes + member.size > MAX_CONFIG_TOTAL_BYTES:
                    raise fail("OWBM-E-CHK-002", reason="конфигурация превышает общий предел 32 МиБ")
                handle = tf.extractfile(member)
                if handle is None:
                    continue
                data = handle.read(member.size + 1)
                if len(data) != member.size:
                    raise fail("OWBM-E-CHK-002", reason="файл конфигурации повреждён или обрезан")
                total_bytes += len(data)
                result[name] = data
    return result


# --------------------------------------------------------------------------
# planning
# --------------------------------------------------------------------------
def target_config_names(client, *, root: str = "") -> Set[str]:
    body = (
        'set -u\nPATH="/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"\n'
        'R="${OWBM_ROOT:-}"\n'
        'for f in "$R"/etc/config/*; do [ -f "$f" ] || continue; n="${f##*/}"; echo "CFG=$n"; done\n'
        'echo DONE=1\n'
    )
    from .remote import build_script

    r = client.run(build_script(body, root=root), timeout=60, allow_failure=True)
    if r.rc != 0 or "DONE=1" not in r.out:
        raise fail("OWBM-E-MIG-003", reason="не завершилось чтение списка /etc/config")
    names = set()
    for line in r.out.splitlines():
        key, _, value = line.partition("=")
        if key == "CFG" and value:
            names.add(value)
    return names


def package_availability(client, names: Iterable[str], *, manager: str) -> Tuple[Set[str], Set[str]]:
    """Which of ``names`` the target's repositories can provide, and which it has."""
    wanted = [name for name in dict.fromkeys(names) if PKG_NAME_RE.match(name)]
    if not wanted:
        return set(), set()
    if manager == "apk":
        check = 'apk search -x "$n" >/dev/null 2>&1'
    elif manager == "opkg":
        check = 'opkg list "$n" 2>/dev/null | grep -q .'
    else:
        return set(), set()
    literals = " ".join(shlex.quote(name) for name in wanted)
    script = (
        'set -u\nPATH="/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"\n'
        f"for n in {literals}; do\n"
        f"  if {check}; then echo \"AVAILABLE=$n\"; else echo \"MISSING=$n\"; fi\n"
        "done\n"
        'for n in ' + literals + '; do\n'
        + ('  apk info -e "$n" >/dev/null 2>&1 && echo "PRESENT=$n"\n' if manager == "apk"
           else '  opkg list-installed "$n" 2>/dev/null | grep -q . && echo "PRESENT=$n"\n')
        + "done\n"
        'echo DONE=1\n'
    )
    result = client.run(script, timeout=300, allow_failure=True)
    available, present = set(), set()
    for line in result.out.splitlines():
        key, _, value = line.partition("=")
        if key == "AVAILABLE":
            available.add(value)
        elif key == "PRESENT":
            present.add(value)
    return available, present


def _payload_files(archive_path: Path, parsed: Manifest, payloads: Sequence[str]):
    """Yield regular payload paths under aggregate member, name, and size limits."""
    members_seen = 0
    path_bytes = 0
    total_size = 0
    with archive.open_zip(archive_path) as zf:
        for component in parsed.components:
            if component.id not in payloads:
                continue
            try:
                payload = zf.open(component.path)
            except KeyError:
                continue
            with payload, archive.open_tar_gz(fileobj=payload) as tf:
                for member in archive.bounded_tar_members(tf):
                    members_seen += 1
                    path_bytes += len(member.name.encode("utf-8", "replace"))
                    total_size += max(member.size, 0)
                    if members_seen > archive.MAX_TAR_MEMBERS:
                        raise fail("OWBM-E-CHK-002", reason="слишком много элементов во вложенных tar")
                    if path_bytes > archive.MAX_TAR_PATH_BYTES:
                        raise fail("OWBM-E-CHK-002", reason="имена элементов во вложенных tar превышают предел 16 МиБ")
                    if total_size > archive.MAX_TAR_UNCOMPRESSED_BYTES:
                        raise fail("OWBM-E-CHK-002", reason="вложенные tar превышают предел распаковки 64 ГиБ")
                    if not member.isfile() or member.size == 0 or member.size > MAX_FILE_BYTES:
                        continue
                    name = member.name
                    while name.startswith("./"):
                        name = name[2:]
                    if not name or name.startswith("/") or ".." in Path(name).parts:
                        continue
                    handle = tf.extractfile(member)
                    if handle is None:
                        continue
                    yield name, handle.read(4)


def target_file_list(client, *, root: str = "", limit: int = 40000) -> Tuple[Set[str], bool]:
    body = (
        'set -u\nPATH="/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"\n'
        'R="${OWBM_ROOT:-}"\n'
        'cd "$R/" 2>/dev/null || exit 1\n'
        'umask 077\n'
        'mkdir -p "$R/tmp" || exit 1\n'
        'LIST="$R/tmp/owbm-migrate-files-$$"\nERR="$R/tmp/owbm-migrate-files-err-$$"\n'
        ': > "$LIST" || exit 1\n'
        'find . -xdev -type f > "$LIST" 2> "$ERR"\nFIND_RC=$?\n'
        'if [ "$FIND_RC" -ne 0 ] || [ -s "$ERR" ]; then rm -f "$LIST" "$ERR"; exit 1; fi\n'
        'head -n ' + str(limit + 1) + ' "$LIST" | sed "s|^\\./||"\n'
        'rm -f "$LIST" "$ERR"\n'
        'echo DONE=1\n'
    )
    from .remote import build_script

    result = client.run(build_script(body, root=root), timeout=180, allow_failure=True)
    if result.rc != 0 or "DONE=1" not in result.out:
        raise fail("OWBM-E-MIG-003", reason="не завершилось сканирование файлов цели")
    files = set()
    for line in result.out.splitlines():
        text = line.strip()
        if not text or text.startswith("DONE"):
            continue
        files.add(text)
    if len(files) > limit:
        return set(), True
    return files, False


def build_plan(
    parsed: Manifest,
    passport: DevicePassport,
    archive_path: Path,
    client,
    *,
    root: str = "",
    options: Optional[MigrateOptions] = None,
) -> MigratePlan:
    options = options or MigrateOptions()
    plan = MigratePlan()
    source_arch = str(parsed.compatibility_key.get("arch", ""))
    target_arch = passport.identity.arch
    plan.install_packages_enabled = options.install_packages
    plan.target_identity = _passport_identity(passport)

    source_manager, source_package_arch, package_records = source_package_inventory(archive_path)
    names = [item["name"] for item in package_records]
    records_by_name = {item["name"]: item for item in package_records}
    target_package_arch = passport.packages.arch or target_arch
    archived, incompatible = _archive_package_files(
        archive_path,
        parsed,
        package_records,
        source_manager=source_manager,
        source_arch=source_package_arch or source_arch,
        source_release=str(parsed.device.get("release", "")),
        source_target=str(parsed.device.get("target", "")),
        target_manager=passport.packages.manager,
        target_arch=target_package_arch,
        target_release=passport.identity.release,
        target_target=passport.identity.target,
    )
    available, present = package_availability(client, names, manager=passport.packages.manager)
    for name in names:
        if name in present:
            plan.packages_present.append(name)
        elif name in available:
            plan.packages_install.append(name)
        elif name in archived:
            plan.packages_archive_install.append(name)
        elif name in incompatible:
            plan.packages_archive_incompatible.append(name)
            record = records_by_name.get(name, {})
            package_arch = (record.get("arch", "") or source_package_arch or source_arch).lower()
            if package_arch not in NOARCH_VALUES and package_arch != target_package_arch.lower():
                plan.packages_foreign_arch.append(name)
        else:
            plan.packages_unavailable.append(name)

    if source_arch and target_arch and source_arch != target_arch:
        plan.warnings.append(
            f"Архив собран для {source_arch}, цель — {target_arch}: пакеты из репозиториев "
            "цели устанавливаются по именам; пакетные файлы из архива допускаются только "
            "для noarch/all либо при совпадении архитектуры, target и release."
        )
    if plan.packages_archive_install:
        plan.warnings.append(
            "Часть пакетов будет установлена из локальных файлов архива; зависимости "
            "должны быть уже установлены или доступны в репозиториях цели."
        )
    if plan.packages_archive_incompatible:
        plan.warnings.append(
            "Пакеты из архива пропущены: менеджер, архитектура, target/release или ABI не совместимы с целью."
        )

    existing = target_config_names(client, root=root)
    for path in sorted(source_configs(archive_path)):
        if not path.startswith(CONFIG_PREFIX):
            continue
        name = path[len(CONFIG_PREFIX):]
        # uci temp files (.dhcp.uci-XXXX), apk leftovers (*.apk-new) и прочее
        # служебное — не конфигурация и переносить их нельзя.
        if not name or not CONFIG_NAME_RE.match(name) or name.endswith(".apk-new"):
            continue
        if name in existing and not options.replace_existing_config:
            plan.configs_kept.append(name)
        else:
            plan.configs_copy.append(name)

    if options.copy_files:
        existing_files, file_scan_truncated = target_file_list(client, root=root)
        if file_scan_truncated:
            plan.warnings.append(
                "Сканирование файлов цели превысило 40 000 записей; копирование файлов приложений отключено, "
                "чтобы не перезаписать существующие файлы."
            )
        else:
            seen = set()
            for name, data in _payload_files(archive_path, parsed, FILE_PAYLOAD_IDS):
                if name in seen or name in existing_files:
                    continue
                seen.add(name)
                if name.startswith(CONFIG_PREFIX):
                    continue
                if data[:4] == ELF_MAGIC:
                    plan.files_skipped_binary.append(name)
                    continue
                plan.files_copy.append(name)

    if plan.files_skipped_binary:
        plan.warnings.append(
            f"Пропущено {len(plan.files_skipped_binary)} бинарных файлов источника: "
            "они собраны под другую архитектуру и на цели не запустятся."
        )
    if plan.configs_kept:
        plan.warnings.append(
            "Совпадающие конфиги цели сохранены как есть (сеть, firewall, ssh и т.п.). "
            "Для полного клонирования используйте --replace-config."
        )
    if not options.install_packages and (plan.packages_install or plan.packages_archive_install):
        plan.warnings.append("Установка пакетов отключена: --no-install-packages.")
    return plan


# --------------------------------------------------------------------------
# applying
# --------------------------------------------------------------------------
def _install(client, names: Sequence[str], *, manager: str, logger) -> Tuple[List[str], List[str]]:
    if not names:
        return [], []
    literals = " ".join(shlex.quote(name) for name in names)
    command = (
        f"apk add {literals}" if manager == "apk" else f"opkg install {literals}"
    )
    script = (
        'set -u\nPATH="/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"\n'
        f"if {command} > {PACKAGE_LOG} 2>&1; then echo 'ORDER=ok'; else echo 'ORDER=fail'; fi\n"
        f"tail -5 {PACKAGE_LOG} 2>/dev/null\n"
    )
    result = client.run(script, timeout=3600, allow_failure=True)
    installed, failed = [], []
    for name in names:
        probe_command = (
            f"apk info -e {shlex.quote(name)} >/dev/null 2>&1 && echo P=1 || echo P=0"
            if manager == "apk"
            else f"opkg list-installed {shlex.quote(name)} 2>/dev/null | grep -q . && echo P=1 || echo P=0"
        )
        try:
            probe = client.run(probe_command, timeout=30, allow_failure=True)
        except Exception:
            probe = None
        if probe is not None and probe.rc == 0 and "P=1" in probe.out:
            installed.append(name)
        else:
            failed.append(name)

    if not failed:
        logger.ok(f"Установлено пакетов: {len(installed)}")
        client.run(f"rm -f {PACKAGE_LOG}", timeout=30, allow_failure=True)
        return installed, []

    detail = " ".join(
        line for line in result.out.splitlines() if "ORDER=" not in line and line.strip()
    )[-400:]
    logger.warn(f"Установка пакетов не подтверждена: {detail or ', '.join(failed)}")
    return installed, failed


def _install_archive_packages(
    client,
    parsed: Manifest,
    archive_path: Path,
    workdir: Path,
    names: Sequence[str],
    *,
    source_manager: str,
    source_arch: str,
    source_release: str,
    source_target: str,
    target_manager: str,
    target_arch: str,
    target_release: str,
    target_target: str,
    logger,
    root: str = "",
) -> Tuple[List[str], List[str]]:
    """Install compatible package files from the archive, never raw foreign binaries."""
    candidates, _incompatible = _archive_package_files(
        archive_path,
        parsed,
        source_package_inventory(archive_path)[2],
        source_manager=source_manager,
        source_arch=source_arch,
        source_release=source_release,
        source_target=source_target,
        target_manager=target_manager,
        target_arch=target_arch,
        target_release=target_release,
        target_target=target_target,
    )
    selected = [(name, *candidates[name]) for name in names if name in candidates]
    missing_names = [name for name in names if name not in candidates]
    if not selected:
        return [], list(names)
    selected_names = [name for name, _filename, _size in selected]
    total_bytes = sum(size for _name, _filename, size in selected)
    if total_bytes > MAX_PACKAGE_BUNDLE_BYTES:
        logger.warn(
            f"Пакетный набор из архива слишком велик ({total_bytes} байт); установка пропущена."
        )
        return [], list(names)

    suffix = ".apk" if target_manager == "apk" else ".ipk"
    bundle = Path(workdir) / "migration-packages.tar.gz"
    component = parsed.component("packages_binaries")
    if component is None:
        return [], list(names)
    selected_files = {filename: (name, size) for name, filename, size in selected}
    written = set()
    with archive.open_zip(archive_path) as zf:
        with zf.open(component.path) as component_file:
            with archive.open_tar_gz(fileobj=component_file) as src:
                with tarfile.open(bundle, "w:gz") as dst:
                    seen_source = set()
                    for member in _bounded_tar_members(src):
                        filename = _normalise_member_name(member.name)
                        selected_file = selected_files.get(filename)
                        if selected_file is None:
                            continue
                        if filename in seen_source:
                            raise fail(
                                "OWBM-E-CHK-002",
                                reason=f"повторяющийся пакетный файл {filename}",
                            )
                        seen_source.add(filename)
                        name, expected_size = selected_file
                        handle = src.extractfile(member)
                        if not member.isfile() or member.size != expected_size or handle is None:
                            raise OwbmError(
                                "OWBM-E-CHK-002",
                                reason=f"повреждён пакетный файл {filename} в архиве",
                            )
                        info = tarfile.TarInfo(name + suffix)
                        info.size = member.size
                        info.mode = 0o600
                        info.mtime = 0
                        dst.addfile(info, handle)
                        written.add(name)
    if written != set(selected_names):
        bundle.unlink(missing_ok=True)
        return [], list(names)

    stage = (root or "") + "/tmp/owbm-migrate-packages-" + uuid.uuid4().hex
    log_path = stage + "/install.log"
    literals = " ".join(shlex.quote(stage + "/" + name + suffix) for name in selected_names)
    install = (
        f"apk add --allow-untrusted --force-non-repository {literals}"
        if target_manager == "apk"
        else f"opkg install {literals}"
    )
    try:
        setup = "umask 077\nmkdir -p " + shlex.quote(stage) + "\necho READY=1\n"
        client.run(build_script(setup, root=root), timeout=60, allow_failure=False)
        send_file(client, "tar -xzpf - -C " + shlex.quote(stage), bundle)
        body = (
            'set -u\nPATH="/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"\n'
            f"if {install} > {shlex.quote(log_path)} 2>&1; then echo INSTALL=ok; "
            f"else echo INSTALL=fail; tail -6 {shlex.quote(log_path)} 2>/dev/null; fi\n"
            + "for n in " + " ".join(shlex.quote(name) for name in selected_names) + "; do\n"
            + ('  apk info -e "$n" >/dev/null 2>&1 && echo "INSTALLED=$n" || echo "FAILED=$n"\n'
               if target_manager == "apk" else
               '  opkg list-installed "$n" 2>/dev/null | grep -q . && echo "INSTALLED=$n" || echo "FAILED=$n"\n')
            + "done\n"
        )
        response = client.run(build_script(body, root=root), timeout=900, allow_failure=True)
        if response.rc != 0 or "INSTALL=ok" not in response.out:
            installed, failed = [], list(selected_names)
        else:
            installed = [line.partition("=")[2] for line in response.out.splitlines() if line.startswith("INSTALLED=")]
            failed = [line.partition("=")[2] for line in response.out.splitlines() if line.startswith("FAILED=")]
            confirmed = set(installed) | set(failed)
            failed.extend(name for name in selected_names if name not in confirmed)
        failed.extend(name for name in missing_names if name not in failed)
        if not failed and len(installed) == len(selected):
            logger.ok(f"Установлено из архива: {len(installed)} пакетов")
        else:
            detail = " ".join(
                line.strip() for line in response.out.splitlines()
                if line.strip() and not line.startswith(("INSTALLED=", "FAILED=", "INSTALL="))
            )[-300:]
            logger.warn("Не все пакетные файлы из архива установлены" + (f": {detail}" if detail else "."))
        return installed, failed
    finally:
        cleanup = "rm -rf " + shlex.quote(stage) + "\necho CLEAN=1\n"
        try:
            client.run(build_script(cleanup, root=root), timeout=60, allow_failure=True)
        except Exception as exc:  # cleanup must not mask the install/transfer result
            logger.warn(f"Не удалось очистить временный каталог пакетов: {exc}")


def _validate_pre_restore_archive(
    path: Path,
    workdir: Path,
    expected_device: Optional[Dict[str, str]] = None,
) -> None:
    report = archive.verify_archive(path, deep=False)
    report.raise_first()
    parsed = manifest_mod.validate(report.manifest or {})
    if parsed.mode != "pre-restore":
        raise fail(
            "OWBM-E-RST-001",
            step="pre-restore",
            reason="передан не снимок pre-restore цели",
        )
    for key, expected in (expected_device or {}).items():
        if expected and str(parsed.device.get(key, "")) != expected:
            raise fail(
                "OWBM-E-RST-001",
                step="pre-restore",
                reason=f"снимок относится к другому устройству ({key})",
            )
    component = parsed.component("configuration")
    if component is None:
        raise fail(
            "OWBM-E-RST-001",
            step="pre-restore",
            reason="снимок цели не содержит конфигурацию",
        )
    if component.path != "payload/configuration.tar.gz":
        raise fail(
            "OWBM-E-RST-001",
            step="pre-restore",
            reason="компонент configuration ссылается на неожиданный файл",
        )

    try:
        checksums = archive._parse_checksums(
            archive.read_member(path, archive.CHECKSUMS_NAME).decode("utf-8")
        )
        with archive.open_zip(path) as zf:
            expected_checksum = checksums.get(component.path)
            if expected_checksum != component.sha256:
                raise fail(
                    "OWBM-E-RST-001",
                    step="pre-restore",
                    reason="контрольные суммы конфигурации в снимке не совпадают",
                )
            digest = hashlib.sha256()
            with zf.open(component.path) as payload_stream:
                for block in iter(lambda: payload_stream.read(1 << 20), b""):
                    digest.update(block)
            if digest.hexdigest() != expected_checksum:
                raise fail(
                    "OWBM-E-RST-001",
                    step="pre-restore",
                    reason="контрольная сумма конфигурации снимка не прошла проверку",
                )
    except (OSError, zipfile.BadZipFile, KeyError, UnicodeDecodeError) as exc:
        raise fail(
            "OWBM-E-RST-001",
            step="pre-restore",
            reason=f"не удалось проверить конфигурацию снимка: {exc}",
        )

    validation_dir = Path(workdir) / "pre-restore-validation"
    try:
        payload = archive.extract_member(path, component.path, validation_dir)
        from .backup.collector import inspect_tar

        inspect_tar(payload)
    finally:
        shutil.rmtree(validation_dir, ignore_errors=True)


def apply_plan(
    client,
    plan: MigratePlan,
    parsed: Manifest,
    archive_path: Path,
    workdir: Path,
    options: MigrateOptions,
    logger,
    *,
    root: str = "",
    pre_restore_archive: Optional[Path] = None,
) -> MigrateResult:
    result = MigrateResult(plan=plan)
    if options.install_packages != plan.install_packages_enabled:
        raise fail("OWBM-E-MIG-001")
    if options.dry_run:
        result.messages.append("Пробный прогон: изменений не вносилось.")
        return result
    changes_planned = bool(
        plan.configs_copy
        or plan.files_copy
        or (options.install_packages and (plan.packages_install or plan.packages_archive_install))
    )
    current_passport = None
    if changes_planned and pre_restore_archive is None:
        raise fail(
            "OWBM-E-RST-001",
            step="pre-restore",
            reason="применение без снимка цели запрещено",
        )
    if changes_planned and pre_restore_archive is not None:
        if not plan.target_identity or not any(plan.target_identity.values()):
            raise fail("OWBM-E-MIG-002")
        current_passport = discover(client, root=root)
        current_identity = _passport_identity(current_passport)
        if any(
            expected and current_identity.get(key, "") != expected
            for key, expected in plan.target_identity.items()
        ):
            raise fail("OWBM-E-MIG-002")
        _validate_pre_restore_archive(pre_restore_archive, workdir, plan.target_identity)
    reload_sensitive = {"network", "firewall", "dropbear", "wireless"} & set(plan.configs_copy)
    if options.reload and reload_sensitive:
        raise fail(
            "OWBM-E-CMP-003",
            reason=(
                "--reload запрещён при замене network/firewall/dropbear/wireless без удалённого сторожа; "
                "выполните применение только при локальном доступе"
            ),
        )
    payloads = source_configs(archive_path)

    if options.install_packages and plan.packages_install:
        logger.step(f"Установка {len(plan.packages_install)} пакетов из репозиториев цели")
        installed, failed = _install(
            client, plan.packages_install, manager=current_passport.packages.manager, logger=logger
        )
        result.installed = installed
        result.install_failed = failed
        if failed:
            result.ok = False
            result.messages.append(
                "Не удалось установить из репозиториев: " + ", ".join(failed[:20])
                + (" и другие" if len(failed) > 20 else "")
            )

    if options.install_packages and plan.packages_archive_install:
        logger.step(f"Установка {len(plan.packages_archive_install)} совместимых пакетов из архива")
        source_manager, source_arch, _records = source_package_inventory(archive_path)
        installed, failed = _install_archive_packages(
            client,
            parsed,
            archive_path,
            workdir,
            plan.packages_archive_install,
            source_manager=source_manager,
            source_arch=source_arch or str(parsed.compatibility_key.get("arch", "")),
            source_release=str(parsed.device.get("release", "")),
            source_target=str(parsed.device.get("target", "")),
            target_manager=current_passport.packages.manager,
            target_arch=current_passport.packages.arch or current_passport.identity.arch,
            target_release=current_passport.identity.release,
            target_target=current_passport.identity.target,
            logger=logger,
            root=root,
        )
        result.installed_from_archive = installed
        result.archive_install_failed = failed
        if failed:
            result.ok = False
            result.messages.append("Не удалось установить из архива: " + ", ".join(failed[:20]))

    config_write_started = False
    configs_attempted: List[str] = []
    try:
        for name in plan.configs_copy:
            key = CONFIG_PREFIX + name
            data = payloads.get(key)
            if data is None:
                continue
            source = Path(workdir) / f"cfg-{name}"
            source.write_bytes(data)
            dest = (root or "") + "/etc/config/" + name
            command = f"cat > {shlex.quote(dest)}"
            config_write_started = True
            configs_attempted.append(name)
            send_file(client, command, source, allow_empty=True)
            result.configs_written.append(name)
            logger.debug(f"скопирован конфиг: {name}")

        if result.configs_written:
            logger.ok(f"Конфигов скопировано: {len(result.configs_written)}")

        if result.plan.files_copy:
            restored = copy_files(client, parsed, archive_path, workdir, result.plan.files_copy, logger, root=root)
            result.files_written = restored
            logger.ok(f"Файлов приложений скопировано: {len(restored)}")
    except Exception as exc:
        result.ok = False
        result.messages.append(f"Перенос прерван: {exc}")
        if config_write_started and pre_restore_archive is not None:
            try:
                _rollback_configuration(
                    client, pre_restore_archive, workdir, logger,
                    names=configs_attempted, root=root,
                )
                result.messages.append("Конфигурация цели возвращена из снимка pre-restore.")
            except Exception as rollback_exc:
                result.messages.append(f"Не удалось автоматически вернуть конфигурацию: {rollback_exc}")
        return result

    if options.reload and (result.configs_written or result.installed or result.installed_from_archive):
        logger.info("Применяю конфигурацию (reload_config)…")
        try:
            _reload_configuration(client)
        except Exception as exc:
            result.ok = False
            result.messages.append(f"Не удалось подтвердить reload_config: {exc}")
            if config_write_started and pre_restore_archive is not None:
                try:
                    _rollback_configuration(
                        client, pre_restore_archive, workdir, logger,
                        names=configs_attempted, root=root,
                    )
                    try:
                        _reload_configuration(client)
                        result.messages.append(
                            "Конфигурация и службы возвращены к состоянию pre-restore."
                        )
                    except Exception as reload_exc:
                        result.messages.append(
                            "Файлы конфигурации возвращены, но не удалось применить их: "
                            f"{reload_exc}"
                        )
                except Exception as rollback_exc:
                    result.messages.append(f"Не удалось автоматически вернуть конфигурацию: {rollback_exc}")
            return result
    elif result.configs_written or result.installed or result.installed_from_archive:
        result.messages.append(
            "Изменения записаны, но службы не перезапускались. "
            "Примените их перезагрузкой устройства или флагом --reload."
        )
    return result


def copy_files(client, parsed: Manifest, archive_path: Path, workdir: Path, wanted: Sequence[str], logger, *, root: str = "") -> List[str]:
    """Stream selected non-binary files into a bounded-memory transfer bundle."""
    if not wanted:
        return []
    wanted_set = set(wanted)
    bundle = Path(workdir) / "files.tar.gz"
    written = []
    with archive.open_zip(archive_path) as zf, tarfile.open(bundle, "w:gz") as tf:
        for component in parsed.components:
            if component.id not in FILE_PAYLOAD_IDS:
                continue
            try:
                payload = zf.open(component.path)
            except KeyError:
                continue
            with payload, archive.open_tar_gz(fileobj=payload) as src:
                for member in archive.bounded_tar_members(src):
                    name = member.name
                    while name.startswith("./"):
                        name = name[2:]
                    if (
                        name not in wanted_set
                        or name in written
                        or not member.isfile()
                        or member.size < 0
                        or member.size > MAX_FILE_BYTES
                    ):
                        continue
                    handle = src.extractfile(member)
                    if handle is None:
                        continue
                    info = tarfile.TarInfo(name)
                    info.size = member.size
                    info.mode = member.mode & 0o777
                    info.mtime = 0
                    tf.addfile(info, handle)
                    written.append(name)
    if not written:
        return []
    send_file(client, "tar -xzpf - -C " + shlex.quote((root or "") + "/"), bundle)
    return written


def _snapshot_config_names(payload: Path) -> Set[str]:
    """Configuration filenames present in sysupgrade or fallback backup tar."""
    names = set()
    with archive.open_tar_gz(payload) as tf:
        for member in archive.bounded_tar_members(tf):
            if not member.isfile():
                continue
            parts = [part for part in _normalise_member_name(member.name).split("/") if part]
            if len(parts) >= 2 and parts[-2] == "config":
                name = parts[-1]
                if CONFIG_NAME_RE.match(name):
                    names.add(name)
    return names


def _reload_configuration(client) -> None:
    result = client.run(
        'set -u\nPATH="/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"\n'
        "if reload_config >/dev/null 2>&1; then echo 'RELOADED=1'; "
        "else echo 'RELOADED=0'; exit 1; fi\n",
        timeout=180,
        allow_failure=True,
    )
    if result.rc != 0 or "RELOADED=1" not in result.out:
        raise fail(
            "OWBM-E-RST-001",
            step="reload_config",
            reason="цель не подтвердила применение конфигурации",
        )


def _rollback_configuration(
    client,
    snapshot: Path,
    workdir: Path,
    logger,
    *,
    names: Sequence[str] = (),
    root: str = "",
) -> None:
    """Restore configuration and remove newly-created files from pre-restore."""
    report = archive.verify_archive(snapshot)
    report.raise_first()
    parsed = manifest_mod.validate(report.manifest or {})
    if parsed.mode != "pre-restore":
        raise fail("OWBM-E-CHK-002", reason="передан архив не в режиме pre-restore")
    component = parsed.component("configuration")
    if component is None or component.path != "payload/configuration.tar.gz":
        raise fail("OWBM-E-CHK-002", reason="в снимке pre-restore нет конфигурации")
    payload = archive.extract_member(
        snapshot, component.path, Path(workdir) / "rollback"
    )
    from .backup.collector import inspect_tar

    inspect_tar(payload)
    snapshot_names = _snapshot_config_names(payload)
    new_names = sorted({name for name in names if CONFIG_NAME_RE.match(name)} - snapshot_names)
    if new_names:
        body = "set -u\n"
        for name in new_names:
            target = (root or "") + "/etc/config/" + name
            body += f"if [ -f {shlex.quote(target)} ] || [ -L {shlex.quote(target)} ]; then rm -f -- {shlex.quote(target)}; fi\n"
        client.run(build_script(body, root=root), timeout=60, allow_failure=False)
    send_file(client, "tar -xzpf - -C " + shlex.quote((root or "") + "/"), payload)
    logger.warn("Конфигурация восстановлена из pre-restore.")
