"""Device discovery: build a passport of the device without changing anything.

The remote part is a single POSIX-sh script that only reads files and runs
read-only commands. All interpretation happens on the client, so the logic is
testable without a device and without root.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .adapters import apk, filesystem, mountinfo, opkg, overlayfs, sysupgrade
from .adapters.apk import PackageEntry
from .adapters.mountinfo import MountEntry
from .errors import fail
from .remote import ProbeResult, run_probe
from .util import parse_iso

_RELEASE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")

DISCOVERY_SCRIPT = r"""
set -u
PATH="/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
PATH="${OWBM_PATH_PREPEND:+${OWBM_PATH_PREPEND}:}${PATH}"
R="${OWBM_ROOT:-}"

emit() { printf '%s=%s\n' "$1" "$2"; }
has() { command -v "$1" >/dev/null 2>&1; }
exists() { if [ -e "$R$1" ]; then printf yes; else printf no; fi; }
first_line() {
  [ -r "$R$1" ] || return 0
  _v=""
  IFS= read -r _v < "$R$1" || true
  printf '%s' "$_v"
}
file_lines() {
  _f="$R$2"
  [ -r "$_f" ] || return 0
  while IFS= read -r _l || [ -n "$_l" ]; do emit "$1" "$_l"; done < "$_f"
}
cmd_lines() {
  _k="$1"; shift
  has "$1" || { emit CMD_MISSING "$1"; return 0; }
  "$@" 2>/dev/null | while IFS= read -r _l || [ -n "$_l" ]; do emit "$_k" "$_l"; done
}

emit PASS 1
emit OS_RELEASE_FILE "$(exists /etc/openwrt_release)"
emit ETC_CONFIG "$(exists /etc/config)"
emit OVERLAY_ROOT "$(exists /overlay)"
emit OVERLAY_UPPER "$(exists /overlay/upper)"
emit OVERLAY_WORK "$(exists /overlay/work)"
emit UPGRADE_KEEP "$(exists /lib/upgrade/keep.d)"
emit EXTROOT_UUID "$(exists /etc/.extroot-uuid)"
emit DROPBEAR_CONFIG "$(exists /etc/config/dropbear)"
emit AUTHORIZED_KEYS "$(exists /etc/dropbear/authorized_keys)"
emit UID "$(id -u 2>/dev/null || printf unknown)"

file_lines REL /etc/openwrt_release
file_lines BOARDJSON /etc/board.json
file_lines FSTAB /etc/config/fstab
emit BOARDNAME "$(first_line /tmp/sysinfo/board_name)"
file_lines MOUNT /proc/self/mountinfo
file_lines MOUNTS /proc/mounts
file_lines FILESYSTEMS /proc/filesystems
file_lines MEMINFO /proc/meminfo
emit UPTIME "$(first_line /proc/uptime)"
emit KERNEL_HOSTNAME "$(first_line /proc/sys/kernel/hostname)"
emit TIME_UTC "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)"
emit APK_ARCH_FILE "$(first_line /etc/apk/arch)"
file_lines APKREPO /etc/apk/repositories
file_lines APKWORLD /etc/apk/world
for _f in "$R"/etc/apk/repositories.d/*; do
  [ -f "$_f" ] || continue
  emit REPO_FILE "${_f#"$R"}"
  while IFS= read -r _l || [ -n "$_l" ]; do emit APKREPO "$_l"; done < "$_f"
done
for _f in "$R"/etc/opkg/*.conf; do
  [ -f "$_f" ] || continue
  emit OPKG_FILE "${_f#"$R"}"
  while IFS= read -r _l || [ -n "$_l" ]; do emit OPKGCONF "$_l"; done < "$_f"
done
file_lines APKDB /lib/apk/db/installed
file_lines OPKGDB /usr/lib/opkg/status
file_lines OPKGWORLD /etc/opkg/user-installed

for _t in ssh tar gzip sha256sum md5sum find awk sed sort xargs df uci ubus jsonfilter \
          sysupgrade opkg apk mktemp nohup setsid at crontab flock ip iw iwinfo logread \
          dropbear reboot sync base64; do
  has "$_t" && emit TOOL "$_t"
done

for _p in "$R"/sys/class/net/*; do
  [ -e "$_p" ] || continue
  _n="${_p##*/}"
  _a="$(cat "$_p/address" 2>/dev/null || true)"
  _s="$(cat "$_p/operstate" 2>/dev/null || true)"
  case "$_a" in ''|00:00:00:00:00:00|ff:ff:ff:ff:ff:ff) continue ;; esac
  emit NET "$_n $_a $_s"
done

cmd_lines DF df -Pk
cmd_lines KERNEL uname -r
cmd_lines MACHINE uname -m
cmd_lines APK_ARCH apk --print-arch
cmd_lines OPKG_ARCH opkg print-architecture
cmd_lines UBUS_BOARD ubus call system board
cmd_lines SYS_UPGRADE_HELP sysupgrade -h
emit SYS_UPGRADE_PATH "$(has sysupgrade && command -v sysupgrade || true)"
emit DONE 1
"""


# --------------------------------------------------------------------------
# model
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Identity:
    system_type: str = "unknown"
    board_name: str = ""
    board_id: str = ""
    model: str = ""
    hostname: str = ""
    release: str = ""
    revision: str = ""
    target: str = ""
    arch: str = ""
    kernel_release: str = ""
    kernel_package: str = ""
    description: str = ""
    macs: Tuple[str, ...] = ()

    def as_dict(self) -> Dict[str, object]:
        return {
            "system_type": self.system_type,
            "board_name": self.board_name,
            "board_id": self.board_id,
            "model": self.model,
            "hostname": self.hostname,
            "release": self.release,
            "revision": self.revision,
            "target": self.target,
            "arch": self.arch,
            "kernel_release": self.kernel_release,
            "kernel_package": self.kernel_package,
            "description": self.description,
            "macs": list(self.macs),
        }


@dataclass(frozen=True)
class MountSummary:
    mountpoint: str
    fstype: str
    source: str
    kind: str
    writable: bool
    free_bytes: Optional[int] = None

    def as_dict(self) -> Dict[str, object]:
        return {
            "mountpoint": self.mountpoint,
            "fstype": self.fstype,
            "source": self.source,
            "kind": self.kind,
            "writable": self.writable,
            "free_bytes": self.free_bytes,
        }


@dataclass(frozen=True)
class NetIface:
    name: str
    mac: str
    state: str

    def as_dict(self) -> Dict[str, str]:
        return {"name": self.name, "mac": self.mac, "state": self.state}


@dataclass(frozen=True)
class OverlayInfo:
    mountpoint: str
    upperdir: str
    workdir: str
    lowerdirs: Tuple[str, ...]
    upper_fstype: str
    persistent: bool

    def as_dict(self) -> Dict[str, object]:
        return {
            "mountpoint": self.mountpoint,
            "upperdir": self.upperdir,
            "workdir": self.workdir,
            "lowerdirs": list(self.lowerdirs),
            "upper_fstype": self.upper_fstype,
            "persistent": self.persistent,
        }


@dataclass(frozen=True)
class StorageInfo:
    root_fstype: str = ""
    root_source: str = ""
    overlay: Optional[OverlayInfo] = None
    extroot: bool = False
    writable_persistent: bool = False
    writable_path: str = ""
    free_bytes_writable: Optional[int] = None
    tmp_path: str = "/tmp"
    tmp_free_bytes: Optional[int] = None
    mounts: Tuple[MountSummary, ...] = ()

    def as_dict(self) -> Dict[str, object]:
        return {
            "root_fstype": self.root_fstype,
            "root_source": self.root_source,
            "overlay": self.overlay.as_dict() if self.overlay else None,
            "extroot": self.extroot,
            "writable_persistent": self.writable_persistent,
            "writable_path": self.writable_path,
            "free_bytes_writable": self.free_bytes_writable,
            "tmp_path": self.tmp_path,
            "tmp_free_bytes": self.tmp_free_bytes,
            "mounts": [item.as_dict() for item in self.mounts],
        }


@dataclass(frozen=True)
class PackageInfo:
    manager: str = "none"
    version: str = ""
    arch: str = ""
    db_path: str = ""
    world: Tuple[str, ...] = ()
    repositories: Tuple[str, ...] = ()
    installed: Tuple[PackageEntry, ...] = ()
    arch_mismatch: Tuple[str, ...] = ()

    @property
    def count(self) -> int:
        return len(self.installed)

    def as_dict(self) -> Dict[str, object]:
        return {
            "manager": self.manager,
            "version": self.version,
            "arch": self.arch,
            "db_path": self.db_path,
            "world": list(self.world),
            "repositories": list(self.repositories),
            "count": self.count,
            "arch_mismatch": list(self.arch_mismatch),
        }


@dataclass(frozen=True)
class ToolSet:
    available: Tuple[str, ...] = ()
    sysupgrade: sysupgrade.SysupgradeInfo = field(default_factory=sysupgrade.SysupgradeInfo)

    def has(self, name: str) -> bool:
        return name in self.available

    def as_dict(self) -> Dict[str, object]:
        return {
            "available": list(self.available),
            "sysupgrade": self.sysupgrade.as_dict(),
        }


@dataclass(frozen=True)
class Resources:
    mem_total_kb: Optional[int] = None
    tmp_free_bytes: Optional[int] = None
    uptime_s: Optional[int] = None

    def as_dict(self) -> Dict[str, object]:
        return {
            "mem_total_kb": self.mem_total_kb,
            "tmp_free_bytes": self.tmp_free_bytes,
            "uptime_s": self.uptime_s,
        }


@dataclass(frozen=True)
class DeviceTime:
    utc: str = ""
    plausible: bool = True

    def as_dict(self) -> Dict[str, object]:
        return {"utc": self.utc, "plausible": self.plausible}


@dataclass(frozen=True)
class DevicePassport:
    identity: Identity = field(default_factory=Identity)
    storage: StorageInfo = field(default_factory=StorageInfo)
    packages: PackageInfo = field(default_factory=PackageInfo)
    tools: ToolSet = field(default_factory=ToolSet)
    resources: Resources = field(default_factory=Resources)
    time: DeviceTime = field(default_factory=DeviceTime)
    network: Tuple[NetIface, ...] = ()
    unknown: Tuple[str, ...] = ()
    warnings: Tuple[str, ...] = ()

    def as_dict(self) -> Dict[str, object]:
        return {
            "identity": self.identity.as_dict(),
            "storage": self.storage.as_dict(),
            "packages": self.packages.as_dict(),
            "tools": self.tools.as_dict(),
            "resources": self.resources.as_dict(),
            "time": self.time.as_dict(),
            "network": [item.as_dict() for item in self.network],
            "unknown": list(self.unknown),
            "warnings": list(self.warnings),
        }

    def label(self) -> str:
        return self.identity.board_id or self.identity.board_name or self.identity.hostname or "openwrt"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _unquote(value: str) -> str:
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def _release_vars(probe: ProbeResult) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for line in probe.all("REL"):
        match = _RELEASE_RE.match(line.strip())
        if match:
            result[match.group(1)] = _unquote(match.group(2))
    return result


def _json_lines(probe: ProbeResult, key: str) -> Optional[dict]:
    text = probe.text(key)
    if not text.strip():
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _parse_proc_mounts(lines: List[str]) -> List[MountEntry]:
    entries: List[MountEntry] = []
    for index, line in enumerate(lines, start=1):
        parts = line.split()
        if len(parts) < 4:
            continue
        entries.append(
            MountEntry(
                mount_id=index,
                parent_id=0,
                dev="",
                root="/",
                mountpoint=mountinfo.unescape(parts[1]),
                options=parts[3],
                fstype=parts[2],
                source=mountinfo.unescape(parts[0]),
                super_options=parts[3],
            )
        )
    return entries


def _parse_free_space(lines: List[str]) -> Dict[str, int]:
    result: Dict[str, int] = {}
    for line in lines:
        parts = line.split()
        if len(parts) < 6:
            continue
        if not (parts[1].isdigit() and parts[2].isdigit() and parts[3].isdigit()):
            continue
        mountpoint = " ".join(parts[5:])
        result[mountpoint] = int(parts[3]) * 1024
    return result


def _mem_total_kb(probe: ProbeResult) -> Optional[int]:
    for line in probe.all("MEMINFO"):
        if line.startswith("MemTotal:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1])
    return None


def _uptime_s(probe: ProbeResult) -> Optional[int]:
    raw = probe.one("UPTIME").split()
    if not raw:
        return None
    try:
        return int(float(raw[0]))
    except ValueError:
        return None


def _first_nonempty(values: List[str]) -> str:
    for value in values:
        text = value.strip()
        if text:
            return text
    return ""


def _detect_package_manager(probe: ProbeResult) -> str:
    tools = set(probe.all("TOOL"))
    if "apk" in tools or probe.all("APKDB"):
        return "apk"
    if "opkg" in tools or probe.all("OPKGDB"):
        return "opkg"
    return "none"


def _detect_extroot(probe: ProbeResult) -> bool:
    """extroot is a configuration fact, not a mount-table guess.

    A wiped flash with a USB drive attached looks exactly like a normal
    partition layout, so we only trust explicit markers: the extroot uuid file
    or an fstab mount section targeting /overlay.
    """
    if probe.one("EXTROOT_UUID") == "yes":
        return True
    in_mount = False
    for line in probe.all("FSTAB"):
        text = line.strip()
        if text.startswith("config "):
            in_mount = text.split(None, 1)[1].strip().strip("'\"") == "mount"
            continue
        if in_mount and text.startswith("option target"):
            parts = text.split(None, 2)
            if len(parts) == 3 and parts[2].strip().strip("'\"") == "/overlay":
                return True
    return False


# --------------------------------------------------------------------------
# passport assembly
# --------------------------------------------------------------------------
def build_passport(probe: ProbeResult) -> DevicePassport:
    warnings: List[str] = []
    unknown: List[str] = []

    if probe.malformed:
        warnings.append(f"Ответ устройства содержал {len(probe.malformed)} нераспознанных строк.")

    release = _release_vars(probe)
    board_json = _json_lines(probe, "BOARDJSON") or {}
    ubus = _json_lines(probe, "UBUS_BOARD") or {}

    release_file = probe.one("OS_RELEASE_FILE") == "yes"
    distrib_id = (release.get("DISTRIB_ID") or ubus.get("system", "") or "").strip()
    is_openwrt = release_file and ("openwrt" in distrib_id.lower() or not distrib_id or distrib_id.lower() == "openwrt")
    if not release_file:
        is_openwrt = False
        warnings.append("Файл /etc/openwrt_release не найден.")
    elif distrib_id and "openwrt" not in distrib_id.lower():
        warnings.append(f"Система сообщает о себе как «{distrib_id}»; похоже на форк OpenWrt.")

    model_info = board_json.get("model") if isinstance(board_json.get("model"), dict) else {}
    ubus_model = ubus.get("model") if isinstance(ubus.get("model"), dict) else {}
    ubus_release = ubus.get("release") if isinstance(ubus.get("release"), dict) else {}

    board_name = _first_nonempty(
        [probe.one("BOARDNAME"), str(board_json.get("board_name", "")), str(ubus.get("board_name", ""))]
    )
    model = _first_nonempty(
        [
            str(model_info.get("id", "")),
            str(ubus_model.get("id", "")),
            str(model_info.get("name", "")),
            str(ubus_model.get("name", "")),
        ]
    )
    hostname = _first_nonempty([probe.one("KERNEL_HOSTNAME"), str(ubus.get("hostname", ""))])
    if not hostname:
        hostname = "openwrt"
        unknown.append("hostname")

    arch = _first_nonempty(
        [
            probe.one("APK_ARCH"),
            release.get("DISTRIB_ARCH", ""),
            probe.one("APK_ARCH_FILE"),
            probe.one("OPKG_ARCH").split()[0] if probe.one("OPKG_ARCH") else "",
            probe.one("MACHINE"),
        ]
    )
    if not arch:
        unknown.append("arch")
        warnings.append("Не удалось определить архитектуру пакетов.")

    kernel = _first_nonempty(probe.all("KERNEL"))
    if not kernel:
        unknown.append("kernel_release")

    target = _first_nonempty([release.get("DISTRIB_TARGET", ""), str(ubus_release.get("target", ""))])
    version = _first_nonempty([release.get("DISTRIB_RELEASE", ""), str(ubus_release.get("version", ""))])
    revision = _first_nonempty([release.get("DISTRIB_REVISION", ""), str(ubus_release.get("revision", ""))])
    description = _first_nonempty(
        [release.get("DISTRIB_DESCRIPTION", ""), str(ubus_release.get("description", ""))]
    )
    if not version:
        unknown.append("release")
    if not board_name:
        unknown.append("board_name")
        warnings.append(
            "Устройство не сообщило идентификатор платы: привязка архива к модели будет неполной."
        )

    macs: List[str] = []
    interfaces: List[NetIface] = []
    for line in probe.all("NET"):
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[0]
        mac = parts[1]
        state = parts[2] if len(parts) > 2 else ""
        if name == "lo":
            continue
        interfaces.append(NetIface(name=name, mac=mac, state=state))
        if mac not in macs:
            macs.append(mac)

    manager = _detect_package_manager(probe)
    entries: List[PackageEntry] = []
    db_path = ""
    world: Tuple[str, ...] = ()
    repositories: Tuple[str, ...] = ()
    pkg_arch = ""
    if manager == "apk":
        entries = apk.parse_installed(probe.all("APKDB"))
        db_path = apk.DB_PATH
        world = tuple(apk.parse_world(probe.all("APKWORLD")))
        repositories = tuple(apk.parse_repositories(probe.all("APKREPO")))
        pkg_arch = arch
    elif manager == "opkg":
        entries = opkg.parse_status(probe.all("OPKGDB"))
        db_path = opkg.STATUS_PATH
        world = tuple(apk.parse_world(probe.all("OPKGWORLD")))
        repositories = tuple(opkg.parse_conf_files(probe.all("OPKGCONF")))
        pkg_arch = arch
    else:
        warnings.append("Пакетный менеджер не обнаружен: список пакетов сохранить не удастся.")

    kernel_package = ""
    for entry in entries:
        if entry.name == "kernel":
            kernel_package = entry.version
            break

    arch_mismatch = tuple(sorted({e.arch for e in entries if e.arch and arch and e.arch != arch and e.name != "kernel"}))
    if arch_mismatch:
        warnings.append(
            "В установленных пакетах встречаются архитектуры, отличные от системной: "
            + ", ".join(arch_mismatch)
        )

    mounts = mountinfo.parse(probe.all("MOUNT"))
    if not mounts:
        mounts = _parse_proc_mounts(probe.all("MOUNTS"))
        if mounts:
            warnings.append("Таблица mountinfo недоступна, использован /proc/mounts (меньше данных).")
    free_space = _parse_free_space(probe.all("DF"))

    def free_for(path: str) -> Optional[int]:
        entry = mountinfo.mount_for_path(mounts, path)
        if entry is None:
            return None
        if entry.mountpoint in free_space:
            return free_space[entry.mountpoint]
        for point, value in free_space.items():
            if point == entry.mountpoint.rstrip("/"):
                return value
        return None

    root = mountinfo.root_mount(mounts)
    root_fstype = root.fstype if root else ""
    root_source = root.source if root else ""
    if not root:
        unknown.append("root_mount")
        warnings.append("Не удалось определить корневую файловую систему.")

    overlay_mount = mountinfo.overlay_mount(mounts)
    layout = overlayfs.layout(overlay_mount)
    overlay_info: Optional[OverlayInfo] = None
    if layout is not None:
        upper_mount = mountinfo.mount_for_path(mounts, layout.upperdir) if layout.upperdir else None
        upper_fstype = upper_mount.fstype if upper_mount else ""
        persistent = bool(upper_mount and filesystem.is_persistent(upper_mount.fstype))
        if layout.upperdir:
            overlay_info = OverlayInfo(
                mountpoint=layout.mountpoint,
                upperdir=layout.upperdir,
                workdir=layout.workdir or "",
                lowerdirs=layout.lowerdirs,
                upper_fstype=upper_fstype,
                persistent=persistent,
            )
            if upper_mount and filesystem.is_ram(upper_mount.fstype):
                warnings.append(
                    "Верхний слой OverlayFS находится в оперативной памяти: изменения не сохранятся после перезагрузки."
                )
        else:
            warnings.append(
                "Обнаружен OverlayFS без записываемого верхнего слоя (upperdir): изменения не сохраняются."
            )

    if overlay_mount is None and root_fstype and not filesystem.is_persistent(root_fstype):
        if filesystem.classify(root_fstype) == "readonly":
            warnings.append(
                "Корневая ФС только для чтения и OverlayFS не обнаружен: "
                "пользовательские изменения на устройстве отсутствуют или хранятся иначе."
            )

    extroot = _detect_extroot(probe)
    if extroot and overlay_info is None:
        warnings.append(
            "Обнаружена конфигурация extroot, но OverlayFS не смонтирован: "
            "внешний носитель, вероятно, не подключён или не смонтирован."
        )

    writable_path = overlay_info.upperdir if overlay_info and overlay_info.upperdir else "/"
    writable_persistent = bool(
        overlay_info and overlay_info.persistent and not extroot
    ) or bool(extroot) or bool(root and filesystem.is_persistent(root.fstype))

    tmp_free = free_for("/tmp")
    if tmp_free is None:
        tmp_free = free_for("/")

    tools = tuple(sorted(set(probe.all("TOOL"))))
    sysupgrade_path = probe.one("SYS_UPGRADE_PATH").strip()
    if not sysupgrade_path and "sysupgrade" in tools:
        sysupgrade_path = "/sbin/sysupgrade"
    sys_info = sysupgrade.analyze(sysupgrade_path, probe.all("SYS_UPGRADE_HELP"))

    if "sha256sum" not in tools:
        warnings.append("На устройстве нет sha256sum: контрольные суммы считаются только на компьютере.")

    device_time = DeviceTime(utc=probe.one("TIME_UTC"), plausible=True)
    parsed_time = parse_iso(device_time.utc)
    if parsed_time is not None and parsed_time.year < 2020:
        device_time = DeviceTime(utc=device_time.utc, plausible=False)
        warnings.append("Часы устройства показывают дату раньше 2020 года.")

    passport = DevicePassport(
        identity=Identity(
            system_type="openwrt" if is_openwrt else "unknown",
            board_name=board_name,
            board_id=board_name,
            model=model,
            hostname=hostname,
            release=version,
            revision=revision,
            target=target,
            arch=arch,
            kernel_release=kernel,
            kernel_package=kernel_package,
            description=description,
            macs=tuple(macs),
        ),
        storage=StorageInfo(
            root_fstype=root_fstype,
            root_source=root_source,
            overlay=overlay_info,
            extroot=extroot,
            writable_persistent=writable_persistent,
            writable_path=writable_path,
            free_bytes_writable=free_for(writable_path),
            tmp_path="/tmp",
            tmp_free_bytes=tmp_free,
            mounts=tuple(
                MountSummary(
                    mountpoint=entry.mountpoint,
                    fstype=entry.fstype,
                    source=entry.source,
                    kind=filesystem.classify(entry.fstype),
                    writable=entry.writable,
                    free_bytes=free_space.get(entry.mountpoint),
                )
                for entry in mounts
            ),
        ),
        packages=PackageInfo(
            manager=manager,
            arch=pkg_arch,
            db_path=db_path,
            world=world,
            repositories=repositories,
            installed=tuple(entries),
            arch_mismatch=arch_mismatch,
        ),
        tools=ToolSet(available=tools, sysupgrade=sys_info),
        resources=Resources(
            mem_total_kb=_mem_total_kb(probe),
            tmp_free_bytes=tmp_free,
            uptime_s=_uptime_s(probe),
        ),
        time=device_time,
        network=tuple(interfaces),
        unknown=tuple(unknown),
        warnings=tuple(warnings),
    )
    return passport


QUICK_IDENTITY_SCRIPT = r"""
set -u
R="${OWBM_ROOT:-}"
ok=0
board="$(cat "$R/tmp/sysinfo/board_name" 2>/dev/null || true)"
[ -n "$board" ] || board="unknown"
printf 'BOARD=%s\n' "$board"
for p in "$R"/sys/class/net/*; do
  [ -e "$p" ] || continue
  n="${p##*/}"
  [ "$n" = "lo" ] && continue
  a="$(cat "$p/address" 2>/dev/null || true)"
  case "$a" in ''|00:00:00:00:00:00|ff:ff:ff:ff:ff:ff) continue ;; esac
  printf 'MAC=%s\n' "$a"
done
printf 'DONE=1\n'
"""


def quick_identity(client, *, root: str = "") -> Tuple[str, Tuple[str, ...]]:
    """Board name and MACs only — used to prove identity after a key change."""
    probe = run_probe(client, QUICK_IDENTITY_SCRIPT, root=root, timeout=60)
    if not probe.has("DONE"):
        raise fail("OWBM-E-DSC-002", stage="проверка идентичности", reason="устройство не ответило")
    return probe.one("BOARD", "unknown"), tuple(probe.all("MAC"))


def discover(client, *, root: str = "", logger=None, timeout: int = 120) -> DevicePassport:
    """Run the read-only probe and assemble the passport."""
    if logger:
        logger.debug("Опрос устройства (только чтение)")
    probe = run_probe(client, DISCOVERY_SCRIPT, root=root, timeout=timeout)
    if not probe.has("DONE"):
        raise fail("OWBM-E-DSC-002", stage="опрос устройства", reason="скрипт опроса не завершился")
    for missing in probe.all("CMD_MISSING"):
        if logger:
            logger.debug(f"на устройстве нет команды {missing}")
    passport = build_passport(probe)
    if passport.identity.system_type != "openwrt":
        raise fail("OWBM-E-DSC-001", host=client.target.host)
    return passport
