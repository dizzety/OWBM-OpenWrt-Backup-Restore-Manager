"""manifest.json: the single source of truth about an archive.

Rules:
* additive changes stay within a format version; readers ignore unknown fields;
* anything missing or inconsistent is an error, never a silently empty value;
* the manifest never contains paths, user names or addresses of the machine that
  created the archive.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from . import FORMAT_NAME, FORMAT_VERSION, MAX_READABLE_FORMAT_VERSION, __version__
from .errors import fail
from .util import parse_iso

STATUS_COMPLETE = "complete"
STATUS_PARTIAL = "partial"
STATUS_FAILED = "failed"
STATUSES = (STATUS_COMPLETE, STATUS_PARTIAL, STATUS_FAILED)

PORTABILITY_PORTABLE = "portable"
PORTABILITY_DEVICE = "device-bound"

COMPONENT_IDS = (
    "configuration",
    "overlay_upper",
    "rootfs",
    "packages_inventory",
    "packages_binaries",
    "user_data",
    "application_data",
    "system_state",
)

_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


@dataclass(frozen=True)
class Component:
    id: str
    path: str
    support_level: str
    portability: str
    critical: bool
    sha256: str
    size: int
    uncompressed_size: int = 0
    members: int = 0
    restore_order: int = 10
    excluded: Sequence[Mapping[str, str]] = ()
    notes: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "path": self.path,
            "support_level": self.support_level,
            "portability": self.portability,
            "critical": self.critical,
            "sha256": self.sha256,
            "size": self.size,
            "uncompressed_size": self.uncompressed_size,
            "members": self.members,
            "restore_order": self.restore_order,
            "excluded": list(self.excluded),
            "notes": self.notes,
        }


@dataclass
class Manifest:
    archive_id: str
    created_utc: str
    mode: str
    device: Dict[str, Any]
    capabilities_snapshot: Dict[str, Any]
    components: List[Component]
    inventory: Dict[str, Any]
    compatibility_key: Dict[str, Any]
    completeness: Dict[str, Any]
    clock_warning: Optional[str] = None
    secrets_present: bool = True
    encrypted_members: Sequence[str] = ()
    format: str = FORMAT_NAME
    format_version: int = FORMAT_VERSION
    tool: Dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "format": self.format,
            "format_version": self.format_version,
            "archive_id": self.archive_id,
            "created_utc": self.created_utc,
            "clock_warning": self.clock_warning,
            "tool": dict(self.tool or {"name": "owbm", "version": __version__}),
            "mode": self.mode,
            "device": dict(self.device),
            "capabilities_snapshot": dict(self.capabilities_snapshot),
            "components": [item.as_dict() for item in self.components],
            "inventory": dict(self.inventory),
            "compatibility_key": dict(self.compatibility_key),
            "completeness": dict(self.completeness),
            "secrets_present": bool(self.secrets_present),
            "encrypted_members": list(self.encrypted_members),
        }

    def component(self, component_id: str) -> Optional[Component]:
        for item in self.components:
            if item.id == component_id:
                return item
        return None

    @property
    def status(self) -> str:
        return str(self.completeness.get("status", STATUS_FAILED))


def _require(data: Mapping[str, Any], key: str, kind: type, where: str = "manifest.json") -> Any:
    if key not in data:
        raise fail("OWBM-E-CHK-002", reason=f"{where}: отсутствует поле {key}")
    value = data[key]
    if not isinstance(value, kind):
        raise fail("OWBM-E-CHK-002", reason=f"{where}: поле {key} имеет неверный тип")
    return value


def validate(data: Mapping[str, Any]) -> Manifest:
    """Strict validation of an untrusted manifest."""
    if not isinstance(data, Mapping):
        raise fail("OWBM-E-CHK-002", reason="manifest.json имеет неверную структуру")
    if data.get("format") != FORMAT_NAME:
        raise fail("OWBM-E-ARC-001", path="manifest.json")
    version = data.get("format_version")
    if not isinstance(version, int) or version < 1:
        raise fail("OWBM-E-CHK-002", reason="отсутствует корректная версия формата")
    if version > MAX_READABLE_FORMAT_VERSION:
        raise fail("OWBM-E-FMT-001", version=version, supported=MAX_READABLE_FORMAT_VERSION)

    archive_id = str(_require(data, "archive_id", str))
    if not _UUID_RE.match(archive_id):
        raise fail("OWBM-E-CHK-002", reason="archive_id не является UUID")
    created = str(_require(data, "created_utc", str))
    if parse_iso(created) is None:
        raise fail("OWBM-E-CHK-002", reason="created_utc не является корректной датой ISO-8601")

    mode = str(_require(data, "mode", str))
    if mode not in ("backup", "pre-restore", "migration"):
        raise fail("OWBM-E-CHK-002", reason=f"неизвестное назначение архива: {mode}")

    device = _require(data, "device", dict)
    for key in ("board_id", "arch"):
        if key not in device:
            raise fail("OWBM-E-CHK-002", reason=f"в манифесте нет сведений об устройстве: {key}")

    raw_components = _require(data, "components", list)
    if not raw_components:
        raise fail("OWBM-E-CHK-002", reason="манифест не описывает ни одного компонента")
    components: List[Component] = []
    seen = set()
    for raw in raw_components:
        if not isinstance(raw, Mapping):
            raise fail("OWBM-E-CHK-002", reason="компонент имеет неверный тип")
        component_id = str(raw.get("id", ""))
        if component_id not in COMPONENT_IDS:
            raise fail("OWBM-E-CHK-002", reason=f"неизвестный компонент архива: {component_id or 'пусто'}")
        if component_id in seen:
            raise fail("OWBM-E-CHK-002", reason=f"компонент повторяется: {component_id}")
        seen.add(component_id)
        path = str(raw.get("path", ""))
        if not path.startswith("payload/") and not path.startswith("inventory/"):
            raise fail("OWBM-E-CHK-002", reason=f"компонент {component_id} ссылается на недопустимый путь")
        digest = str(raw.get("sha256", ""))
        if len(digest) != 64:
            raise fail("OWBM-E-CHK-002", reason=f"компонент {component_id} без корректной контрольной суммы")
        size = raw.get("size")
        if not isinstance(size, int) or size <= 0:
            raise fail("OWBM-E-CHK-002", reason=f"компонент {component_id} имеет неверный размер")
        components.append(
            Component(
                id=component_id,
                path=path,
                support_level=str(raw.get("support_level", "")),
                portability=str(raw.get("portability", PORTABILITY_PORTABLE)),
                critical=bool(raw.get("critical", False)),
                sha256=digest,
                size=size,
                uncompressed_size=int(raw.get("uncompressed_size", 0) or 0),
                members=int(raw.get("members", 0) or 0),
                restore_order=int(raw.get("restore_order", 10) or 10),
                excluded=tuple(raw.get("excluded", ()) or ()),
                notes=str(raw.get("notes", "")),
            )
        )
    components.sort(key=lambda item: (item.restore_order, item.id))

    completeness = _require(data, "completeness", dict)
    status = completeness.get("status")
    if status not in STATUSES:
        raise fail("OWBM-E-CHK-002", reason="неизвестный статус завершённости архива")

    compatibility_key = _require(data, "compatibility_key", dict)
    inventory = data.get("inventory") or {}
    if not isinstance(inventory, dict):
        raise fail("OWBM-E-CHK-002", reason="поле inventory имеет неверный тип")

    return Manifest(
        archive_id=archive_id,
        created_utc=created,
        mode=mode,
        device=dict(device),
        capabilities_snapshot=dict(data.get("capabilities_snapshot") or {}),
        components=components,
        inventory=dict(inventory),
        compatibility_key=dict(compatibility_key),
        completeness=dict(completeness),
        clock_warning=data.get("clock_warning"),
        secrets_present=bool(data.get("secrets_present", True)),
        encrypted_members=tuple(data.get("encrypted_members") or ()),
        format=FORMAT_NAME,
        format_version=version,
        tool=dict(data.get("tool") or {}),
    )


def compatibility_key(device: Mapping[str, Any], capabilities: Mapping[str, Any]) -> Dict[str, Any]:
    """The minimal set of facts used for a first-pass compatibility check."""
    layer = str(device.get("writable_layer") or "")
    if not layer:
        storage = capabilities.get("storage") or {}
        overlay = storage.get("overlay") or {}
        if overlay.get("upperdir"):
            layer = "overlayfs"
        elif storage.get("extroot"):
            layer = "extroot"
        else:
            layer = "filesystem"
    return {
        "board_id": device.get("board_id", ""),
        "target": device.get("target", ""),
        "arch": device.get("arch", ""),
        "kernel_release": device.get("kernel_release", ""),
        "kernel_package": device.get("kernel_package", ""),
        "package_manager": device.get("package_manager", "none"),
        "writable_layer": layer,
    }


def build(
    *,
    archive_id: str,
    created_utc: str,
    mode: str,
    device: Mapping[str, Any],
    capabilities_snapshot: Mapping[str, Any],
    components: Iterable[Component],
    inventory: Mapping[str, Any],
    status: str,
    stages: Sequence[Mapping[str, str]] = (),
    warnings: Sequence[str] = (),
    clock_warning: Optional[str] = None,
    secrets_present: bool = True,
) -> Manifest:
    component_list = sorted(list(components), key=lambda item: (item.restore_order, item.id))
    completeness = {
        "status": status,
        "stages": [dict(item) for item in stages],
        "warnings": list(warnings),
    }
    return Manifest(
        archive_id=archive_id,
        created_utc=created_utc,
        mode=mode,
        device=dict(device),
        capabilities_snapshot=dict(capabilities_snapshot),
        components=component_list,
        inventory=dict(inventory),
        compatibility_key=compatibility_key(device, capabilities_snapshot),
        completeness=completeness,
        clock_warning=clock_warning,
        secrets_present=secrets_present,
        tool={"name": "owbm", "version": __version__},
    )
