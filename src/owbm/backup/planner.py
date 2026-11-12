"""Backup planning: what can be captured, in which order, and what cannot.

The plan is a pure function of the device passport: no SSH, no side effects.
It is shown to the user before anything is collected, and it is what the tests
assert against.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Sequence, Tuple

from .. import capabilities
from ..capabilities import (
    LEVEL_CONFIG,
    LEVEL_EXACT,
    LEVEL_INVENTORY,
    LEVEL_UNSUPPORTED,
    CapabilityProfile,
)
from ..discovery import DevicePassport

MIB = 1024 * 1024


@dataclass(frozen=True)
class Step:
    id: str
    title: str
    critical: bool
    reason: str
    estimate: int = 0
    order: int = 10

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "critical": self.critical,
            "reason": self.reason,
            "estimate": self.estimate,
        }


@dataclass
class BackupPlan:
    steps: List[Step] = field(default_factory=list)
    skipped: List[Tuple[str, str]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def estimate_total(self) -> int:
        return sum(step.estimate for step in self.steps)

    def ids(self) -> List[str]:
        return [step.id for step in self.steps]

    def step(self, step_id: str) -> Step | None:
        for item in self.steps:
            if item.id == step_id:
                return item
        return None

    def as_dict(self) -> dict:
        return {
            "steps": [step.as_dict() for step in self.steps],
            "skipped": [{"id": item[0], "reason": item[1]} for item in self.skipped],
            "warnings": list(self.warnings),
            "estimate_total": self.estimate_total,
        }


def plan(
    passport: DevicePassport,
    profile: CapabilityProfile,
    *,
    include_package_binaries: bool = True,
    include_user_data: bool = True,
    user_data_paths: Sequence[str] = (),
    include_rootfs: bool = True,
) -> BackupPlan:
    result = BackupPlan()
    result.warnings.extend(profile.warnings)

    def add(step_id: str, title: str, critical: bool, reason: str, estimate: int, order: int) -> None:
        result.steps.append(
            Step(id=step_id, title=title, critical=critical, reason=reason, estimate=estimate, order=order)
        )

    def skip(step_id: str, reason: str) -> None:
        result.skipped.append((step_id, reason))

    # 1. configuration ------------------------------------------------------
    if profile.configuration.usable:
        add(
            "configuration",
            "Конфигурация OpenWrt",
            True,
            profile.configuration.reason,
            int(2 * MIB),
            10,
        )
    else:
        skip("configuration", profile.configuration.reason)
        result.warnings.append(
            "Конфигурация не будет сохранена: без неё архив не позволит восстановить устройство."
        )

    # 2. package inventory --------------------------------------------------
    if profile.packages_inventory.usable:
        add("packages_inventory", "Список установленных пакетов", True, profile.packages_inventory.reason, int(1 * MIB), 20)
    else:
        skip("packages_inventory", profile.packages_inventory.reason)

    # 3. overlay ------------------------------------------------------------
    has_upper = bool(passport.storage.overlay and passport.storage.overlay.upperdir)
    if profile.overlay_upper.usable and not has_upper:
        skip(
            "overlay_upper",
            "на устройстве нет записываемого слоя OverlayFS: сохраняются конфигурация, "
            "список пакетов и явно выбранные каталоги",
        )
    elif profile.overlay_upper.usable:
        add(
            "overlay_upper",
            "Файлы системы и приложений",
            profile.overlay_upper.level == LEVEL_EXACT,
            profile.overlay_upper.reason,
            int(32 * MIB),
            30,
        )
    else:
        skip("overlay_upper", profile.overlay_upper.reason)

    # 3b. root filesystem (no OverlayFS) -----------------------------------
    if profile.rootfs.usable and include_rootfs:
        add(
            "rootfs",
            "Файлы системы (корневая ФС)",
            True,
            profile.rootfs.reason,
            int(96 * MIB),
            35,
        )
    elif profile.rootfs.usable:
        skip("rootfs", "отключено параметром --no-rootfs")
    else:
        skip("rootfs", profile.rootfs.reason)

    # 4. package binaries ---------------------------------------------------
    if include_package_binaries and profile.packages_binaries.usable:
        estimate = int(min(passport.packages.count * 200 * 1024, 2048 * MIB)) or int(4 * MIB)
        add("packages_binaries", "Пакеты для восстановления без интернета", False, profile.packages_binaries.reason, estimate, 40)
    elif include_package_binaries:
        skip("packages_binaries", profile.packages_binaries.reason)
    else:
        skip("packages_binaries", "отключено параметром --no-package-binaries")

    # 5. user data ----------------------------------------------------------
    if include_user_data and user_data_paths:
        if profile.user_data.level in (LEVEL_EXACT, LEVEL_CONFIG):
            add(
                "user_data",
                "Пользовательские каталоги",
                False,
                f"выбрано каталогов: {len(user_data_paths)}",
                int(16 * MIB),
                50,
            )
        else:
            skip("user_data", profile.user_data.reason)
    elif include_user_data:
        skip("user_data", "каталоги не выбраны (по умолчанию сохраняется только состояние системы)")
    else:
        skip("user_data", "отключено параметром --no-user-data")

    if profile.system_state.usable:
        add("system_state", "Службы, скрипты, автозапуск", False, profile.system_state.reason, int(2 * MIB), 60)
    else:
        skip("system_state", profile.system_state.reason)

    if not any(step.critical for step in result.steps):
        result.warnings.append(
            "Ни один критичный компонент не доступен: архив не будет создан."
        )
    if profile.overlay_upper.level == LEVEL_INVENTORY:
        result.warnings.append(
            "Файлы системы сохраняются частично: выбранный для устройства уровень — "
            + profile.overlay_upper.reason
        )
    result.steps.sort(key=lambda item: (item.order, item.id))
    return result


def describe(plan_obj: BackupPlan) -> List[str]:
    """Human-readable plan lines for the interface."""
    lines: List[str] = []
    from ..util import human_size

    for step in plan_obj.steps:
        marker = "!" if step.critical else "·"
        lines.append(
            f"  {marker} {step.title:<38} ~{human_size(step.estimate):>9}  {step.reason}"
        )
    for step_id, reason in plan_obj.skipped:
        lines.append(f"  – {step_id:<38} {'пропущено':>10}  {reason}")
    return lines
