"""Restore planning: an ordered, explained list of steps. No side effects.

The plan is the dry run. It is produced from the archive manifest plus the target
passport only, so showing it can never change anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from ..discovery import DevicePassport
from ..manifest import Manifest
from ..util import human_size
from . import compatibility, migration
from .compatibility import CompatibilityReport

RISK_NONE = "none"
RISK_LOW = "low"
RISK_MEDIUM = "medium"
RISK_HIGH = "high"

RISK_MARK = {RISK_NONE: "·", RISK_LOW: "·", RISK_MEDIUM: "!", RISK_HIGH: "!!"}

COMPONENT_TITLES = {
    "configuration": "Конфигурация OpenWrt",
    "overlay_upper": "Файлы системы и приложений",
    "rootfs": "Файлы системы (корневая ФС)",
    "rootfs": "Файлы системы (корневая ФС)",
    "packages_inventory": "Список пакетов",
    "packages_binaries": "Бинарные пакеты",
    "user_data": "Пользовательские каталоги",
    "system_state": "Службы и скрипты",
    "application_data": "Данные приложений",
}

NOT_APPLIED = {"packages_inventory"}

COMPONENT_RISK = {
    "configuration": RISK_MEDIUM,
    "overlay_upper": RISK_HIGH,
    "rootfs": RISK_HIGH,
    "rootfs": RISK_HIGH,
    "packages_inventory": RISK_LOW,
    "packages_binaries": RISK_LOW,
    "user_data": RISK_LOW,
    "system_state": RISK_MEDIUM,
    "application_data": RISK_LOW,
}

NETWORK_COMPONENTS = ("configuration", "overlay_upper", "rootfs", "system_state")


@dataclass(frozen=True)
class PlanStep:
    id: str
    title: str
    order: int
    risk: str
    component: Optional[str] = None
    touches_network: bool = False
    size: int = 0
    detail: str = ""

    @property
    def mark(self) -> str:
        return RISK_MARK.get(self.risk, "·")

    def as_dict(self) -> Dict[str, object]:
        return {
            "id": self.id,
            "title": self.title,
            "order": self.order,
            "risk": self.risk,
            "component": self.component,
            "touches_network": self.touches_network,
            "size": self.size,
            "detail": self.detail,
        }


@dataclass
class RestorePlan:
    archive_path: Optional[Path]
    strategy: str
    report: CompatibilityReport
    steps: List[PlanStep] = field(default_factory=list)
    skipped: List[Dict[str, str]] = field(default_factory=list)
    adaptations: List[migration.Adaptation] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    blockers: List[str] = field(default_factory=list)
    reboot: bool = False

    @property
    def ok(self) -> bool:
        return not self.blockers

    @property
    def size_total(self) -> int:
        return sum(step.size for step in self.steps)

    @property
    def touches_network(self) -> bool:
        return any(step.touches_network for step in self.steps)

    def component_ids(self) -> List[str]:
        return [step.component for step in self.steps if step.component]

    def as_dict(self) -> Dict[str, object]:
        return {
            "strategy": self.strategy,
            "archive": str(self.archive_path) if self.archive_path else None,
            "compatible": self.report.as_dict(),
            "steps": [step.as_dict() for step in self.steps],
            "skipped": list(self.skipped),
            "adaptations": [item.as_dict() for item in self.adaptations],
            "warnings": list(self.warnings),
            "blockers": list(self.blockers),
            "reboot": self.reboot,
            "size_total": self.size_total,
        }

    def describe(self) -> List[str]:
        lines = ["Порядок действий:"]
        for step in self.steps:
            size = f" {human_size(step.size):>9}" if step.size else ""
            lines.append(f"  {step.mark} {step.order:>3}. {step.title:<44}{size}")
            if step.detail:
                lines.append(f"            {step.detail}")
        for item in self.skipped:
            lines.append(f"  –  ---  {item['title']:<44}  пропущено: {item['reason']}")
        return lines


def build_plan(
    parsed: Manifest,
    passport: DevicePassport,
    report: CompatibilityReport,
    *,
    strategy: str,
    archive_path: Optional[Path] = None,
    selected: Optional[Sequence[str]] = None,
    source_interfaces: Sequence[str] = (),
    reboot: bool = False,
) -> RestorePlan:
    plan = RestorePlan(archive_path=archive_path, strategy=strategy, report=report, reboot=reboot)
    plan.warnings.extend(report.notes)

    target_interfaces = tuple(item.name for item in passport.network)
    plan.adaptations = migration.adapt(
        parsed,
        passport,
        source_interfaces=source_interfaces,
        target_interfaces=target_interfaces,
    )
    auto_excluded = migration.excluded_components(plan.adaptations)

    chosen: List[str] = []
    for component in parsed.components:
        if selected and component.id not in set(selected):
            plan.skipped.append(
                {"id": component.id, "title": COMPONENT_TITLES.get(component.id, component.id), "reason": "не выбрано"}
            )
            continue
        if component.id == "overlay_upper" and not (
            passport.storage.overlay and passport.storage.overlay.upperdir
        ):
            plan.skipped.append(
                {
                    "id": component.id,
                    "title": COMPONENT_TITLES.get(component.id, component.id),
                    "reason": "на устройстве нет отдельного записываемого слоя: собирать нечего",
                }
            )
            continue
        if component.id in NOT_APPLIED:
            plan.skipped.append(
                {
                    "id": component.id,
                    "title": COMPONENT_TITLES.get(component.id, component.id),
                    "reason": "перечень для справки: применять нечего",
                }
            )
            continue
        if component.id in auto_excluded:
            plan.skipped.append(
                {
                    "id": component.id,
                    "title": COMPONENT_TITLES.get(component.id, component.id),
                    "reason": "несовместимо с целевым устройством",
                }
            )
            continue
        chosen.append(component.id)

    if selected:
        unknown = [item for item in selected if item not in {c.id for c in parsed.components}]
        for item in unknown:
            plan.warnings.append(f"Категория «{item}» в архиве отсутствует.")

    if not chosen:
        plan.blockers.append("Не выбрано ни одной категории для восстановления.")

    if any(item.id == "configuration" for item in parsed.components):
        plan.warnings.append(
            "Восстановление конфигурации переустанавливает ключи Dropbear: SSH-ключ устройства "
            "изменится. Программа обновит свой known_hosts после проверки платы и MAC."
        )

    for check in report.blocking:
        plan.blockers.append(
            f"{check.title}: в архиве «{check.source}», на устройстве «{check.target}». "
            + (check.mitigation or "Восстановление на это устройство невозможно.")
        )

    watchdog_available = passport.tools.has("nohup") or passport.tools.has("setsid")
    needs_network = any(item in NETWORK_COMPONENTS for item in chosen)
    if needs_network and not watchdog_available:
        plan.blockers.append(
            "На устройстве нет nohup/setsid: безопасный откат сети невозможен. "
            "Выполните Selective Restore без сетевых категорий или обеспечьте локальный доступ."
        )

    # ordered steps --------------------------------------------------------
    order = 5
    plan.steps.append(
        PlanStep(
            id="pre-restore-backup",
            title="Резервная копия целевого устройства",
            order=order,
            risk=RISK_NONE,
            detail=f"обязательна; будет сохранена в хранилище как pre-restore ({parsed.device.get('release', '?')} → архив не изменяется)",
        )
    )
    order += 1
    plan.steps.append(
        PlanStep(
            id="stage-rollback",
            title="Сохранить сетевые настройки цели для отката",
            order=order,
            risk=RISK_LOW,
            detail="network, firewall, dropbear копируются в /tmp/owbm-rollback на устройстве",
        )
    )
    order += 1
    if needs_network:
        plan.steps.append(
            PlanStep(
                id="arm-watchdog",
                title="Включить сторожевой процесс возврата сети",
                order=order,
                risk=RISK_LOW,
                touches_network=True,
                detail="если связь не восстановится за отведённое время, устройство вернётся к прежней сети",
            )
        )
        order += 1

    for component in sorted(parsed.components, key=lambda item: item.restore_order):
        if component.id not in chosen:
            continue
        touches = component.id in NETWORK_COMPONENTS
        plan.steps.append(
            PlanStep(
                id=f"apply-{component.id}",
                title=COMPONENT_TITLES.get(component.id, component.id),
                order=component.restore_order + 10,
                risk=COMPONENT_RISK.get(component.id, RISK_LOW),
                component=component.id,
                touches_network=touches,
                size=int(component.uncompressed_size or component.size),
                detail=(
                    component.notes
                    + (
                        " — будут установлены из архива (интернет не нужен)"
                        if component.id == "packages_binaries"
                        and not ({"rootfs", "overlay_upper"} & set(chosen))
                        else ""
                    )
                ),
            )
        )

    if needs_network:
        plan.steps.append(
            PlanStep(
                id="reload-network",
                title="Применить сетевые настройки",
                order=95,
                risk=RISK_HIGH,
                touches_network=True,
                detail="самый рискованный шаг: SSH-соединение может прерваться",
            )
        )

    if reboot:
        plan.steps.append(
            PlanStep(
                id="reboot",
                title="Перезагрузка устройства",
                order=99,
                risk=RISK_MEDIUM,
                detail="после перезагрузки проверьте сеть, DNS и службы",
            )
        )
    plan.steps.append(
        PlanStep(
            id="confirm",
            title="Подтвердить успех и отключить сторожевой процесс",
            order=97,
            risk=RISK_NONE,
            detail="выполняется после проверки связи по новому адресу",
        )
    )

    plan.steps.sort(key=lambda item: item.order)
    for item in plan.adaptations:
        plan.warnings.append(f"{item.title}: {item.detail}")
    return plan
