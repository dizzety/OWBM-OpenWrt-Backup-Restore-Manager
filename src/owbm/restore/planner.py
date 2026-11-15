"""Restore planning: an ordered, explained list of steps. No side effects.

The plan is the dry run. It is produced from the archive manifest plus the target
passport only, so showing it can never change anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from .. import i18n
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

COMPONENT_TITLE_KEYS = {
    "configuration": "restore.plan.title.configuration",
    "overlay_upper": "restore.plan.title.overlay_upper",
    "rootfs": "restore.plan.title.rootfs",
    "packages_inventory": "restore.plan.title.packages_inventory",
    "packages_binaries": "restore.plan.title.packages_binaries",
    "user_data": "restore.plan.title.user_data",
    "system_state": "restore.plan.title.system_state",
    "application_data": "restore.plan.title.application_data",
}


def component_title(component_id: str) -> str:
    key = COMPONENT_TITLE_KEYS.get(component_id)
    return i18n.tr(key) if key else component_id

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
        lines = [i18n.tr("restore.plan.steps_heading")]
        for step in self.steps:
            size = f" {human_size(step.size):>9}" if step.size else ""
            lines.append(f"  {step.mark} {step.order:>3}. {step.title:<44}{size}")
            if step.detail:
                lines.append(f"            {step.detail}")
        for item in self.skipped:
            lines.append(i18n.tr("restore.plan.skipped", title=item['title'], reason=item['reason']))
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
                {"id": component.id, "title": component_title(component.id), "reason": i18n.tr("restore.plan.reason.not_selected")}
            )
            continue
        if component.id == "overlay_upper" and not (
            passport.storage.overlay and passport.storage.overlay.upperdir
        ):
            plan.skipped.append(
                {
                    "id": component.id,
                    "title": component_title(component.id),
                    "reason": i18n.tr("restore.plan.reason.no_overlay"),
                }
            )
            continue
        if component.id in NOT_APPLIED:
            plan.skipped.append(
                {
                    "id": component.id,
                    "title": component_title(component.id),
                    "reason": i18n.tr("restore.plan.reason.inventory_only"),
                }
            )
            continue
        if component.id in auto_excluded:
            plan.skipped.append(
                {
                    "id": component.id,
                    "title": component_title(component.id),
                    "reason": i18n.tr("restore.plan.reason.incompatible"),
                }
            )
            continue
        chosen.append(component.id)

    if selected:
        unknown = [item for item in selected if item not in {c.id for c in parsed.components}]
        for item in unknown:
            plan.warnings.append(i18n.tr("restore.plan.warning.missing_category", item=item))

    if not chosen:
        plan.blockers.append(i18n.tr("restore.plan.blocker.no_category"))

    if any(item.id == "configuration" for item in parsed.components):
        plan.warnings.append(i18n.tr("restore.plan.warning.dropbear"))

    for check in report.blocking:
        plan.blockers.append(i18n.tr(
            "restore.plan.blocker.compatibility", title=check.title, source=check.source,
            target=check.target, mitigation=check.mitigation or i18n.tr("restore.plan.blocker.impossible"),
        ))

    watchdog_available = passport.tools.has("nohup") or passport.tools.has("setsid")
    needs_network = any(item in NETWORK_COMPONENTS for item in chosen)
    if needs_network and not watchdog_available:
        plan.blockers.append(i18n.tr("restore.plan.blocker.no_watchdog"))

    # ordered steps --------------------------------------------------------
    order = 5
    plan.steps.append(
        PlanStep(
            id="pre-restore-backup",
            title=i18n.tr("restore.plan.step.pre_restore"),
            order=order,
            risk=RISK_NONE,
            detail=i18n.tr("restore.plan.detail.pre_restore", release=parsed.device.get('release', '?')),
        )
    )
    order += 1
    plan.steps.append(
        PlanStep(
            id="stage-rollback",
            title=i18n.tr("restore.plan.step.stage_rollback"),
            order=order,
            risk=RISK_LOW,
            detail=i18n.tr("restore.plan.detail.stage_rollback"),
        )
    )
    order += 1
    if needs_network:
        plan.steps.append(
            PlanStep(
                id="arm-watchdog",
                title=i18n.tr("restore.plan.step.watchdog"),
                order=order,
                risk=RISK_LOW,
                touches_network=True,
                detail=i18n.tr("restore.plan.detail.watchdog"),
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
                title=component_title(component.id),
                order=component.restore_order + 10,
                risk=COMPONENT_RISK.get(component.id, RISK_LOW),
                component=component.id,
                touches_network=touches,
                size=int(component.uncompressed_size or component.size),
                detail=(
                    i18n.localize_text(component.notes)
                    + (
                        i18n.tr("restore.plan.detail.packages_offline")
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
                title=i18n.tr("restore.plan.step.reload_network"),
                order=95,
                risk=RISK_HIGH,
                touches_network=True,
                detail=i18n.tr("restore.plan.detail.reload_network"),
            )
        )

    if reboot:
        plan.steps.append(
            PlanStep(
                id="reboot",
                title=i18n.tr("restore.plan.step.reboot"),
                order=99,
                risk=RISK_MEDIUM,
                detail=i18n.tr("restore.plan.detail.reboot"),
            )
        )
    plan.steps.append(
        PlanStep(
            id="confirm",
            title=i18n.tr("restore.plan.step.confirm"),
            order=97,
            risk=RISK_NONE,
            detail=i18n.tr("restore.plan.detail.confirm"),
        )
    )

    plan.steps.sort(key=lambda item: item.order)
    for item in plan.adaptations:
        plan.warnings.append(f"{item.title}: {item.detail}")
    return plan
