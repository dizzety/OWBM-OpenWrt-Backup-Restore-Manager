"""Migration adaptation: what must change when the target is a different device.

These are statements of fact plus a concrete action. The planner uses them to
exclude components that cannot be carried over and to list the rest as tasks the
user must be aware of. Nothing here performs changes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence

from .. import i18n
from ..discovery import DevicePassport
from ..manifest import Manifest

RISK_LOW = "low"
RISK_MEDIUM = "medium"
RISK_HIGH = "high"


@dataclass(frozen=True)
class Adaptation:
    id: str
    title: str
    detail: str
    risk: str
    automatic: bool
    excludes: tuple = ()

    def as_dict(self) -> Dict[str, object]:
        return {
            "id": self.id,
            "title": self.title,
            "detail": self.detail,
            "risk": self.risk,
            "automatic": self.automatic,
            "excludes": list(self.excludes),
        }


def adapt(
    parsed: Manifest,
    passport: DevicePassport,
    *,
    source_interfaces: Sequence[str] = (),
    target_interfaces: Sequence[str] = (),
) -> List[Adaptation]:
    identity = passport.identity
    key = parsed.compatibility_key
    result: List[Adaptation] = []

    if key.get("arch") and identity.arch and key["arch"] != identity.arch:
        result.append(
            Adaptation(
                id="drop-binary-packages",
                title=i18n.tr("migration.adaptation.binary.title"),
                detail=i18n.tr("migration.adaptation.binary.detail", source=key['arch'], target=identity.arch),
                risk=RISK_MEDIUM,
                automatic=True,
                excludes=("packages_binaries",),
            )
        )

    if key.get("package_manager") and passport.packages.manager and key["package_manager"] != passport.packages.manager:
        result.append(
            Adaptation(
                id="package-manager-change",
                title=i18n.tr("migration.adaptation.manager.title"),
                detail=i18n.tr("migration.adaptation.manager.detail", source=key['package_manager'].upper(),
                               target=passport.packages.manager.upper()),
                risk=RISK_MEDIUM,
                automatic=True,
                excludes=("packages_binaries",),
            )
        )

    if key.get("board_id") and identity.board_id and key["board_id"] != identity.board_id:
        result.append(
            Adaptation(
                id="board-change",
                title=i18n.tr("migration.adaptation.board.title"),
                detail=i18n.tr("migration.adaptation.board.detail", source=key['board_id'], target=identity.board_id),
                risk=RISK_HIGH,
                automatic=False,
            )
        )

    if key.get("target") and identity.target and key["target"] != identity.target:
        result.append(
            Adaptation(
                id="target-change",
                title=i18n.tr("migration.adaptation.target.title"),
                detail=i18n.tr("migration.adaptation.target.detail", source=key['target'], target=identity.target),
                risk=RISK_HIGH,
                automatic=False,
            )
        )

    if key.get("kernel_package") and identity.kernel_package and key["kernel_package"] != identity.kernel_package:
        result.append(
            Adaptation(
                id="kernel-change",
                title=i18n.tr("migration.adaptation.kernel.title"),
                detail=i18n.tr("migration.adaptation.kernel.detail", source=key['kernel_package'],
                               target=identity.kernel_package),
                risk=RISK_HIGH,
                automatic=False,
            )
        )

    if source_interfaces and target_interfaces:
        source = [name for name in source_interfaces if name]
        target = [name for name in target_interfaces if name]
        missing = [name for name in source if name not in target]
        extra = [name for name in target if name not in source]
        if missing:
            result.append(
                Adaptation(
                    id="interface-missing",
                    title=i18n.tr("migration.adaptation.interfaces_missing.title"),
                    detail=i18n.tr("migration.adaptation.interfaces_missing.detail", interfaces=', '.join(missing)),
                    risk=RISK_HIGH,
                    automatic=False,
                )
            )
        if extra:
            result.append(
                Adaptation(
                    id="interface-extra",
                    title=i18n.tr("migration.adaptation.interfaces_extra.title"),
                    detail=i18n.tr("migration.adaptation.interfaces_extra.detail", interfaces=', '.join(extra)),
                    risk=RISK_LOW,
                    automatic=False,
                )
            )

    if key.get("writable_layer") == "overlayfs" and not (passport.storage.overlay and passport.storage.overlay.upperdir):
        result.append(
            Adaptation(
                id="storage-change",
                title=i18n.tr("migration.adaptation.storage.title"),
                detail=i18n.tr("migration.adaptation.storage.detail"),
                risk=RISK_MEDIUM,
                automatic=True,
            )
        )

    return result


def excluded_components(adaptations: Iterable[Adaptation]) -> List[str]:
    result: List[str] = []
    for item in adaptations:
        for name in item.excludes:
            if name not in result:
                result.append(name)
    return result
