"""Migration adaptation: what must change when the target is a different device.

These are statements of fact plus a concrete action. The planner uses them to
exclude components that cannot be carried over and to list the rest as tasks the
user must be aware of. Nothing here performs changes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence

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
                title="Бинарные пакеты не переносятся",
                detail=(
                    f"Архив собран для {key['arch']}, целевое устройство — {identity.arch}. "
                    "Файлы пакетов будут исключены, пакеты нужно ставить из репозиториев цели."
                ),
                risk=RISK_MEDIUM,
                automatic=True,
                excludes=("packages_binaries",),
            )
        )

    if key.get("package_manager") and passport.packages.manager and key["package_manager"] != passport.packages.manager:
        result.append(
            Adaptation(
                id="package-manager-change",
                title="Смена пакетного менеджера",
                detail=(
                    f"Архив: {key['package_manager'].upper()}, цель: {passport.packages.manager.upper()}. "
                    "Список пакетов сохраняется как справка, автоматическая установка невозможна."
                ),
                risk=RISK_MEDIUM,
                automatic=True,
                excludes=("packages_binaries",),
            )
        )

    if key.get("board_id") and identity.board_id and key["board_id"] != identity.board_id:
        result.append(
            Adaptation(
                id="board-change",
                title="Другая модель устройства",
                detail=(
                    f"Архив снят с «{key['board_id']}», цель — «{identity.board_id}». "
                    "Секция wireless и параметры оборудования почти наверняка не подойдут: "
                    "после восстановления проверьте /etc/config/wireless и удалите чужие радио-секции."
                ),
                risk=RISK_HIGH,
                automatic=False,
            )
        )

    if key.get("target") and identity.target and key["target"] != identity.target:
        result.append(
            Adaptation(
                id="target-change",
                title="Другая цель сборки",
                detail=(
                    f"{key['target']} → {identity.target}: наборы драйверов и ядер различаются. "
                    "Модули ядра и системные пакеты из архива не применяются."
                ),
                risk=RISK_HIGH,
                automatic=False,
            )
        )

    if key.get("kernel_package") and identity.kernel_package and key["kernel_package"] != identity.kernel_package:
        result.append(
            Adaptation(
                id="kernel-change",
                title="Другое ядро",
                detail=(
                    f"Пакет ядра: {key['kernel_package']} → {identity.kernel_package}. "
                    "Модули из архива несовместимы; после перезагрузки проверьте dmesg на отсутствующие модули."
                ),
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
                    title="Интерфейсы архива отсутствуют на цели",
                    detail=(
                        "В архиве есть: "
                        + ", ".join(missing)
                        + ". На цели их нет: правила в /etc/config/network и /etc/config/firewall "
                        "нужно перенести на существующие интерфейсы, иначе сеть не поднимется."
                    ),
                    risk=RISK_HIGH,
                    automatic=False,
                )
            )
        if extra:
            result.append(
                Adaptation(
                    id="interface-extra",
                    title="На цели есть новые интерфейсы",
                    detail="Не описаны в архиве: " + ", ".join(extra) + ". Их настройки сохраняются как есть.",
                    risk=RISK_LOW,
                    automatic=False,
                )
            )

    if key.get("writable_layer") == "overlayfs" and not (passport.storage.overlay and passport.storage.overlay.upperdir):
        result.append(
            Adaptation(
                id="storage-change",
                title="Другая схема хранения",
                detail=(
                    "В архиве записываемый слой OverlayFS, на цели его нет. "
                    "Файлы будут разложены по объединённой файловой системе; часть метаданных слоя теряется."
                ),
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
