"""Capabilities: turn a device passport into explicit support levels.

Discovery answers "what does the device have". This module answers "what can we
promise for it" — per category, with a reason. It never throws a device away
because one category is missing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from .adapters import filesystem
from .discovery import DevicePassport

LEVEL_EXACT = "exact"
LEVEL_CONFIG = "config"
LEVEL_INVENTORY = "inventory-only"
LEVEL_UNSUPPORTED = "unsupported"

_LEVEL_TITLES = {
    LEVEL_EXACT: "точное восстановление",
    LEVEL_CONFIG: "восстановление конфигурации",
    LEVEL_INVENTORY: "только список (переустановка из репозиториев)",
    LEVEL_UNSUPPORTED: "не поддерживается",
}


@dataclass(frozen=True)
class Support:
    level: str
    reason: str

    @property
    def usable(self) -> bool:
        return self.level != LEVEL_UNSUPPORTED

    @property
    def title(self) -> str:
        return _LEVEL_TITLES.get(self.level, self.level)

    def as_dict(self) -> Dict[str, str]:
        return {"level": self.level, "reason": self.reason, "title": self.title}


@dataclass(frozen=True)
class CapabilityProfile:
    configuration: Support
    overlay_upper: Support
    rootfs: Support
    packages_inventory: Support
    packages_binaries: Support
    user_data: Support
    application_data: Support
    system_state: Support
    exact_restore: bool = False
    warnings: Tuple[str, ...] = ()
    notes: Tuple[str, ...] = ()

    def as_dict(self) -> Dict[str, object]:
        return {
            "configuration": self.configuration.as_dict(),
            "overlay_upper": self.overlay_upper.as_dict(),
            "rootfs": self.rootfs.as_dict(),
            "packages_inventory": self.packages_inventory.as_dict(),
            "packages_binaries": self.packages_binaries.as_dict(),
            "user_data": self.user_data.as_dict(),
            "application_data": self.application_data.as_dict(),
            "system_state": self.system_state.as_dict(),
            "exact_restore": self.exact_restore,
            "warnings": list(self.warnings),
            "notes": list(self.notes),
        }

    def categories(self) -> Dict[str, Support]:
        return {
            "configuration": self.configuration,
            "overlay_upper": self.overlay_upper,
            "rootfs": self.rootfs,
            "packages_inventory": self.packages_inventory,
            "packages_binaries": self.packages_binaries,
            "user_data": self.user_data,
            "application_data": self.application_data,
            "system_state": self.system_state,
        }


def analyze(passport: DevicePassport) -> CapabilityProfile:
    identity = passport.identity
    storage = passport.storage
    packages = passport.packages
    warnings: List[str] = list(passport.warnings)
    notes: List[str] = []

    fs_desc = filesystem.describe(storage.root_fstype) if storage.root_fstype else "тип ФС не определён"

    # --- configuration ----------------------------------------------------
    if passport.tools.sysupgrade.available and passport.tools.sysupgrade.supports_backup:
        configuration = Support(
            LEVEL_EXACT,
            "Нативная резервная копия OpenWrt (sysupgrade -b) сохранит конфигурацию по правилам самого устройства.",
        )
    elif packages.manager != "none":
        configuration = Support(
            LEVEL_CONFIG,
            "sysupgrade -b недоступен: конфигурация будет собрана из /etc/config и /etc вручную.",
        )
    else:
        configuration = Support(
            LEVEL_UNSUPPORTED,
            "Не найдены ни sysupgrade, ни каталог /etc/config: сохранять конфигурацию не из чего.",
        )

    # --- overlay / writable layer ----------------------------------------
    overlay = storage.overlay
    if overlay is not None and overlay.upperdir:
        if overlay.persistent:
            overlay_upper = Support(
                LEVEL_EXACT,
                f"Записываемый слой OverlayFS найден: {overlay.upperdir} ({filesystem.describe(overlay.upper_fstype)}).",
            )
        elif overlay.upper_fstype:
            overlay_upper = Support(
                LEVEL_CONFIG,
                "Записываемый слой находится в памяти ("
                + filesystem.describe(overlay.upper_fstype)
                + "): он не переживает перезагрузку, поэтому снимок не отражает постоянное состояние.",
            )
        else:
            overlay_upper = Support(
                LEVEL_CONFIG,
                "Записываемый слой OverlayFS найден, но его файловая система не определена.",
            )
    elif storage.extroot:
        overlay_upper = Support(
            LEVEL_EXACT,
            "Используется extroot: пользовательские данные находятся на постоянном носителе и доступны для копирования.",
        )
    elif storage.root_fstype and filesystem.is_persistent(storage.root_fstype):
        overlay_upper = Support(
            LEVEL_CONFIG,
            f"OverlayFS не используется, корень — {fs_desc}. "
            "Отдельного записываемого слоя нет: сохраняются конфигурация, список пакетов и "
            "явно выбранные каталоги; файлы системы целиком не копируются.",
        )
    else:
        overlay_upper = Support(
            LEVEL_UNSUPPORTED,
            f"OverlayFS не обнаружен, корневая ФС — {fs_desc}. "
            "Точное восстановление системного состояния на этой схеме хранения невозможно.",
        )
        notes.append(
            "Отсутствие /overlay/upper само по себе не является ошибкой: конфигурация и список пакетов сохраняются."
        )

    # --- root filesystem (devices without OverlayFS) ----------------------
    if overlay is not None and overlay.upperdir:
        rootfs = Support(
            LEVEL_UNSUPPORTED,
            "Не требуется: изменения хранятся в записываемом слое OverlayFS.",
        )
    elif storage.writable_persistent and storage.root_fstype and filesystem.is_persistent(storage.root_fstype):
        rootfs = Support(
            LEVEL_EXACT,
            f"Корневая ФС — {fs_desc}: копируется целиком, кроме /proc, /sys, /dev, /tmp, /boot "
            "и других точек монтирования.",
        )
    else:
        rootfs = Support(
            LEVEL_UNSUPPORTED,
            "Постоянной корневой ФС для копирования не найдено.",
        )

    # --- packages ---------------------------------------------------------
    if packages.manager == "none":
        packages_inventory = Support(LEVEL_UNSUPPORTED, "Пакетный менеджер не обнаружен.")
        packages_binaries = Support(LEVEL_UNSUPPORTED, "Пакетный менеджер не обнаружен.")
    else:
        manager_title = "APK" if packages.manager == "apk" else "OPKG"
        if packages.count:
            packages_inventory = Support(
                LEVEL_EXACT,
                f"{manager_title}: прочитан список из {packages.count} пакетов с версиями и архитектурой.",
            )
        else:
            packages_inventory = Support(
                LEVEL_INVENTORY,
                f"{manager_title} найден, но список установленных пакетов пуст или недоступен для чтения.",
            )
        if packages.repositories:
            packages_binaries = Support(
                LEVEL_EXACT,
                f"{manager_title}: доступны {len(packages.repositories)} источника пакетов — "
                "бинарные пакеты можно сохранить для восстановления без интернета.",
            )
        else:
            packages_binaries = Support(
                LEVEL_INVENTORY,
                f"{manager_title}: репозитории не настроены, бинарные пакеты сохранить неоткуда. "
                "Восстановление будет требовать доступа к репозиториям.",
            )

    # --- user data --------------------------------------------------------
    if storage.writable_persistent:
        user_data = Support(
            LEVEL_EXACT,
            "Есть постоянное записываемое хранилище: пользовательские каталоги сохраняются как есть.",
        )
        application_data = Support(
            LEVEL_EXACT,
            "Каталоги приложений на постоянном хранилище сохраняются; их список показывается до начала работы.",
        )
        system_state = Support(
            LEVEL_CONFIG,
            "Пользовательские скрипты, службы и автозапуск сохраняются. "
            "Драйверы, модули ядра и системные бинарники не переносятся.",
        )
    else:
        user_data = Support(
            LEVEL_CONFIG,
            "Постоянного записываемого хранилища не найдено: пользовательские файлы могут отсутствовать.",
        )
        application_data = Support(LEVEL_CONFIG, "Данные приложений могут отсутствовать по той же причине.")
        system_state = Support(LEVEL_UNSUPPORTED, "Нет постоянного хранилища для пользовательских скриптов и служб.")

    if identity.arch and packages.arch_mismatch:
        notes.append(
            "В системе есть пакеты с архитектурой, отличной от системной: при восстановлении "
            "они будут перечислены отдельно."
        )

    if not passport.tools.sysupgrade.supports_restore:
        notes.append("sysupgrade -r недоступен: восстановление конфигурации будет выполняться пофайлово.")

    exact = bool(
        configuration.level == LEVEL_EXACT
        and (
            overlay_upper.level == LEVEL_EXACT
            or storage.extroot
            or rootfs.level == LEVEL_EXACT
        )
        and packages_inventory.usable
    )

    deduped_warnings: List[str] = []
    for item in warnings:
        if item not in deduped_warnings:
            deduped_warnings.append(item)

    return CapabilityProfile(
        configuration=configuration,
        overlay_upper=overlay_upper,
        packages_inventory=packages_inventory,
        rootfs=rootfs,
        packages_binaries=packages_binaries,
        user_data=user_data,
        application_data=application_data,
        system_state=system_state,
        exact_restore=exact,
        warnings=tuple(deduped_warnings),
        notes=tuple(notes),
    )


def narrative(passport: DevicePassport, profile: CapabilityProfile) -> str:
    """Short human summary in the wording the requirements ask for."""
    identity = passport.identity
    storage = passport.storage
    parts: List[str] = []
    if identity.system_type == "openwrt":
        parts.append(f"OpenWrt обнаружен: {identity.board_name or identity.model or 'модель неизвестна'}"
                     + (f", {identity.release}" if identity.release else ""))
    else:
        parts.append("OpenWrt не обнаружен")
    manager = passport.packages.manager
    if manager == "apk":
        parts.append("APK доступен")
    elif manager == "opkg":
        parts.append("OPKG доступен")
    else:
        parts.append("пакетный менеджер не обнаружен")
    if profile.rootfs.level == LEVEL_EXACT:
        parts.append("корневая ФС копируется целиком")
    if storage.overlay and storage.overlay.upperdir:
        parts.append(
            "OverlayFS обнаружен"
            + ("" if storage.overlay.persistent else " (но записываемый слой в памяти)")
        )
    else:
        parts.append("OverlayFS не обнаружен")
    if profile.configuration.usable:
        parts.append("конфигурацию сохранить можно")
    if profile.packages_inventory.usable:
        parts.append("список пакетов сохранить можно")
    if not profile.exact_restore:
        parts.append("точное восстановление системного состояния на этой файловой системе не поддерживается")
    return ". ".join(parts) + "."
