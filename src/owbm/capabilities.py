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
from . import i18n

LEVEL_EXACT = "exact"
LEVEL_CONFIG = "config"
LEVEL_INVENTORY = "inventory-only"
LEVEL_UNSUPPORTED = "unsupported"

_LEVEL_TITLE_KEYS = {
    LEVEL_EXACT: "cap.level.exact",
    LEVEL_CONFIG: "cap.level.config",
    LEVEL_INVENTORY: "cap.level.inventory",
    LEVEL_UNSUPPORTED: "cap.level.unsupported",
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
        key = _LEVEL_TITLE_KEYS.get(self.level)
        return i18n.tr(key) if key else self.level

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

    fs_desc = filesystem.describe(storage.root_fstype) if storage.root_fstype else i18n.tr("cap.fs.unknown")

    # --- configuration ----------------------------------------------------
    if passport.tools.sysupgrade.available and passport.tools.sysupgrade.supports_backup:
        configuration = Support(
            LEVEL_EXACT,
            i18n.tr("cap.config.native"),
        )
    elif packages.manager != "none":
        configuration = Support(
            LEVEL_CONFIG,
            i18n.tr("cap.config.manual"),
        )
    else:
        configuration = Support(
            LEVEL_UNSUPPORTED,
            i18n.tr("cap.config.unsupported"),
        )

    # --- overlay / writable layer ----------------------------------------
    overlay = storage.overlay
    if overlay is not None and overlay.upperdir:
        if overlay.persistent:
            overlay_upper = Support(
                LEVEL_EXACT,
                i18n.tr("cap.overlay.persistent", path=overlay.upperdir,
                        filesystem=filesystem.describe(overlay.upper_fstype)),
            )
        elif overlay.upper_fstype:
            overlay_upper = Support(
                LEVEL_CONFIG,
                i18n.tr("cap.overlay.memory", filesystem=filesystem.describe(overlay.upper_fstype)),
            )
        else:
            overlay_upper = Support(
                LEVEL_CONFIG,
                i18n.tr("cap.overlay.unknown_fs"),
            )
    elif storage.extroot:
        overlay_upper = Support(
            LEVEL_EXACT,
            i18n.tr("cap.overlay.extroot"),
        )
    elif storage.root_fstype and filesystem.is_persistent(storage.root_fstype):
        overlay_upper = Support(
            LEVEL_CONFIG,
            i18n.tr("cap.overlay.no_layer", filesystem=fs_desc),
        )
    else:
        overlay_upper = Support(
            LEVEL_UNSUPPORTED,
            i18n.tr("cap.overlay.restore_unsupported", filesystem=fs_desc),
        )
        notes.append(
            i18n.tr("cap.overlay.missing_note")
        )

    # --- root filesystem (devices without OverlayFS) ----------------------
    if overlay is not None and overlay.upperdir:
        rootfs = Support(
            LEVEL_UNSUPPORTED,
            i18n.tr("cap.rootfs.not_needed"),
        )
    elif storage.writable_persistent and storage.root_fstype and filesystem.is_persistent(storage.root_fstype):
        rootfs = Support(
            LEVEL_EXACT,
            i18n.tr("cap.rootfs.copy", filesystem=fs_desc),
        )
    else:
        rootfs = Support(
            LEVEL_UNSUPPORTED,
            i18n.tr("cap.rootfs.none"),
        )

    # --- packages ---------------------------------------------------------
    if packages.manager == "none":
        packages_inventory = Support(LEVEL_UNSUPPORTED, i18n.tr("cap.packages.manager_missing"))
        packages_binaries = Support(LEVEL_UNSUPPORTED, i18n.tr("cap.packages.manager_missing"))
    else:
        manager_title = "APK" if packages.manager == "apk" else "OPKG"
        if packages.count:
            packages_inventory = Support(
                LEVEL_EXACT,
                i18n.tr("cap.packages.inventory", manager=manager_title, count=packages.count),
            )
        else:
            packages_inventory = Support(
                LEVEL_INVENTORY,
                i18n.tr("cap.packages.inventory_empty", manager=manager_title),
            )
        if packages.repositories:
            packages_binaries = Support(
                LEVEL_EXACT,
                i18n.tr("cap.packages.binaries", manager=manager_title, count=len(packages.repositories)),
            )
        else:
            packages_binaries = Support(
                LEVEL_INVENTORY,
                i18n.tr("cap.packages.repositories_missing", manager=manager_title),
            )

    # --- user data --------------------------------------------------------
    if storage.writable_persistent:
        user_data = Support(
            LEVEL_EXACT,
            i18n.tr("cap.userdata.persistent"),
        )
        application_data = Support(
            LEVEL_EXACT,
            i18n.tr("cap.appdata.persistent"),
        )
        system_state = Support(
            LEVEL_CONFIG,
            i18n.tr("cap.systemstate.persistent"),
        )
    else:
        user_data = Support(
            LEVEL_CONFIG,
            i18n.tr("cap.userdata.missing"),
        )
        application_data = Support(LEVEL_CONFIG, i18n.tr("cap.appdata.missing"))
        system_state = Support(LEVEL_UNSUPPORTED, i18n.tr("cap.systemstate.missing"))

    if identity.arch and packages.arch_mismatch:
        notes.append(
            i18n.tr("cap.packages.arch_mismatch")
        )

    if not passport.tools.sysupgrade.supports_restore:
        notes.append(i18n.tr("cap.config.restore_filewise"))

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
        model = identity.board_name or identity.model or i18n.tr("cap.narrative.model_unknown")
        release = f", {identity.release}" if identity.release else ""
        parts.append(i18n.tr("cap.narrative.openwrt", model=model, release=release))
    else:
        parts.append(i18n.tr("cap.narrative.openwrt_missing"))
    manager = passport.packages.manager
    if manager == "apk":
        parts.append(i18n.tr("cap.narrative.apk"))
    elif manager == "opkg":
        parts.append(i18n.tr("cap.narrative.opkg"))
    else:
        parts.append(i18n.tr("cap.narrative.manager_missing"))
    if profile.rootfs.level == LEVEL_EXACT:
        parts.append(i18n.tr("cap.narrative.rootfs"))
    if storage.overlay and storage.overlay.upperdir:
        parts.append(i18n.tr("cap.narrative.overlay" if storage.overlay.persistent
                             else "cap.narrative.overlay_memory"))
    else:
        parts.append(i18n.tr("cap.narrative.overlay_missing"))
    if profile.configuration.usable:
        parts.append(i18n.tr("cap.narrative.config_available"))
    if profile.packages_inventory.usable:
        parts.append(i18n.tr("cap.narrative.packages_available"))
    if not profile.exact_restore:
        parts.append(i18n.tr("cap.narrative.exact_unsupported"))
    return ". ".join(parts) + "."
