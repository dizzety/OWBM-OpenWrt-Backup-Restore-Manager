"""Packaging: assemble, verify, and publish an archive. Never overwrite, never lie.

The publishing order matters: the candidate is written in the store's temp area,
fully verified (structure, checksums, permissions), and only then linked into its
final unique name. A failure at any point leaves only a `.part` file, which the
next operation removes.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .. import __version__, archive, manifest as manifest_mod
from ..discovery import DevicePassport
from ..errors import fail
from ..storage import ArchiveInfo, ArchiveStore
from ..util import clock_sanity, human_size, iso_utc, sha256_file, which
from . import collector, planner

PAYLOAD_PATHS = {
    "configuration": "payload/configuration.tar.gz",
    "rootfs": "payload/rootfs.tar.gz",
    "overlay_upper": "payload/overlay-upper.tar.gz",
    "rootfs": "payload/rootfs.tar.gz",
    "packages_binaries": "payload/packages-binaries.tar.gz",
    "user_data": "payload/user-data.tar.gz",
    "system_state": "payload/system-state.tar.gz",
}

RESTORE_ORDER = {
    "configuration": 10,
    "rootfs": 15,
    "packages_inventory": 20,
    "overlay_upper": 30,
    "rootfs": 30,
    "packages_binaries": 40,
    "user_data": 50,
    "system_state": 60,
}


@dataclass
class BackupOptions:
    include_package_binaries: bool = True
    include_user_data: bool = True
    include_rootfs: bool = True
    include_rootfs: bool = True
    user_data_paths: Tuple[str, ...] = ()
    package_chunk: int = 25
    compresslevel: int = 6
    encrypt: Optional[str] = None
    mode: str = "backup"
    dry_run: bool = False
    lock_timeout: int = 30


@dataclass
class BackupResult:
    path: Optional[Path] = None
    manifest: Optional[dict] = None
    plan: Optional[planner.BackupPlan] = None
    warnings: List[str] = field(default_factory=list)
    status: str = manifest_mod.STATUS_COMPLETE
    info: Optional[ArchiveInfo] = None
    report: List[str] = field(default_factory=list)
    stages: List[Dict[str, str]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.path is not None


def _json_bytes(data) -> bytes:
    return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")


def _device_block(passport: DevicePassport, label: str) -> Dict[str, object]:
    ident = passport.identity
    if passport.storage.overlay and passport.storage.overlay.upperdir:
        layer = "overlayfs"
    elif passport.storage.extroot:
        layer = "extroot"
    else:
        layer = "filesystem"
    return {
        "board_id": ident.board_id,
        "board_name": ident.board_name,
        "model": ident.model,
        "target": ident.target,
        "release": ident.release,
        "revision": ident.revision,
        "arch": ident.arch,
        "kernel_release": ident.kernel_release,
        "kernel_package": ident.kernel_package,
        "package_manager": passport.packages.manager,
        "package_arch": passport.packages.arch,
        "hostname": ident.hostname,
        "label": label,
        "device_time_utc": passport.time.utc,
        "device_time_plausible": passport.time.plausible,
        "writable_layer": layer,
    }


def _collect_step(client, step, workdir: Path, passport: DevicePassport, options: BackupOptions, logger):
    """Return (Collected | None, extra dict)."""
    if step.id == "configuration":
        return collector.collect_configuration(client, workdir / "configuration.tar.gz", passport, logger), {}
    if step.id == "rootfs":
        return collector.collect_rootfs(client, workdir / "rootfs.tar.gz", passport, logger), {}
    if step.id == "overlay_upper":
        upperdir = passport.storage.overlay.upperdir if passport.storage.overlay else None
        if not upperdir:
            return None, {}
        item = collector.collect_overlay(client, workdir / "overlay-upper.tar.gz", upperdir, logger)
        return item, {"whiteouts": list(item.extra.get("whiteouts") or [])}
    if step.id == "rootfs":
        return collector.collect_rootfs(client, workdir / "rootfs.tar.gz", passport, logger), {}
    if step.id == "packages_binaries":
        item, status = collector.collect_packages(
            client, workdir, passport, chunk_size=options.package_chunk, logger=logger
        )
        return item, {"packages": status}
    if step.id == "user_data":
        if not options.user_data_paths:
            return None, {}
        return collector.collect_user_data(client, workdir / "user-data.tar.gz", options.user_data_paths, logger), {}
    if step.id == "system_state":
        try:
            return collector.collect_system_state(client, workdir / "system-state.tar.gz", logger), {}
        except Exception as exc:  # noqa: BLE001 - optional category
            logger.debug(f"system_state не собран: {exc}")
            return None, {}
    return None, {}


def _encrypt_candidate(candidate: Path, tool: str, logger) -> Path:
    if not which(tool):
        raise fail("OWBM-E-CFG-004", tool=tool, purpose="шифрование архива")
    if not sys.stdin.isatty():
        raise fail(
            "OWBM-E-CFG-002",
            key="--encrypt",
            reason="шифрование требует интерактивного ввода пароля в терминале",
        )
    if tool == "age":
        target = candidate.with_suffix(candidate.suffix + ".age")
        argv = ["age", "-p", "-o", str(target), str(candidate)]
    else:
        target = candidate.with_suffix(candidate.suffix + ".gpg")
        argv = ["gpg", "--symmetric", "--cipher-algo", "AES256", "--output", str(target), str(candidate)]
    import subprocess

    proc = subprocess.run(argv)
    if proc.returncode != 0 or not target.exists() or target.stat().st_size == 0:
        target.unlink(missing_ok=True)
        raise fail("OWBM-E-CFG-002", key="--encrypt", reason=f"{tool} завершился с ошибкой")
    candidate.unlink(missing_ok=True)
    logger.ok(f"Архив зашифрован: {tool}")
    return target


def _inventory_blobs(
    passport: DevicePassport,
    profile_caps,
    plan_obj: planner.BackupPlan,
    package_status: Sequence[Dict[str, str]],
    whiteouts: Sequence[str],
    collected: Dict[str, collector.Collected],
) -> Dict[str, bytes]:
    blobs: Dict[str, bytes] = {
        "inventory/device-passport.json": _json_bytes(passport.as_dict()),
        "inventory/storage.json": _json_bytes(passport.storage.as_dict()),
        "inventory/interfaces.json": _json_bytes([item.as_dict() for item in passport.network]),
        "inventory/packages.json": _json_bytes(
            {
                "manager": passport.packages.manager,
                "arch": passport.packages.arch,
                "world": list(passport.packages.world),
                "repositories": list(passport.packages.repositories),
                "count": passport.packages.count,
                "entries": list(package_status)
                or [item.as_dict() for item in passport.packages.installed],
            }
        ),
        "inventory/capabilities.json": _json_bytes(profile_caps.as_dict()),
    }
    excluded: List[Dict[str, object]] = [
        {"id": step_id, "reason": reason} for step_id, reason in plan_obj.skipped
    ]
    for component_id, item in collected.items():
        if item.excluded:
            excluded.append({"id": component_id, "reason": "исключено при сборе", "items": list(item.excluded)})
    blobs["inventory/excluded.json"] = _json_bytes(excluded)
    if whiteouts:
        blobs["inventory/overlay-whiteouts.txt"] = ("\n".join(whiteouts) + "\n").encode("utf-8")
    return blobs


def _instructions(passport: DevicePassport, manifest_obj) -> str:
    ident = passport.identity
    lines = [
        "OWBM — архив пользовательского состояния OpenWrt",
        "",
        f"Устройство: {ident.board_name or 'неизвестно'} ({ident.model or 'модель не указана'})",
        f"OpenWrt: {ident.release or 'неизвестно'} {ident.revision or ''}".rstrip(),
        f"Архитектура: {ident.arch or 'неизвестно'}; ядро: {ident.kernel_release or 'неизвестно'}",
        f"Создан: {manifest_obj.created_utc} (UTC)",
        "",
        "Состав архива:",
    ]
    for component in manifest_obj.components:
        lines.append(f"  - {component.id}: {component.path}")
    lines += [
        "",
        "Архив содержит пароли, ключи и токены из конфигураций. Храните его приватно.",
        "Прошивка, /rom и raw-разделы в архив не входят и не восстанавливаются.",
        "Восстанавливайте архив программой owbm: она проверяет совместимость,",
        "создаёт снапшот целевого устройства и умеет откатываться при сбое.",
    ]
    return "\n".join(lines) + "\n"


def _support_level(profile_caps, component_id: str) -> str:
    mapping = {
        "configuration": profile_caps.configuration,
        "overlay_upper": profile_caps.overlay_upper,
        "rootfs": profile_caps.rootfs,
        "rootfs": profile_caps.rootfs,
        "packages_binaries": profile_caps.packages_binaries,
        "user_data": profile_caps.user_data,
        "system_state": profile_caps.system_state,
    }
    support = mapping.get(component_id)
    return support.level if support is not None else "exact"


def create_backup(
    client,
    passport: DevicePassport,
    profile_caps,
    store: ArchiveStore,
    options: BackupOptions,
    logger,
    *,
    now: Optional[datetime] = None,
    label: Optional[str] = None,
) -> BackupResult:
    journal = logger.journal
    plan_obj = planner.plan(
        passport,
        profile_caps,
        include_package_binaries=options.include_package_binaries,
        include_user_data=options.include_user_data,
        user_data_paths=options.user_data_paths,
        include_rootfs=options.include_rootfs,
    )
    result = BackupResult(plan=plan_obj, warnings=list(plan_obj.warnings))

    if not any(step.critical for step in plan_obj.steps):
        raise fail("OWBM-E-CMP-001", reason="нет ни одного критичного компонента для сохранения")

    if options.dry_run:
        result.report.append("Пробный запуск: сбор и запись не выполнялись.")
        return result

    moment = now or datetime.now(timezone.utc)
    store.ensure()
    clock_warning = clock_sanity(moment)
    if clock_warning:
        result.warnings.append(clock_warning)

    device_label = label or passport.identity.board_id or passport.identity.hostname or "openwrt"
    workdir = Path(tempfile.mkdtemp(prefix="owbm-backup-", dir=os.environ.get("TMPDIR") or None))
    candidate: Optional[Path] = None
    try:
        with store.lock(timeout=max(0, options.lock_timeout)):
            store.cleanup_temp()

            collected: Dict[str, collector.Collected] = {}
            package_status: List[Dict[str, str]] = []
            whiteouts: List[str] = []
            stages: List[Dict[str, str]] = []

            for step in plan_obj.steps:
                journal.start(step.id)
                logger.step(step.title)
                try:
                    item, extra = _collect_step(client, step, workdir, passport, options, logger)
                except Exception as exc:  # noqa: BLE001 - re-raised if critical
                    journal.fail(step.id, str(exc))
                    if step.critical:
                        stages.append({"name": step.id, "status": "failed", "detail": str(exc)})
                        result.stages = stages
                        raise
                    logger.warn(f"Шаг «{step.title}» пропущен: {exc}")
                    stages.append({"name": step.id, "status": "failed", "detail": str(exc)})
                    result.warnings.append(f"Не сохранено: {step.title} ({exc})")
                    continue
                if item is None:
                    journal.skip(step.id, "нет данных")
                    stages.append({"name": step.id, "status": "skipped", "detail": "нет данных"})
                    continue
                if extra.get("whiteouts"):
                    whiteouts = list(extra["whiteouts"])
                if extra.get("packages"):
                    package_status = list(extra["packages"])
                collected[step.id] = item
                journal.ok(step.id, item.notes)
                stages.append({"name": step.id, "status": "ok", "detail": item.notes})

            inventory_blobs = _inventory_blobs(
                passport, profile_caps, plan_obj, package_status, whiteouts, collected
            )

            components: List[manifest_mod.Component] = []
            for component_id, item in sorted(collected.items()):
                archive_path = PAYLOAD_PATHS.get(component_id)
                if archive_path is None:
                    continue
                components.append(
                    manifest_mod.Component(
                        id=component_id,
                        path=archive_path,
                        support_level=_support_level(profile_caps, component_id),
                        portability=manifest_mod.PORTABILITY_PORTABLE,
                        critical=component_id in ("configuration", "overlay_upper", "rootfs"),
                        sha256=sha256_file(item.path),
                        size=item.path.stat().st_size,
                        uncompressed_size=item.uncompressed,
                        members=item.members,
                        restore_order=RESTORE_ORDER.get(component_id, 99),
                        excluded=item.excluded,
                        notes=item.notes,
                    )
                )
            packages_json = inventory_blobs["inventory/packages.json"]
            components.append(
                manifest_mod.Component(
                    id="packages_inventory",
                    path="inventory/packages.json",
                    support_level="exact",
                    portability=manifest_mod.PORTABILITY_PORTABLE,
                    critical=True,
                    sha256=hashlib.sha256(packages_json).hexdigest(),
                    size=len(packages_json),
                    restore_order=RESTORE_ORDER["packages_inventory"],
                    notes=f"{passport.packages.manager}: {passport.packages.count} пакетов",
                )
            )

            status = manifest_mod.STATUS_COMPLETE
            if any(stage["status"] == "failed" for stage in stages):
                status = manifest_mod.STATUS_PARTIAL
            result.status = status
            result.stages = stages

            manifest_obj = manifest_mod.build(
                archive_id=str(uuid.uuid4()),
                created_utc=iso_utc(moment),
                mode=options.mode,
                device=_device_block(passport, device_label),
                capabilities_snapshot=profile_caps.as_dict(),
                components=components,
                inventory={
                    "packages": {
                        "path": "inventory/packages.json",
                        "count": passport.packages.count,
                        "manager": passport.packages.manager,
                    },
                    "whiteouts": len(whiteouts),
                },
                status=status,
                stages=stages,
                warnings=result.warnings,
                clock_warning=clock_warning,
            )

            needed = sum(item.path.stat().st_size for item in collected.values()) + sum(
                len(blob) for blob in inventory_blobs.values()
            )
            store.require_space(int(needed * 1.1) + 64 * 1024 * 1024)

            members = [
                archive.Member(archive.MANIFEST_NAME, data=_json_bytes(manifest_obj.as_dict()), compress=True)
            ]
            for name in sorted(inventory_blobs):
                members.append(archive.Member(name, data=inventory_blobs[name], compress=True))
            for component in components:
                if component.id in collected:
                    members.append(archive.Member(component.path, source=collected[component.id].path))
            members.append(
                archive.Member(
                    "meta/restore-instructions.ru.txt",
                    data=_instructions(passport, manifest_obj).encode("utf-8"),
                    compress=True,
                )
            )
            members.append(
                archive.Member("meta/owbm-version.txt", data=f"owbm {__version__}\n".encode(), compress=True)
            )

            candidate = store.tmp_dir / f"{uuid.uuid4().hex}.owbm.part"
            journal.start("pack")
            archive.write_archive(candidate, members, compresslevel=options.compresslevel)
            journal.ok("pack", human_size(candidate.stat().st_size))

            journal.start("verify")
            report = archive.verify_archive(candidate)
            report.raise_first()
            journal.ok("verify", f"элементов: {report.members}, сумм: {report.checksums_verified}")
            logger.ok(
                f"Собрано и проверено: {human_size(candidate.stat().st_size)}, "
                f"элементов {report.members}, контрольных сумм {report.checksums_verified}"
            )

            if options.encrypt:
                journal.start("encrypt")
                candidate = _encrypt_candidate(candidate, options.encrypt, logger)
                journal.ok("encrypt", options.encrypt)

            final = store.new_path(device_label, moment=moment, mode=options.mode)
            store.publish(candidate, final)
            candidate = None
            journal.start("publish")
            journal.ok("publish", str(final))

            mode_bits = final.stat().st_mode & 0o777
            if mode_bits != 0o600:
                result.warnings.append(f"Не удалось ограничить права архива (режим {oct(mode_bits)}).")

            result.path = final
            result.manifest = manifest_obj.as_dict()
            result.info = ArchiveInfo(
                path=final,
                name=final.name,
                size=final.stat().st_size,
                mtime=final.stat().st_mtime,
                manifest=result.manifest,
                mode=options.mode,
            )
            result.report.append(f"Архив: {final}")
            result.report.append(f"Размер: {human_size(final.stat().st_size)}")
            result.report.append(f"SHA-256: {sha256_file(final)}")
        return result
    finally:
        if candidate is not None and candidate.exists():
            candidate.unlink(missing_ok=True)
        shutil.rmtree(workdir, ignore_errors=True)
