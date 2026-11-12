"""Acceptance matrix: the 25 scenarios required by the specification.

Each test names its scenario number so docs/TESTING.md stays a direct map.
Nothing here needs real hardware, real networks or root.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import shutil
import stat
import threading
import time
import zipfile
from pathlib import Path

import pytest

from owbm import archive, capabilities, cli, config as cfgmod, discovery, manifest as manifest_mod, storage
from owbm.backup import collector, packager
from owbm.errors import OwbmError
from owbm.log import Logger
from owbm.restore import apply as restore_apply
from owbm.restore import compatibility, planner


@pytest.fixture
def logger():
    return Logger(json_mode=True)


def _passport(device, name):
    return discovery.discover(device(name).client())


def _backup(device, tmp_path, logger, name="apk_overlay_x86", options=None, store_name="store"):
    dev = device(name)
    client = dev.client()
    passport = discovery.discover(client)
    profile = capabilities.analyze(passport)
    store = storage.ArchiveStore(tmp_path / store_name)
    result = packager.create_backup(
        client, passport, profile, store, options or packager.BackupOptions(), logger
    )
    return dev, client, passport, profile, store, result


def _parsed(result):
    return manifest_mod.validate(result.manifest)


# --- 1..5 platform discovery and backup ------------------------------------
def test_scenario_01_apk_device(device, tmp_path, logger):
    _dev, _client, passport, profile, store, result = _backup(device, tmp_path, logger, "apk_overlay_x86")
    assert passport.packages.manager == "apk"
    assert passport.packages.count == 4
    assert profile.packages_inventory.level == "exact"
    assert archive.verify_archive(result.path).ok


def test_scenario_02_opkg_device(device, tmp_path, logger):
    _dev, _client, passport, profile, store, result = _backup(device, tmp_path, logger, "opkg_overlay_f2fs")
    assert passport.packages.manager == "opkg"
    assert passport.packages.count == 3  # not-installed entries are filtered out
    assert profile.packages_inventory.usable
    assert archive.verify_archive(result.path).ok


def test_scenario_03_overlayfs_device(device, tmp_path, logger):
    _dev, _client, passport, _profile, _store, result = _backup(device, tmp_path, logger, "apk_overlay_x86")
    assert passport.storage.overlay is not None
    assert passport.storage.overlay.upperdir == "/overlay/upper"
    ids = {item.id for item in _parsed(result).components}
    assert "overlay_upper" in ids


def test_scenario_04_device_without_overlay_upper(device, tmp_path, logger):
    _dev, _client, passport, profile, _store, result = _backup(device, tmp_path, logger, "opkg_no_overlay")
    assert passport.storage.overlay is None
    assert profile.overlay_upper.level == "unsupported"
    assert profile.configuration.usable and profile.packages_inventory.usable
    ids = {item.id for item in _parsed(result).components}
    assert "configuration" in ids
    assert "overlay_upper" not in ids
    assert not profile.exact_restore


def test_scenario_05_extroot_device(device, tmp_path, logger):
    _dev, _client, passport, profile, _store, result = _backup(device, tmp_path, logger, "opkg_extroot")
    assert passport.storage.extroot is True
    assert passport.storage.writable_persistent is True
    assert profile.overlay_upper.level == "exact"
    assert archive.verify_archive(result.path).ok


# --- 6..10 compatibility across devices -----------------------------------
def test_scenario_06_different_architectures(device, tmp_path, logger):
    _dev, _client, passport, _profile, _store, result = _backup(device, tmp_path, logger, "apk_overlay_x86")
    parsed = _parsed(result)
    other = dataclasses.replace(passport, identity=dataclasses.replace(passport.identity, arch="aarch64_cortex-a53"))
    report = compatibility.compare(parsed, other, strategy=compatibility.STRATEGY_MIGRATION)
    arch = [item for item in report.checks if item.name == "arch"][0]
    assert arch.verdict == compatibility.VERDICT_MISMATCH
    assert not report.blocking
    plan = planner.build_plan(parsed, other, report, strategy="migration")
    assert any(item["id"] == "packages_binaries" for item in plan.skipped)


def test_scenario_07_different_kernels(device, tmp_path, logger):
    _dev, _client, passport, _profile, _store, result = _backup(device, tmp_path, logger, "apk_overlay_x86")
    parsed = _parsed(result)
    other = dataclasses.replace(
        passport,
        identity=dataclasses.replace(passport.identity, kernel_release="6.12.1", kernel_package="6.12.1~1-x"),
    )
    report = compatibility.compare(parsed, other, strategy=compatibility.STRATEGY_EXACT)
    kernel = [item for item in report.checks if item.name == "kernel_release"][0]
    assert kernel.verdict == compatibility.VERDICT_MISMATCH
    assert kernel.blocking, "exact restore must refuse a different kernel"


def test_scenario_08_same_model_and_version(device, tmp_path, logger):
    _dev, _client, passport, _profile, _store, result = _backup(device, tmp_path, logger, "apk_overlay_x86")
    parsed = _parsed(result)
    report = compatibility.compare(parsed, passport, strategy=compatibility.STRATEGY_EXACT)
    assert report.ok and report.level == compatibility.LEVEL_EXACT
    plan = planner.build_plan(parsed, passport, report, strategy="exact")
    assert plan.ok


def test_scenario_09_different_model_and_arch(device, tmp_path, logger):
    dev = device("opkg_overlay_f2fs")
    client = dev.client()
    source = discovery.discover(client)
    profile = capabilities.analyze(source)
    store = storage.ArchiveStore(tmp_path / "store")
    result = packager.create_backup(client, source, profile, store, packager.BackupOptions(), Logger(json_mode=True))
    parsed = manifest_mod.validate(result.manifest)

    target = _passport(device, "apk_tmpfs_upper")
    report = compatibility.compare(parsed, target, strategy=compatibility.STRATEGY_MIGRATION)
    assert report.ok and report.level == compatibility.LEVEL_MIGRATION
    plan = planner.build_plan(parsed, target, report, strategy="migration")
    ids = {item.id for item in plan.adaptations}
    assert {"board-change", "drop-binary-packages"} <= ids
    assert plan.ok


def test_scenario_10_router_to_vm(device, tmp_path, logger):
    """Physical router (ramips/OPKG) -> x86 VM whose overlay upper lives in tmpfs."""
    dev = device("opkg_overlay_f2fs")
    client = dev.client()
    source = discovery.discover(client)
    profile = capabilities.analyze(source)
    store = storage.ArchiveStore(tmp_path / "store")
    result = packager.create_backup(client, source, profile, store, packager.BackupOptions(), Logger(json_mode=True))
    parsed = manifest_mod.validate(result.manifest)

    vm = _passport(device, "apk_tmpfs_upper")
    report = compatibility.compare(parsed, vm, strategy=compatibility.STRATEGY_MIGRATION)
    plan = planner.build_plan(parsed, vm, report, strategy="migration")
    detail = " ".join(item.detail for item in plan.adaptations)
    assert "целевое устройство" in detail or "→" in detail
    assert any(item.id == "kernel-change" for item in plan.adaptations) or any(
        check.name == "kernel_release" and check.verdict == compatibility.VERDICT_MISMATCH
        for check in report.checks
    )
    assert plan.adaptations, "миграция обязана перечислить различия"


# --- 11..18 storage and archive safety ------------------------------------
def test_scenario_11_ssh_interrupted_mid_backup(device, tmp_path, logger):
    dev = device("apk_overlay_x86")
    client = dev.client()
    passport = discovery.discover(client)
    profile = capabilities.analyze(passport)
    store = storage.ArchiveStore(tmp_path / "store")
    original = client.popopen if hasattr(client, "popopen") else None

    calls = {"count": 0}
    real_popen = client.popen

    def flaky(script):
        calls["count"] += 1
        if calls["count"] > 1:
            raise OwbmError("OWBM-E-SSH-002", host="fixture", port=22, reason="соединение прервано")
        return real_popen(script)

    client.popen = flaky
    with pytest.raises(OwbmError):
        packager.create_backup(client, passport, profile, store, packager.BackupOptions(), logger)

    assert store.list() == [], "оборванная копия не должна публиковаться"
    parts = [item for item in store.tmp_dir.iterdir() if item.name.endswith(".part")]
    assert parts == []


def test_scenario_12_not_enough_space(device, tmp_path, logger, monkeypatch):
    monkeypatch.setattr(storage, "free_bytes", lambda _path: 4096)
    dev = device("apk_overlay_x86")
    client = dev.client()
    passport = discovery.discover(client)
    profile = capabilities.analyze(passport)
    store = storage.ArchiveStore(tmp_path / "store")
    with pytest.raises(OwbmError) as exc:
        packager.create_backup(client, passport, profile, store, packager.BackupOptions(), logger)
    assert exc.value.code == "OWBM-E-STO-001"
    assert store.list() == []


def test_scenario_13_corrupted_archive(tmp_path):
    path = tmp_path / "broken.owbm"
    path.write_bytes(os.urandom(4096))
    report = archive.verify_archive(path)
    assert not report.ok
    with pytest.raises(OwbmError) as exc:
        report.raise_first()
    assert exc.value.code == "OWBM-E-ARC-001"


def test_scenario_14_modified_checksum(device, tmp_path, logger):
    _dev, _client, _passport, _profile, _store, result = _backup(device, tmp_path, logger)
    work = tmp_path / "tampered.owbm"
    with zipfile.ZipFile(result.path) as src, zipfile.ZipFile(work, "w") as dst:
        for item in src.infolist():
            data = src.read(item.filename)
            if item.filename.startswith("inventory/packages"):
                data = data.replace(b"apk", b"xxx")
            dst.writestr(item, data)
    report = archive.verify_archive(work)
    assert not report.ok
    assert any(issue.code == "OWBM-E-CHK-001" for issue in report.issues)


def test_scenario_15_broken_manifest(device, tmp_path, logger):
    _dev, _client, _passport, _profile, _store, result = _backup(device, tmp_path, logger)
    broken = tmp_path / "broken-manifest.owbm"
    with zipfile.ZipFile(result.path) as src, zipfile.ZipFile(broken, "w") as dst:
        for item in src.infolist():
            data = src.read(item.filename)
            if item.filename == "manifest.json":
                data = b'{"format": "owbm", "format_version": 1}'
            dst.writestr(item, data)
    report = archive.verify_archive(broken)
    assert not report.ok
    with pytest.raises(OwbmError):
        report.raise_first()


def test_scenario_16_same_second_backups(device, tmp_path, logger):
    from datetime import datetime, timezone

    moment = datetime(2026, 11, 9, 9, 15, 0, tzinfo=timezone.utc)
    dev = device("apk_overlay_x86")
    client = dev.client()
    passport = discovery.discover(client)
    profile = capabilities.analyze(passport)
    store = storage.ArchiveStore(tmp_path / "store")
    first = packager.create_backup(
        client, passport, profile, store, packager.BackupOptions(), logger, now=moment
    )
    second = packager.create_backup(
        client, passport, profile, store, packager.BackupOptions(), logger, now=moment
    )
    assert first.path != second.path
    assert first.path.name.split("_")[0] == second.path.name.split("_")[0]
    assert archive.verify_archive(first.path).ok
    assert archive.verify_archive(second.path).ok
    assert len(store.list()) == 2


def test_scenario_17_two_parallel_backups(device, tmp_path, logger):
    dev = device("apk_overlay_x86")
    client = dev.client()
    passport = discovery.discover(client)
    profile = capabilities.analyze(passport)
    store = storage.ArchiveStore(tmp_path / "store")
    store.ensure()

    errors = []
    started = threading.Event()

    def holder():
        with store.lock(timeout=5):
            started.set()
            time.sleep(0.6)

    thread = threading.Thread(target=holder)
    thread.start()
    assert started.wait(5)

    with pytest.raises(OwbmError) as exc:
        packager.create_backup(
            client, passport, profile, store, packager.BackupOptions(lock_timeout=0), logger
        )
    assert exc.value.code == "OWBM-E-STO-004"
    thread.join()
    assert store.list() == []


def test_scenario_18_existing_name_is_not_overwritten(tmp_path):
    store = storage.ArchiveStore(tmp_path).ensure()
    target = store.new_path("generic")
    first = tmp_path / "a.part"
    first.write_bytes(b"one")
    store.publish(first, target)
    second = tmp_path / "b.part"
    second.write_bytes(b"two")
    with pytest.raises(OwbmError) as exc:
        store.publish(second, target)
    assert exc.value.code == "OWBM-E-STO-002"
    assert target.read_bytes() == b"one"


# --- 19..25 portability, environment and safety ---------------------------
def test_scenario_19_archive_moved_between_computers(device, tmp_path, logger, monkeypatch, capsys):
    _dev, _client, _passport, _profile, _store, result = _backup(device, tmp_path, logger)
    elsewhere = tmp_path / "other machine" / "downloads"
    elsewhere.mkdir(parents=True)
    moved = elsewhere / result.path.name
    shutil.copy2(result.path, moved)

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "m2cfg"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "m2data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "m2state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "m2cache"))
    rc = cli.main(["check", str(moved)])
    assert rc == 0
    assert "Структура и контрольные суммы в порядке" in (capsys.readouterr().err or capsys.readouterr().out)


def test_scenario_20_application_config_is_portable(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg1"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data1"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state1"))
    cfg = cfgmod.load()
    cfg.general.backup_root = str(tmp_path / "backups")
    cfg.devices["home"] = cfgmod.DeviceProfile(name="home", host="192.0.2.50", port=2222)
    saved = cfgmod.save(cfg)

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg2"))
    destination = cfgmod.xdg_paths().config_file
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(saved, destination)
    moved = cfgmod.load()
    assert moved.devices["home"].host == "192.0.2.50"
    assert moved.devices["home"].port == 2222
    assert moved.general.backup_root == str(tmp_path / "backups")


def test_scenario_21_paths_with_spaces(device, tmp_path, logger):
    spaced = tmp_path / "backup directory" / "with spaces"
    dev = device("apk_overlay_x86")
    client = dev.client()
    passport = discovery.discover(client)
    profile = capabilities.analyze(passport)
    store = storage.ArchiveStore(spaced)
    result = packager.create_backup(client, passport, profile, store, packager.BackupOptions(), logger)
    assert result.ok
    assert " " in str(result.path)
    assert archive.verify_archive(result.path).ok


def test_scenario_22_missing_optional_dependencies(device, tmp_path, logger, monkeypatch):
    import importlib

    packager_module = importlib.import_module("owbm.backup.packager")
    monkeypatch.setattr(packager_module, "which", lambda name: None)
    dev = device("apk_overlay_x86")
    client = dev.client()
    passport = discovery.discover(client)
    profile = capabilities.analyze(passport)
    store = storage.ArchiveStore(tmp_path / "store")
    with pytest.raises(OwbmError) as exc:
        packager.create_backup(
            client, passport, profile, store, packager.BackupOptions(encrypt="age"), logger
        )
    assert exc.value.code == "OWBM-E-CFG-004"
    assert store.list() == []


def test_scenario_23_unavailable_storage(device, tmp_path, logger):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("file", encoding="utf-8")
    dev = device("apk_overlay_x86")
    client = dev.client()
    passport = discovery.discover(client)
    profile = capabilities.analyze(passport)
    store = storage.ArchiveStore(blocker / "backups")
    with pytest.raises(OwbmError) as exc:
        packager.create_backup(client, passport, profile, store, packager.BackupOptions(), logger)
    assert exc.value.code in ("OWBM-E-STO-003", "OWBM-E-STO-001")


def test_scenario_24_permission_errors(device, tmp_path, logger):
    locked = tmp_path / "locked"
    locked.mkdir()
    os.chmod(locked, 0o500)
    try:
        dev = device("apk_overlay_x86")
        client = dev.client()
        passport = discovery.discover(client)
        profile = capabilities.analyze(passport)
        store = storage.ArchiveStore(locked / "backups")
        with pytest.raises(OwbmError) as exc:
            packager.create_backup(client, passport, profile, store, packager.BackupOptions(), logger)
        assert exc.value.code == "OWBM-E-STO-003"
    finally:
        os.chmod(locked, 0o700)


def test_scenario_25_incompatible_restore_is_refused(device, tmp_path, logger):
    dev, _client, passport, _profile, store, result = _backup(device, tmp_path, logger)
    parsed = _parsed(result)
    other = dataclasses.replace(
        passport, identity=dataclasses.replace(passport.identity, board_id="xiaomi,redmi-router-ax6s")
    )
    report = compatibility.compare(parsed, other, strategy=compatibility.STRATEGY_EXACT)
    assert not report.ok

    before = {path.name: path.stat().st_mtime_ns for path in (dev.root / "etc" / "config").iterdir()}
    with pytest.raises(OwbmError) as exc:
        compatibility.raise_if_blocked(report)
    assert exc.value.code == "OWBM-E-CMP-001"

    plan = planner.build_plan(parsed, other, report, strategy="exact")
    ctx = restore_apply.ApplyContext(
        client=dev.client(),
        passport=other,
        parsed=parsed,
        profile_caps=capabilities.analyze(passport),
        archive_path=result.path,
        workdir=tmp_path / "work",
        store=store,
        options=restore_apply.ApplyOptions(),
        logger=logger,
        root=str(dev.root),
    )
    (tmp_path / "work").mkdir(exist_ok=True)
    outcome = restore_apply.apply_plan(ctx, plan)
    assert outcome.status in (restore_apply.STATUS_FAILED, restore_apply.STATUS_ABORTED)
    after = {path.name: path.stat().st_mtime_ns for path in (dev.root / "etc" / "config").iterdir()}
    assert before == after, "несовместимое восстановление не должно менять устройство"


# --- full cycle ------------------------------------------------------------
def test_full_cycle_backup_check_restore(device, tmp_path, logger, monkeypatch, capsys):
    dev = device("apk_overlay_x86")
    monkeypatch.setattr(cli, "SSHClient", lambda *a, **kw: dev.client())
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    root = tmp_path / "archives"

    # 1. discovery
    assert cli.main(["--backup-root", str(root), "info", "--host", "192.0.2.1"]) == 0
    assert "Что можно сохранить" in (capsys.readouterr().out)

    # 2. first backup
    assert cli.main(["--backup-root", str(root), "backup", "--host", "192.0.2.1", "--json"]) == 0
    first = json.loads(capsys.readouterr().out)
    first_path = Path(first["path"])
    assert first["status"] == "complete"
    digest = hashlib.sha256(first_path.read_bytes()).hexdigest()

    # 3. check
    assert cli.main(["--backup-root", str(root), "check", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True

    # 4. second backup must not touch the first
    assert cli.main(["--backup-root", str(root), "backup", "--host", "192.0.2.1", "--json"]) == 0
    second = json.loads(capsys.readouterr().out)
    assert Path(second["path"]) != first_path
    assert hashlib.sha256(first_path.read_bytes()).hexdigest() == digest

    # 5. list shows both, newest first
    assert cli.main(["--backup-root", str(root), "list", "--json"]) == 0
    items = json.loads(capsys.readouterr().out)
    assert len(items) == 2 and all(item["valid"] for item in items)

    # 6. dry run changes nothing
    assert cli.main(["--backup-root", str(root), "restore", str(first_path), "--host", "192.0.2.1"]) == 0
    assert "Пробный прогон" in capsys.readouterr().out
    assert not (dev.root / "tmp" / "owbm-armed").exists()

    # 7. real restore
    root_cls = restore_apply.ApplyContext
    monkeypatch.setattr(
        cli.restore_apply,
        "ApplyContext",
        lambda **kwargs: root_cls(**{**kwargs, "root": str(dev.root)}),
    )
    rc = cli.main(
        [
            "--backup-root",
            str(root),
            "restore",
            str(first_path),
            "--host",
            "192.0.2.1",
            "--apply",
            "--yes",
            "--watchdog-timeout",
            "2",
        ]
    )
    captured = capsys.readouterr()
    assert rc == 0, captured.out + captured.err
    assert "Восстановление выполнено" in (captured.out + captured.err)

    # 8. target state is sane afterwards
    assert not (dev.root / "tmp" / "owbm-armed").exists()
    assert not (dev.root / "tmp" / "owbm-watchdog.sh").exists()
    assert (dev.root / "etc" / "config" / "network").exists()

    # 9. a third archive exists: the pre-restore snapshot
    snapshots = [item for item in storage.ArchiveStore(root).list() if item.mode == "pre-restore"]
    assert len(snapshots) == 1
    assert archive.verify_archive(snapshots[0].path).ok
