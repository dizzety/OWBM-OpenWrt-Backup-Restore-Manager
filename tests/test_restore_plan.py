import dataclasses
import inspect
import json
from pathlib import Path

import pytest

from owbm import archive, capabilities, discovery, manifest as manifest_mod, storage
from owbm.backup import packager
from owbm.log import Logger
from owbm.restore import compatibility, migration, planner
from owbm.errors import OwbmError


@pytest.fixture
def logger():
    return Logger(json_mode=True)


def _archive_for(device, tmp_path, logger, name="apk_overlay_x86"):
    dev = device(name)
    client = dev.client()
    passport = discovery.discover(client)
    profile = capabilities.analyze(passport)
    store = storage.ArchiveStore(tmp_path / "store")
    result = packager.create_backup(client, passport, profile, store, packager.BackupOptions(), logger)
    parsed = manifest_mod.validate(result.manifest)
    return dev, passport, profile, result.path, parsed


# --- compatibility ---------------------------------------------------------
def test_same_device_is_exact(device, tmp_path, logger):
    _dev, passport, _profile, _path, parsed = _archive_for(device, tmp_path, logger)
    report = compatibility.compare(parsed, passport, strategy=compatibility.STRATEGY_EXACT)
    assert report.ok
    assert report.level == compatibility.LEVEL_EXACT
    assert not report.mismatches


def test_board_mismatch_blocks_exact(device, tmp_path, logger):
    _dev, passport, _profile, _path, parsed = _archive_for(device, tmp_path, logger)
    other = dataclasses.replace(
        passport, identity=dataclasses.replace(passport.identity, board_id="xiaomi,other-router")
    )
    report = compatibility.compare(parsed, other, strategy=compatibility.STRATEGY_EXACT)
    assert not report.ok
    assert report.level == compatibility.LEVEL_INCOMPATIBLE
    with pytest.raises(OwbmError) as exc:
        compatibility.raise_if_blocked(report)
    assert exc.value.code == "OWBM-E-CMP-001"
    assert "Плата" in exc.value.why or "Плата" in exc.value.what


def test_board_mismatch_is_allowed_in_migration(device, tmp_path, logger):
    _dev, passport, _profile, _path, parsed = _archive_for(device, tmp_path, logger)
    other = dataclasses.replace(
        passport, identity=dataclasses.replace(passport.identity, board_id="xiaomi,other-router")
    )
    report = compatibility.compare(parsed, other, strategy=compatibility.STRATEGY_MIGRATION)
    assert report.ok
    assert report.level == compatibility.LEVEL_MIGRATION
    mismatch = [item for item in report.checks if item.name == "board_id"][0]
    assert mismatch.verdict == compatibility.VERDICT_MISMATCH
    assert mismatch.severity == compatibility.SEVERITY_WARNING
    assert mismatch.mitigation


def test_arch_mismatch_in_migration_stays_visible(device, tmp_path, logger):
    _dev, passport, _profile, _path, parsed = _archive_for(device, tmp_path, logger)
    other = dataclasses.replace(passport, identity=dataclasses.replace(passport.identity, arch="aarch64_cortex-a53"))
    report = compatibility.compare(parsed, other, strategy=compatibility.STRATEGY_MIGRATION)
    arch_check = [item for item in report.checks if item.name == "arch"][0]
    assert arch_check.verdict == compatibility.VERDICT_MISMATCH
    assert "бинарные пакеты" in arch_check.mitigation.lower()


def test_free_space_shortage_blocks(device, tmp_path, logger):
    _dev, passport, _profile, _path, parsed = _archive_for(device, tmp_path, logger)
    storage_info = dataclasses.replace(passport.storage, free_bytes_writable=1)
    other = dataclasses.replace(passport, storage=storage_info)
    report = compatibility.compare(parsed, other, strategy=compatibility.STRATEGY_MIGRATION)
    blocking = [item for item in report.blocking if item.name == "free_space"]
    assert blocking
    with pytest.raises(OwbmError) as exc:
        compatibility.raise_if_blocked(report)
    assert exc.value.code == "OWBM-E-CMP-002"


def test_unknown_values_are_warnings_not_blocks(device, tmp_path, logger):
    _dev, passport, _profile, _path, parsed = _archive_for(device, tmp_path, logger)
    other = dataclasses.replace(passport, identity=dataclasses.replace(passport.identity, kernel_package=""))
    report = compatibility.compare(parsed, other, strategy=compatibility.STRATEGY_EXACT)
    check = [item for item in report.checks if item.name == "kernel_package"][0]
    assert check.verdict == compatibility.VERDICT_UNKNOWN
    assert not check.blocking


# --- migration -------------------------------------------------------------
def test_migration_lists_adaptations(device, tmp_path, logger):
    _dev, passport, _profile, _path, parsed = _archive_for(device, tmp_path, logger)
    other = dataclasses.replace(
        passport,
        identity=dataclasses.replace(passport.identity, board_id="xiaomi,other", arch="aarch64_cortex-a53"),
    )
    items = migration.adapt(parsed, other, source_interfaces=("br-lan", "wan"), target_interfaces=("eth0",))
    ids = {item.id for item in items}
    assert "drop-binary-packages" in ids
    assert "board-change" in ids
    assert "interface-missing" in ids
    assert migration.excluded_components(items) == ["packages_binaries"]


def test_adaptation_marks_interface_risk_high(device, tmp_path, logger):
    _dev, passport, _profile, _path, parsed = _archive_for(device, tmp_path, logger)
    items = migration.adapt(parsed, passport, source_interfaces=("br-lan", "wan"), target_interfaces=("eth0",))
    interface = [item for item in items if item.id == "interface-missing"][0]
    assert interface.risk == migration.RISK_HIGH
    assert interface.automatic is False


# --- planner ---------------------------------------------------------------
def test_plan_order_and_content(device, tmp_path, logger):
    _dev, passport, _profile, _path, parsed = _archive_for(device, tmp_path, logger)
    report = compatibility.compare(parsed, passport, strategy=compatibility.STRATEGY_EXACT)
    plan = planner.build_plan(parsed, passport, report, strategy="exact", reboot=True)
    ids = [step.id for step in plan.steps]
    assert ids[0] == "pre-restore-backup"
    assert ids[-1] == "reboot"
    assert ids.index("confirm") < ids.index("reboot")
    assert ids.index("stage-rollback") < ids.index("apply-configuration")
    assert ids.index("arm-watchdog") < ids.index("reload-network")
    assert "reboot" in ids
    assert plan.ok
    assert plan.size_total > 0


def test_plan_is_blocked_without_watchdog(device, tmp_path, logger):
    _dev, passport, _profile, _path, parsed = _archive_for(device, tmp_path, logger)
    tools = dataclasses.replace(passport.tools, available=tuple(t for t in passport.tools.available if t not in ("nohup", "setsid")))
    other = dataclasses.replace(passport, tools=tools)
    report = compatibility.compare(parsed, other, strategy=compatibility.STRATEGY_MIGRATION)
    plan = planner.build_plan(parsed, other, report, strategy="migration")
    assert not plan.ok
    assert any("откат сети" in item for item in plan.blockers)


def test_selective_plan_only_includes_chosen(device, tmp_path, logger):
    _dev, passport, _profile, _path, parsed = _archive_for(device, tmp_path, logger)
    report = compatibility.compare(
        parsed, passport, strategy=compatibility.STRATEGY_SELECTIVE, selected=("configuration",)
    )
    plan = planner.build_plan(
        parsed, passport, report, strategy="selective", selected=("configuration",)
    )
    assert plan.component_ids() == ["configuration"]
    assert any(item["id"] == "overlay_upper" for item in plan.skipped)


def test_selective_without_network_avoids_watchdog(device, tmp_path, logger):
    _dev, passport, _profile, _path, parsed = _archive_for(device, tmp_path, logger)
    tools = dataclasses.replace(passport.tools, available=tuple(t for t in passport.tools.available if t not in ("nohup", "setsid")))
    other = dataclasses.replace(passport, tools=tools)
    report = compatibility.compare(parsed, other, strategy=compatibility.STRATEGY_SELECTIVE, selected=("user_data",))
    parsed_with_data = parsed
    plan = planner.build_plan(
        parsed_with_data, other, report, strategy="selective", selected=("user_data",)
    )
    # user_data is not in the archive for this fixture, so nothing is chosen -> blocked,
    # but the reason must not be the watchdog
    assert all("откат сети" not in item for item in plan.blockers)


def test_plan_dict_is_json_serialisable(device, tmp_path, logger):
    _dev, passport, _profile, _path, parsed = _archive_for(device, tmp_path, logger)
    report = compatibility.compare(parsed, passport, strategy=compatibility.STRATEGY_EXACT)
    plan = planner.build_plan(parsed, passport, report, strategy="exact")
    text = json.dumps(plan.as_dict(), ensure_ascii=False)
    assert "pre-restore-backup" in text


# --- structural guarantee --------------------------------------------------
def test_planning_modules_cannot_write_anything():
    """Dry run is trustworthy only if these modules contain no I/O by design."""
    forbidden = ("subprocess", "owbm.ssh", "owbm.remote", "owbm.backup.collector", "socket")
    for module in (compatibility, migration, planner):
        source = inspect.getsource(module)
        for needle in forbidden:
            assert f"import {needle}" not in source, f"{module.__name__} must not import {needle}"
            assert f"from {needle}" not in source
        for needle in ("open(", "os.remove", "shutil.", "pathlib.Path.write"):
            assert needle not in source, f"{module.__name__} must not use {needle}"


def test_restore_cli_dry_run(device, tmp_path, monkeypatch, capsys):
    from owbm import cli

    dev, _passport, _profile, path, _parsed = _archive_for(device, tmp_path, Logger(json_mode=True))
    monkeypatch.setattr(cli, "SSHClient", lambda *a, **kw: dev.client())
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))

    rc = cli.main(["--backup-root", str(tmp_path / "store"), "restore", str(path), "--host", "192.0.2.1"])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "Пробный прогон" in out
    assert "pre-restore" in out or "Резервная копия целевого" in out

    rc = cli.main(
        ["--backup-root", str(tmp_path / "store"), "restore", str(path), "--host", "192.0.2.1", "--json"]
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["dry_run"] is True
    assert payload["compatible"] == "exact"
    assert rc == 0
