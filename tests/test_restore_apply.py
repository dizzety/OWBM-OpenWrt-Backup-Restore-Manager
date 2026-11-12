import dataclasses
import io
import json
import time
from pathlib import Path

import pytest

from owbm import archive, capabilities, discovery, manifest as manifest_mod, storage
from owbm.backup import packager
from owbm.errors import OwbmError
from owbm.log import Logger
from owbm.restore import apply as restore_apply
from owbm.restore import compatibility, planner, rollback


@pytest.fixture
def logger():
    return Logger(json_mode=True)


def _bind_root(monkeypatch, cli, dev):
    """Point the CLI's apply context at the fake device root instead of /."""
    original = restore_apply.ApplyContext

    def factory(**kwargs):
        kwargs.setdefault("root", str(dev.root))
        return original(**kwargs)

    monkeypatch.setattr(cli.restore_apply, "ApplyContext", factory)


def _prepare(device, tmp_path, logger, fixture="apk_overlay_x86"):
    dev = device(fixture)
    client = dev.client()
    passport = discovery.discover(client)
    profile = capabilities.analyze(passport)
    store = storage.ArchiveStore(tmp_path / "store")
    backup = packager.create_backup(client, passport, profile, store, packager.BackupOptions(), logger)
    parsed = manifest_mod.validate(backup.manifest)
    report = compatibility.compare(parsed, passport, strategy=compatibility.STRATEGY_EXACT)
    plan = planner.build_plan(parsed, passport, report, strategy="exact", archive_path=backup.path)
    ctx = restore_apply.ApplyContext(
        client=client,
        passport=passport,
        parsed=parsed,
        profile_caps=profile,
        archive_path=backup.path,
        workdir=tmp_path / "work",
        store=store,
        options=restore_apply.ApplyOptions(watchdog_timeout=3, confirm_timeout=10),
        logger=logger,
        root=str(dev.root),
    )
    ctx.workdir.mkdir(parents=True, exist_ok=True)
    return dev, passport, plan, ctx, store


# --- rollback staging and watchdog -----------------------------------------
def test_stage_copies_network_config(device):
    dev = device("apk_overlay_x86")
    client = dev.client()
    rollback.stage(client, root=str(dev.root))
    staged = dev.root / "tmp" / "owbm-rollback" / "network"
    assert staged.exists()
    assert "loopback" in staged.read_text(encoding="utf-8")


def test_watchdog_restores_previous_network(device):
    dev = device("apk_overlay_x86")
    client = dev.client()
    network = dev.root / "etc" / "config" / "network"
    original = network.read_text(encoding="utf-8")

    rollback.stage(client, root=str(dev.root))
    network.write_text("config interface 'broken'\n", encoding="utf-8")
    rollback.arm(client, root=str(dev.root), timeout=1)

    deadline = time.time() + 10
    while time.time() < deadline:
        if network.read_text(encoding="utf-8") == original:
            break
        time.sleep(0.2)

    assert network.read_text(encoding="utf-8") == original, "watchdog must restore the staged config"

    deadline = time.time() + 10
    while time.time() < deadline and not (dev.root / "reboot.log").exists():
        time.sleep(0.2)
    assert (dev.root / "reboot.log").exists(), "watchdog must reboot after restoring"
    assert not (dev.root / "tmp" / "owbm-armed").exists()


def test_disarm_prevents_rollback(device):
    dev = device("apk_overlay_x86")
    client = dev.client()
    network = dev.root / "etc" / "config" / "network"
    rollback.stage(client, root=str(dev.root))
    network.write_text("config interface 'new'\n", encoding="utf-8")
    rollback.arm(client, root=str(dev.root), timeout=1)
    rollback.disarm(client, root=str(dev.root))
    time.sleep(1.5)
    assert network.read_text(encoding="utf-8") == "config interface 'new'\n"
    assert not (dev.root / "reboot.log").exists()
    assert not (dev.root / "tmp" / "owbm-rollback").exists()


def test_whiteout_replay_rejects_unsafe_paths():
    with pytest.raises(OwbmError) as exc:
        rollback.replay_whiteouts_script(["../../etc/passwd"])
    assert exc.value.code == "OWBM-E-CHK-003"


def test_whiteout_replay_deletes_files(device):
    from owbm.remote import run_probe

    dev = device("apk_overlay_x86")
    target = dev.root / "etc" / "config" / "removed.conf"
    target.write_text("x", encoding="utf-8")
    body = rollback.replay_whiteouts_script(["etc/config/removed.conf"], root=str(dev.root))
    head = run_probe(dev.client(), body, root=str(dev.root))
    assert head.has("DONE")
    assert not target.exists()


# --- apply -----------------------------------------------------------------
def test_apply_runs_full_plan(device, tmp_path, logger):
    dev, passport, plan, ctx, store = _prepare(device, tmp_path, logger)
    result = restore_apply.apply_plan(ctx, plan)

    assert result.ok, result.messages
    assert result.failed is None
    assert not result.armed
    steps = [item["step"] for item in result.done]
    assert steps[0] == "pre-restore-backup"
    assert "apply-configuration" in steps
    assert steps[-1] == "confirm"

    snapshots = [item for item in store.list() if item.mode == "pre-restore"]
    assert len(snapshots) == 1, "pre-restore snapshot must exist in a separate area"
    assert not (dev.root / "tmp" / "owbm-armed").exists()
    assert not (dev.root / "tmp" / "owbm-watchdog.sh").exists()
    assert not (dev.root / "tmp" / "owbm-rollback").exists()


def test_apply_restores_configuration_files(device, tmp_path, logger):
    dev, passport, plan, ctx, store = _prepare(device, tmp_path, logger)
    network = dev.root / "etc" / "config" / "network"
    network.write_text("config interface 'wiped'\n", encoding="utf-8")
    result = restore_apply.apply_plan(ctx, plan)
    assert result.ok, result.messages
    restored = network.read_text(encoding="utf-8")
    assert restored != "config interface 'wiped'\n", "файл должен быть перезаписан из архива"
    assert "config interface 'lan'" in restored


def test_apply_failure_keeps_watchdog_armed(device, tmp_path, logger, monkeypatch):
    dev, passport, plan, ctx, store = _prepare(device, tmp_path, logger)

    def boom(*_args, **_kwargs):
        raise OwbmError("OWBM-E-RST-001", step="overlay_upper", reason="имитация обрыва")

    monkeypatch.setattr(restore_apply, "_apply_component", boom)
    result = restore_apply.apply_plan(ctx, plan)

    assert result.status == restore_apply.STATUS_FAILED
    assert result.failed == "apply-configuration"
    assert result.armed is True
    assert (dev.root / "tmp" / "owbm-armed").exists(), "watchdog must stay armed after a failure"
    assert any("Сторожевой процесс оставлен" in item for item in result.messages)


def test_apply_refuses_when_plan_is_blocked(device, tmp_path, logger):
    dev, passport, plan, ctx, store = _prepare(device, tmp_path, logger)
    plan.blockers.append("нет nohup")
    result = restore_apply.apply_plan(ctx, plan)
    assert result.status == restore_apply.STATUS_ABORTED
    assert result.done == []


def test_apply_refuses_reboot_while_armed(device, tmp_path, logger):
    dev, passport, plan, ctx, store = _prepare(device, tmp_path, logger)
    state = {"armed": True}
    with pytest.raises(OwbmError) as exc:
        restore_apply._reboot(ctx, plan, state)
    assert exc.value.code == "OWBM-E-RST-001"


def test_apply_reboot_uses_device_binary(device, tmp_path, logger):
    dev, passport, plan, ctx, store = _prepare(device, tmp_path, logger)
    restore_apply._reboot(ctx, plan, {"armed": False})
    deadline = time.time() + 8
    while time.time() < deadline and not (dev.root / "reboot.log").exists():
        time.sleep(0.2)
    assert (dev.root / "reboot.log").exists()


def test_pre_restore_snapshot_is_taken_before_changes(device, tmp_path, logger):
    dev, passport, plan, ctx, store = _prepare(device, tmp_path, logger)
    network = dev.root / "etc" / "config" / "network"
    network.write_text("config interface 'target-only'\n", encoding="utf-8")
    result = restore_apply.apply_plan(ctx, plan)
    assert result.ok, result.messages

    snapshot = [item for item in store.list() if item.mode == "pre-restore"][0]
    payload = archive.extract_member(snapshot.path, "payload/configuration.tar.gz", tmp_path / "snap")
    import tarfile

    with tarfile.open(payload, "r:gz") as tf:
        names = tf.getnames()
    assert any("network" in name for name in names)


def test_apply_result_is_json(device, tmp_path, logger):
    dev, passport, plan, ctx, store = _prepare(device, tmp_path, logger)
    result = restore_apply.apply_plan(ctx, plan)
    text = json.dumps(result.as_dict(), ensure_ascii=False)
    assert '"status": "applied"' in text


def test_cli_apply_end_to_end(device, tmp_path, monkeypatch, capsys):
    from owbm import cli

    dev = device("apk_overlay_x86")
    client = dev.client()
    passport = discovery.discover(client)
    profile = capabilities.analyze(passport)
    store = storage.ArchiveStore(tmp_path / "store")
    backup = packager.create_backup(client, passport, profile, store, packager.BackupOptions(), Logger(json_mode=True))

    monkeypatch.setattr(cli, "SSHClient", lambda *a, **kw: dev.client())
    _bind_root(monkeypatch, cli, dev)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))

    rc = cli.main(
        [
            "--backup-root",
            str(tmp_path / "store"),
            "restore",
            str(backup.path),
            "--host",
            "192.0.2.1",
            "--apply",
            "--yes",
            "--watchdog-timeout",
            "2",
            "--confirm-timeout",
            "10",
        ]
    )
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert rc == 0, out
    assert "Восстановление выполнено" in out
    assert "Шагов выполнено" in out
    assert not (dev.root / "tmp" / "owbm-armed").exists()


def test_cli_apply_requires_confirmation(device, tmp_path, monkeypatch, capsys):
    from owbm import cli

    dev = device("apk_overlay_x86")
    client = dev.client()
    passport = discovery.discover(client)
    profile = capabilities.analyze(passport)
    store = storage.ArchiveStore(tmp_path / "store")
    backup = packager.create_backup(client, passport, profile, store, packager.BackupOptions(), Logger(json_mode=True))

    monkeypatch.setattr(cli, "SSHClient", lambda *a, **kw: dev.client())
    _bind_root(monkeypatch, cli, dev)
    monkeypatch.setattr("builtins.input", lambda *_: "no")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))

    rc = cli.main(
        ["--backup-root", str(tmp_path / "store"), "restore", str(backup.path), "--host", "192.0.2.1", "--apply"]
    )
    captured = capsys.readouterr()
    assert rc == 0
    assert "Отменено" in (captured.out + captured.err)
    assert not (dev.root / "tmp" / "owbm-armed").exists()


class _KeyClient:
    """Minimal client double for the host-key rotation logic."""

    class _Target:
        host = "192.0.2.1"
        port = 22
        known_hosts = Path("/tmp/kh")

    def __init__(self):
        self.target = self._Target()
        self.scan_count = 0
        self.pinned = None
        self.candidate = ("ssh-ed25519", "192.0.2.1 ssh-ed25519 candidate-key")
        self.candidates = [self.candidate, ("ssh-rsa", "192.0.2.1 ssh-rsa other-key")]

    def scan_host_keys(self):
        self.scan_count += 1
        return self.candidates

    def fingerprint(self, _key_line):
        return "SHA256:candidate"

    def known_host_fingerprints(self):
        return ["SHA256:old"]

    def repin_host_key(self, *, keys=None):
        self.pinned = list(keys or [])
        return {"fingerprint": "SHA256:candidate"}


class _ConfirmUI:
    def __init__(self, answer, interactive=True):
        self.answer = answer
        self.interactive = interactive
        self.messages = []
        self.questions = []

    def is_interactive(self):
        return self.interactive

    def say(self, message):
        self.messages.append(message)

    def ask_yes_no(self, question, default=False):
        self.questions.append((question, default))
        return self.answer


def _rotation_context(passport, client, ui, *, json_mode=False):
    return restore_apply.ApplyContext(
        client=client, passport=passport, parsed=None, profile_caps=None,
        archive_path=Path("/tmp/x.owbm"), workdir=Path("/tmp"), store=None,
        options=restore_apply.ApplyOptions(),
        logger=Logger(json_mode=json_mode, stream=io.StringIO()), ui=ui,
    )


def test_host_key_rotation_requires_manual_fingerprint_confirmation(device):
    dev = device("apk_overlay_x86")
    passport = discovery.discover(dev.client())
    client = _KeyClient()
    ui = _ConfirmUI(answer=True)
    ctx = _rotation_context(passport, client, ui)
    error = OwbmError("OWBM-E-SSH-003", host="192.0.2.1", port=22, known_hosts="/tmp/kh")

    recovered = restore_apply._recover_host_key(
        ctx, "apply-system_state", {"configuration_applied": True}, error
    )

    assert recovered is True
    assert client.scan_count == 1
    assert client.pinned == client.candidates
    assert sum("SHA256:candidate" in message for message in ui.messages) == 2
    assert ui.questions and ui.questions[0][1] is False


def test_host_key_rotation_decline_does_not_change_pin(device):
    dev = device("apk_overlay_x86")
    passport = discovery.discover(dev.client())
    client = _KeyClient()
    ui = _ConfirmUI(answer=False)
    ctx = _rotation_context(passport, client, ui)
    error = OwbmError("OWBM-E-SSH-003", host="192.0.2.1", port=22, known_hosts="/tmp/kh")

    recovered = restore_apply._recover_host_key(
        ctx, "apply-system_state", {"configuration_applied": True}, error
    )

    assert recovered is False
    assert client.pinned is None
    assert client.scan_count == 1


def test_host_key_rotation_is_not_accepted_without_a_terminal(device):
    dev = device("apk_overlay_x86")
    passport = discovery.discover(dev.client())
    client = _KeyClient()
    ui = _ConfirmUI(answer=True, interactive=False)
    ctx = _rotation_context(passport, client, ui)
    error = OwbmError("OWBM-E-SSH-003", host="192.0.2.1", port=22, known_hosts="/tmp/kh")

    recovered = restore_apply._recover_host_key(
        ctx, "apply-system_state", {"configuration_applied": True}, error
    )

    assert recovered is False
    assert client.scan_count == 0
    assert client.pinned is None


def test_host_key_rotation_is_not_accepted_in_json_mode(device):
    dev = device("apk_overlay_x86")
    passport = discovery.discover(dev.client())
    client = _KeyClient()
    ui = _ConfirmUI(answer=True)
    ctx = _rotation_context(passport, client, ui, json_mode=True)
    error = OwbmError("OWBM-E-SSH-003", host="192.0.2.1", port=22, known_hosts="/tmp/kh")

    recovered = restore_apply._recover_host_key(
        ctx, "apply-system_state", {"configuration_applied": True}, error
    )

    assert recovered is False
    assert client.scan_count == 0
    assert client.pinned is None


def test_failed_restore_rolls_configuration_back(device, tmp_path, logger, monkeypatch):
    """After a failure the target must not keep another device's configuration."""
    dev, passport, plan, ctx, store = _prepare(device, tmp_path, logger)
    network = dev.root / "etc" / "config" / "network"
    original = network.read_text(encoding="utf-8")

    calls = {"n": 0}
    real_apply = restore_apply._apply_component

    def flaky(ctx_arg, component_id=None, applied=None, state=None):
        if component_id == "packages_binaries":
            raise OwbmError("OWBM-E-RST-001", step="packages_binaries", reason="имитация сбоя")
        return real_apply(ctx_arg, component_id, applied)

    monkeypatch.setattr(restore_apply, "_apply_component", flaky)

    # break the target config so the rollback has something to undo
    network.write_text("config interface 'from-other-router'\n", encoding="utf-8")

    result = restore_apply.apply_plan(ctx, plan)
    assert result.status == restore_apply.STATUS_FAILED
    assert any("возвращена к снимку pre-restore" in item for item in result.messages)

    restored = network.read_text(encoding="utf-8")
    assert restored != "config interface 'from-other-router'\n"
    assert "loopback" in restored or "lan" in restored


def _selective_ctx(device, tmp_path, logger, monkeypatch, fixture="apk_overlay_x86", fail_install=False):
    """Config-only restore: package archives must be installed, not just unpacked."""
    dev = device(fixture)
    client = dev.client()
    passport = discovery.discover(client)
    profile = capabilities.analyze(passport)
    store = storage.ArchiveStore(tmp_path / "store")
    backup = packager.create_backup(client, passport, profile, store, packager.BackupOptions(), logger)
    parsed = manifest_mod.validate(backup.manifest)
    selected = ("configuration", "packages_binaries")
    report = compatibility.compare(parsed, passport, strategy=compatibility.STRATEGY_SELECTIVE, selected=selected)
    plan = planner.build_plan(parsed, passport, report, strategy="selective", selected=selected)
    if fail_install:
        monkeypatch.setenv("FAKE_APK_ADD_FAIL", "1")
    ctx = restore_apply.ApplyContext(
        client=client,
        passport=passport,
        parsed=parsed,
        profile_caps=profile,
        archive_path=backup.path,
        workdir=tmp_path / "work",
        store=store,
        options=restore_apply.ApplyOptions(watchdog_timeout=3, confirm_timeout=10, install_packages=True),
        logger=logger,
        root=str(dev.root),
    )
    ctx.workdir.mkdir(parents=True, exist_ok=True)
    return dev, plan, ctx


def test_packages_are_installed_from_archive(device, tmp_path, logger, monkeypatch):
    dev, plan, ctx = _selective_ctx(device, tmp_path, logger, monkeypatch)
    result = restore_apply.apply_plan(ctx, plan)
    assert result.ok, result.messages
    log = dev.root / "install.log"
    assert log.exists(), "установщик пакетов не вызывался"
    assert not (dev.root / "tmp" / "owbm-packages").exists(), "временный каталог должен быть убран"
    text = log.read_text(encoding="utf-8")
    assert "--allow-untrusted" in text and "--force-non-repository" in text
    assert ".apk" in text


def test_packages_can_be_left_uninstalled(device, tmp_path, logger, monkeypatch):
    dev, plan, ctx = _selective_ctx(device, tmp_path, logger, monkeypatch)
    ctx.options.install_packages = False
    result = restore_apply.apply_plan(ctx, plan)
    assert result.ok, result.messages
    assert not (dev.root / "install.log").exists()


def test_install_failure_is_reported_not_hidden(device, tmp_path, logger, monkeypatch):
    dev, plan, ctx = _selective_ctx(device, tmp_path, logger, monkeypatch, fail_install=True)
    result = restore_apply.apply_plan(ctx, plan)
    assert result.status == restore_apply.STATUS_PARTIAL
    assert any("Пакеты не установлены" in item for item in result.messages)


def test_install_is_skipped_when_system_files_are_restored(device, tmp_path, logger, monkeypatch):
    dev = device("apk_overlay_x86")
    client = dev.client()
    passport = discovery.discover(client)
    profile = capabilities.analyze(passport)
    store = storage.ArchiveStore(tmp_path / "store")
    backup = packager.create_backup(client, passport, profile, store, packager.BackupOptions(), logger)
    parsed = manifest_mod.validate(backup.manifest)
    report = compatibility.compare(parsed, passport, strategy=compatibility.STRATEGY_EXACT)
    plan = planner.build_plan(parsed, passport, report, strategy="exact")
    ctx = restore_apply.ApplyContext(
        client=client, passport=passport, parsed=parsed, profile_caps=profile,
        archive_path=backup.path, workdir=tmp_path / "work", store=store,
        options=restore_apply.ApplyOptions(watchdog_timeout=3, confirm_timeout=10),
        logger=logger, root=str(dev.root),
    )
    ctx.workdir.mkdir(parents=True, exist_ok=True)
    result = restore_apply.apply_plan(ctx, plan)
    assert result.ok, result.messages
    assert not (dev.root / "install.log").exists(), "при восстановлении системы пакеты ставить не нужно"
