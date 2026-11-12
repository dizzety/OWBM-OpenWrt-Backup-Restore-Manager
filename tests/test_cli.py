import json
from types import SimpleNamespace

import pytest

from owbm import cli


@pytest.fixture
def isolated_env(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.delenv("OWBM_CONFIG", raising=False)
    return tmp_path


def test_version_json(isolated_env, capsys):
    rc = cli.main(["version", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["format"] == "owbm"
    assert payload["format_version"] == 1


def test_help_without_command(isolated_env, capsys):
    rc = cli.main([])
    assert rc == 2


def test_info_without_target(isolated_env, capsys):
    rc = cli.main(["info"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "OWBM-E-CFG-003" in err


def test_config_show_defaults(isolated_env, capsys):
    rc = cli.main(["config-show"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "[general]" in out
    assert "не найден" in out


def test_config_init_creates_file(isolated_env, capsys):
    rc = cli.main(["config-init"])
    assert rc == 0
    path = isolated_env / "config" / "owbm" / "config.toml"
    assert path.exists()
    assert (path.stat().st_mode & 0o077) == 0
    assert "192.0.2.1" in path.read_text(encoding="utf-8")

    rc = cli.main(["config-init"])
    assert rc == 2  # refuses to overwrite without --force

    rc = cli.main(["config-init", "--force"])
    assert rc == 0


def test_trust_repins_only_after_terminal_confirmation(monkeypatch):
    candidate = ("ssh-ed25519", "router.fixture ssh-ed25519 example-key")
    clients = []

    class TrustClient:
        def __init__(self, *_args, **_kwargs):
            self.pinned = None
            clients.append(self)

        def known_host_fingerprints(self):
            return ["SHA256:old"]

        def scan_host_keys(self):
            return [candidate]

        def fingerprint(self, _line):
            return "SHA256:new"

        def repin_host_key(self, *, keys):
            self.pinned = keys
            return {"fingerprint": "SHA256:new"}

    class UI:
        def __init__(self):
            self.confirmed = False

        def is_interactive(self):
            return True

        def ask_yes_no(self, question, default=False):
            self.confirmed = question.startswith("Все отпечатки") and default is False
            return self.confirmed

    class Logger:
        def raw(self, _message):
            pass

        def ok(self, _message):
            pass

    monkeypatch.setattr(cli, "SSHClient", TrustClient)
    ui = UI()
    rt = SimpleNamespace(
        args=SimpleNamespace(json=False, accept_host_key=True),
        ui=ui,
        logger=Logger(),
        target=lambda: SimpleNamespace(host="router.fixture", port=22),
        password=lambda: None,
    )

    rc = cli.cmd_trust(rt)

    assert rc == 0
    assert ui.confirmed
    assert clients[0].pinned == [candidate]


def test_trust_refuses_json_even_when_accept_flag_is_set(isolated_env, capsys):
    rc = cli.main(["trust", "--host", "192.0.2.1", "--json", "--accept-host-key"])

    assert rc == 2
    assert "интерактивный терминал" in json.loads(capsys.readouterr().err)["error"]


def test_trust_refuses_noninteractive_accept(isolated_env, capsys):
    rc = cli.main(["trust", "--host", "192.0.2.1", "--accept-host-key"])

    assert rc == 2
    assert "интерактивный терминал" in capsys.readouterr().err


def test_doctor_runs_without_device(isolated_env, capsys):
    rc = cli.main(["doctor"])
    out = capsys.readouterr().out
    assert "Диагностика:" in out
    assert "python" in out
    assert rc in (0, 3)


def test_error_rendering_has_all_four_answers(isolated_env, capsys):
    rc = cli.main(["info", "--host", "192.0.2.1", "--config", str(isolated_env / "nope.toml")])
    err = capsys.readouterr().err
    assert rc != 0
    if "OWBM-" in err:
        assert "Что произошло:" in err or "Что произошло" in err


def test_explicit_empty_archive_is_an_error(isolated_env, capsys):
    """`owbm restore ""` must not silently fall back to the newest archive."""
    rc = cli.main(["restore", "", "--host", "192.0.2.1"])
    err = capsys.readouterr().err
    assert rc == 7
    assert "OWBM-E-ARC-001" in err


def test_missing_archive_path_is_an_error(isolated_env, capsys):
    rc = cli.main(["check", "/nonexistent/backup.owbm"])
    err = capsys.readouterr().err
    assert rc == 7
    assert "/nonexistent/backup.owbm" in err


def test_no_archive_and_empty_store_is_an_error(isolated_env, capsys):
    rc = cli.main(["--backup-root", str(isolated_env / "empty"), "check"])
    err = capsys.readouterr().err
    assert rc == 7
    assert "OWBM-E-ARC-001" in err


def test_keyboard_interrupt_reports_recovery_guidance(isolated_env, capsys, monkeypatch):
    def interrupt(_runtime):
        raise KeyboardInterrupt

    monkeypatch.setitem(cli.COMMANDS, "version", interrupt)
    assert cli.main(["version"]) == 10
    output = capsys.readouterr()
    text = output.out + output.err
    assert "OWBM-E-INT-001" in text
    assert "pre-restore" in text
    assert "проверьте его состояние" in text
