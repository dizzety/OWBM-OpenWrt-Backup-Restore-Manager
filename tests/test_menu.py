import json
from pathlib import Path

import pytest

from owbm import cli, menu


class ScriptedIO(menu.ConsoleIO):
    """Menu driver for tests: answers come from a list, output is captured."""

    def __init__(self, script):
        self.script = list(script)
        self.out = []

    def say(self, message: str = "") -> None:
        self.out.append(str(message))

    def _next(self) -> str:
        if not self.script:
            raise KeyboardInterrupt
        return self.script.pop(0)

    def ask(self, prompt: str, default: str = "") -> str:
        value = self._next()
        return value if value != "" else default

    def ask_yes_no(self, question: str, default: bool = False) -> bool:
        value = self._next().strip().lower()
        if value == "":
            return default
        return value in ("y", "yes", "д", "да")

    def ask_password(self, prompt: str = "Пароль SSH") -> str:
        return self._next()

    def choose(self, title: str, options, back: bool = True) -> int:
        raw = self._next()
        try:
            number = int(raw)
        except ValueError:
            return -1
        if number == 0:
            return -1
        return number - 1 if 1 <= number <= len(options) else -1

    def text(self) -> str:
        return "\n".join(self.out)


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    for name, sub in (
        ("XDG_CONFIG_HOME", "config"),
        ("XDG_DATA_HOME", "data"),
        ("XDG_STATE_HOME", "state"),
        ("XDG_CACHE_HOME", "cache"),
    ):
        monkeypatch.setenv(name, str(tmp_path / sub))
    monkeypatch.delenv("OWBM_CONFIG", raising=False)
    return tmp_path


def _menu(script):
    io = ScriptedIO(script)
    return menu.Menu(io), io


def test_menu_has_all_nine_items():
    instance, _io = _menu([])
    titles = [title for title, _ in instance.items()]
    assert len(titles) == 9
    assert titles[0] == "Создать резервную копию"
    assert titles[-1] == "Выход"


def test_menu_exits_on_nine(isolated, capsys):
    instance, io = _menu(["9"])
    assert instance.run() == 0
    assert "До свидания" in io.text()
    assert "Хранилище:" in io.text()


def test_menu_list_is_empty(isolated, capsys):
    instance, io = _menu(["5", "9"])
    assert instance.run() == 0
    out = capsys.readouterr().out
    assert "Резервных копий нет" in out


def test_menu_settings_persist(isolated):
    target = isolated / "archives"
    instance, io = _menu(["7", "1", str(target), "0", "9"])
    assert instance.run() == 0
    saved = isolated / "config" / "owbm" / "config.toml"
    assert saved.exists()
    assert str(target) in saved.read_text(encoding="utf-8")
    assert "Сохранено" in io.text()


def test_menu_settings_rejects_bad_policy(isolated):
    instance, io = _menu(["7", "3", "maybe", "0", "9"])
    instance.run()
    assert "Допустимо: ask или strict" in io.text()


def test_menu_unknown_choice_returns_to_menu(isolated):
    instance, io = _menu(["42", "9"])
    assert instance.run() == 0
    assert io.script == [], "после неверного ввода меню должно продолжить работу"


def test_menu_eof_exits_cleanly(isolated):
    instance, io = _menu([])
    assert instance.run() == 0
    assert "До свидания" in io.text()


def test_menu_backup_end_to_end(isolated, device, monkeypatch, capsys):
    dev = device("apk_overlay_x86")
    monkeypatch.setattr(cli, "SSHClient", lambda *a, **kw: dev.client())
    root = isolated / "archives"
    instance, io = _menu(["1", "1", "192.0.2.1", "root", "22", "1", "y", "9"])
    # point the menu at an isolated storage
    instance._config = lambda: _cfg(instance, root)
    assert instance.run() == 0
    out = capsys.readouterr().out
    assert "Резервная копия создана" in io.text()
    assert list((root).rglob("*.owbm")), out


def _cfg(instance, root):
    from owbm import config as cfgmod

    cfg = cfgmod.load()
    cfg.general.backup_root = str(root)
    return cfg


def test_menu_check_existing_archive(isolated, device, monkeypatch, capsys):
    from owbm import capabilities, discovery, storage
    from owbm.backup import packager
    from owbm.log import Logger

    dev = device("apk_overlay_x86")
    client = dev.client()
    passport = discovery.discover(client)
    profile = capabilities.analyze(passport)
    root = isolated / "archives"
    store = storage.ArchiveStore(root)
    result = packager.create_backup(
        client, passport, profile, store, packager.BackupOptions(), Logger(json_mode=True)
    )

    monkeypatch.setattr(cli, "SSHClient", lambda *a, **kw: dev.client())
    instance, io = _menu(["4", "1", "9"])
    instance._config = lambda: _cfg(instance, root)
    assert instance.run() == 0
    captured = capsys.readouterr()
    assert "проверен" in io.text() or "Структура и контрольные суммы" in captured.out


def test_menu_device_info(isolated, device, monkeypatch, capsys):
    dev = device("apk_overlay_x86")
    monkeypatch.setattr(cli, "SSHClient", lambda *a, **kw: dev.client())
    instance, io = _menu(["6", "1", "192.0.2.1", "root", "22", "1", "9"])
    assert instance.run() == 0
    out = capsys.readouterr().out
    assert "Устройство:" in out
    assert "Что можно сохранить" in out


def test_menu_selective_components_parsing(isolated):
    instance, io = _menu(["1,3", "x"])
    assert instance._pick_components() == ["configuration", "overlay_upper"]


def test_menu_survives_operation_error(isolated, monkeypatch):
    instance, io = _menu(["6", "1", "192.0.2.1", "root", "22", "1", "9"])

    def boom(*_args, **_kwargs):
        raise RuntimeError("сломалось")

    monkeypatch.setattr(instance, "_run", boom)
    assert instance.run() == 0
    assert "Непредвиденная ошибка" in io.text()


def test_cli_menu_command(isolated, monkeypatch):
    called = {}

    class FakeMenu:
        def run(self):
            called["yes"] = True
            return 0

    monkeypatch.setattr(menu, "Menu", FakeMenu)
    assert cli.main(["menu"]) == 0
    assert called.get("yes") is True


def test_menu_accepts_password_without_touching_argv(isolated, device, monkeypatch):
    dev = device("apk_overlay_x86")
    seen = {}

    def fake_main(argv, password=None):
        seen["argv"] = argv
        seen["password"] = password
        return 0

    import owbm.cli as cli_module

    monkeypatch.setattr(cli_module, "main", fake_main)
    instance, io = _menu(["1", "1", "192.0.2.1", "root", "2222", "2", "s3cret", "y", "9"])
    instance._config = lambda: _cfg(instance, isolated / "archives")
    instance.run()

    assert seen["password"] == "s3cret"
    assert "s3cret" not in " ".join(seen["argv"])
    assert "--port" in seen["argv"] and "2222" in seen["argv"]
    assert "--password-stdin" not in seen["argv"]


def test_menu_login_can_be_aborted(isolated):
    instance, io = _menu(["1", "1", "192.0.2.1", "root", "22", "0", "9"])
    instance._config = lambda: _cfg(instance, isolated / "archives")
    instance.run()
    assert io.script == [], "меню должно продолжить работу после отмены входа"


def test_menu_empty_password_is_refused(isolated):
    instance, io = _menu(["1", "1", "192.0.2.1", "root", "22", "2", "", "9"])
    instance._config = lambda: _cfg(instance, isolated / "archives")
    instance.run()
    assert "Пароль не введён" in io.text()


def test_menu_interrupt_during_operation_shows_recovery_guidance(isolated, monkeypatch):
    instance, io = _menu(["1", "2"])

    def interrupt():
        raise KeyboardInterrupt

    monkeypatch.setattr(
        instance,
        "items",
        lambda: [("Прервать операцию", interrupt), ("Выход", instance._exit)],
    )
    assert instance.run() == 0
    assert "OWBM-E-INT-001" in io.text()
    assert "pre-restore" in io.text()
