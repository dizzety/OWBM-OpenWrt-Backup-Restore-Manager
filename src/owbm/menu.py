"""Interactive menu: the primary interface for people who do not want a CLI.

Every screen explains what is about to happen, what it costs and what it changes.
All real work is delegated to the same commands as the CLI, so there is exactly
one implementation of every operation.
"""

from __future__ import annotations

import getpass
import sys
from typing import Callable, List, Optional, Sequence, Tuple

from . import __version__, capabilities, config as cfgmod, discovery
from .errors import EXIT_OK, OwbmError
from .log import Logger
from .ssh import UI
from .storage import ArchiveStore
from .util import human_size


class ConsoleIO(UI):
    """Prompting surface; replaceable in tests."""

    def say(self, message: str = "") -> None:
        print(message, flush=True)

    def ask(self, prompt: str, default: str = "") -> str:
        suffix = f" [{default}]" if default else ""
        try:
            answer = input(f"{prompt}{suffix}: ").strip()
        except EOFError:
            raise KeyboardInterrupt
        return answer or default

    def ask_yes_no(self, question: str, default: bool = False) -> bool:
        suffix = "[Y/n]" if default else "[y/N]"
        try:
            answer = input(f"{question} {suffix} ").strip().lower()
        except EOFError:
            raise KeyboardInterrupt
        if not answer:
            return default
        return answer in ("y", "yes", "д", "да")

    def ask_password(self, prompt: str = "Пароль SSH") -> str:
        try:
            return getpass.getpass(f"{prompt}: ")
        except (EOFError, KeyboardInterrupt):
            raise KeyboardInterrupt

    def choose(self, title: str, options: Sequence[str], back: bool = True) -> int:
        self.say("")
        self.say(title)
        for index, option in enumerate(options, start=1):
            self.say(f"  {index}. {option}")
        if back:
            self.say("  0. назад")
        raw = self.ask("Номер", "0")
        try:
            number = int(raw)
        except ValueError:
            self.say("Нужно ввести число.")
            return -1
        if number == 0:
            return -1
        if 1 <= number <= len(options):
            return number - 1
        self.say("Такого номера нет.")
        return -1


class Menu:
    def __init__(self, io: Optional[ConsoleIO] = None) -> None:
        self.io = io or ConsoleIO()
        self.running = True

    # -- helpers -----------------------------------------------------------
    def _config(self) -> cfgmod.Config:
        return cfgmod.load()

    def _device_args(self, cfg: cfgmod.Config) -> Optional[List[str]]:
        names = cfg.device_names()
        options = [f"профиль: {name} ({cfg.devices[name].host})" for name in names]
        options.append("ввести адрес вручную")
        choice = self.io.choose("К какому устройству подключаться?", options)
        if choice < 0:
            return None
        if choice < len(names):
            return ["--device", names[choice]]
        address = self.io.ask("Адрес или имя устройства (IP, DNS, ssh alias)")
        if not address:
            self.io.say("Адрес не указан.")
            return None
        return ["--host", address]

    def _login(self, cfg: cfgmod.Config, device: List[str]) -> Optional[Tuple[List[str], Optional[str]]]:
        """Collect SSH credentials for this operation; the password stays in memory."""
        args = list(device)
        user = self.io.ask("Пользователь SSH", cfg.ssh.user or "root")
        if user and user != (cfg.ssh.user or "root"):
            args.extend(["--user", user])
        port = self.io.ask("Порт SSH", str(cfg.ssh.port))
        if port and port.isdigit() and int(port) != cfg.ssh.port:
            args.extend(["--port", port])
        mode = self.io.choose(
            "Как подключаться?",
            ["ключ или SSH agent (по умолчанию в системе)", "пароль root (спрошу сейчас)"],
        )
        if mode < 0:
            return None
        password = None
        if mode == 1:
            password = self.io.ask_password("Пароль SSH")
            if not password:
                self.io.say("Пароль не введён.")
                return None
        return args, password

    def _pick_archive(self, cfg: cfgmod.Config) -> Optional[str]:
        store = ArchiveStore(cfg.backup_root())
        items = store.list()
        if not items:
            self.io.say(f"Резервных копий нет: {store.root}")
            return None
        options = [
            f"{item.created_utc or '?'}  {item.device_label}  {item.release}  "
            f"{human_size(item.size)}  {item.status}"
            + ("" if item.valid else f"  [повреждён: {item.error}]")
            for item in items
        ]
        choice = self.io.choose("Выберите резервную копию (новые сверху):", options)
        if choice < 0:
            return None
        return str(items[choice].path)

    def _run(self, argv: List[str], password: Optional[str] = None) -> int:
        from . import cli

        return cli.main(argv, password=password)

    def _report(self, rc: int, ok_text: str) -> None:
        if rc == EXIT_OK:
            self.io.say(f"✓ {ok_text}")
        else:
            self.io.say(f"✗ Операция завершилась с кодом {rc}. Подробности выше.")
        self.io.say("")

    # -- items -------------------------------------------------------------
    def backup(self) -> None:
        self.io.say("")
        self.io.say("Резервная копия сохраняет конфигурацию OpenWrt, систему в записываемом слое")
        self.io.say("и сведения о пакетах. Устройство не изменяется. Существующие копии не трогаются.")
        cfg = self._config()
        device = self._device_args(cfg)
        if device is None:
            return
        login = self._login(cfg, device)
        if login is None:
            return
        device_args, password = login
        binaries = self.io.ask_yes_no(
            "Сохранить бинарные пакеты для восстановления без интернета?", default=True
        )
        argv = device_args + ["--backup-root", str(cfg.backup_root()), "backup"]
        if not binaries:
            argv.append("--no-package-binaries")
        rc = self._run(argv, password=password)
        self._report(rc, "Резервная копия создана.")

    def _restore(self, strategy: Optional[str] = None) -> None:
        cfg = self._config()
        device = self._device_args(cfg)
        if device is None:
            return
        login = self._login(cfg, device)
        if login is None:
            return
        device_args, password = login
        path = self._pick_archive(cfg)
        if path is None:
            return
        if strategy is None:
            variants = [
                "Exact Restore — на такое же устройство (проверка полной совместимости)",
                "Migration Restore — на другое оборудование (с адаптацией)",
                "Selective Restore — только выбранные категории",
            ]
            choice = self.io.choose("Стратегия восстановления:", variants)
            if choice < 0:
                return
            strategy = ("exact", "migration", "selective")[choice]
        argv = device_args + ["--backup-root", str(cfg.backup_root()), "restore", path, "--strategy", strategy]
        if strategy == "selective":
            chosen = self._pick_components()
            if not chosen:
                self.io.say("Категории не выбраны.")
                return
            for component in chosen:
                argv.extend(["--only", component])
        self.io.say("")
        self.io.say("Сначала будет показан план. Изменения начнутся только после ввода слова RESTORE.")
        rc = self._run(argv + ["--apply"], password=password)
        self._report(rc, "Восстановление завершено.")

    def _pick_components(self) -> List[str]:
        names = {
            "configuration": "Конфигурация OpenWrt",
            "packages_inventory": "Список пакетов",
            "overlay_upper": "Файлы системы и приложений",
            "packages_binaries": "Бинарные пакеты",
            "user_data": "Пользовательские каталоги",
            "system_state": "Службы и скрипты",
        }
        order = list(names)
        options = [names[key] for key in order]
        self.io.say("")
        self.io.say("Категории (введите номера через запятую, например 1,2):")
        for index, option in enumerate(options, start=1):
            self.io.say(f"  {index}. {option}")
        raw = self.io.ask("Номера", "")
        result: List[str] = []
        for chunk in raw.replace(" ", ",").split(","):
            if not chunk.isdigit():
                continue
            index = int(chunk) - 1
            if 0 <= index < len(order) and order[index] not in result:
                result.append(order[index])
        return result

    def migrate(self) -> None:
        """Роутер → роутер, роутер → VM, VM → роутер, VM → VM: одинаковый путь."""
        self.io.say("")
        self.io.say("Перенос системы на другое устройство. Источник — любой архив OWBM")
        self.io.say("(с роутера или виртуальной машины), цель — любое OpenWrt-устройство.")
        self.io.say("Пакеты ставятся из репозиториев цели или из совместимых файлов архива.")
        self.io.say("Перед изменениями OWBM создаёт снимок цели; при сбое конфиги откатываются.")
        cfg = self._config()
        device = self._device_args(cfg)
        if device is None:
            return
        login = self._login(cfg, device)
        if login is None:
            return
        device_args, password = login
        path = self._pick_archive(cfg)
        if path is None:
            return
        argv = device_args + ["--backup-root", str(cfg.backup_root()), "migrate", path]
        if self.io.ask_yes_no(
            "Заменить и системные конфиги цели (сеть, firewall, ssh)? "
            "Обычно нет: их нужно адаптировать под железо цели", default=False
        ):
            argv.append("--replace-config")
        self.io.say("")
        self.io.say("Сначала будет показан план. Изменения начнутся только после ввода слова MIGRATE.")
        rc = self._run(argv + ["--apply"], password=password)
        self._report(rc, "Перенос завершён.")

    def check(self) -> None:
        cfg = self._config()
        path = self._pick_archive(cfg)
        if path is None:
            return
        rc = self._run(["--backup-root", str(cfg.backup_root()), "check", path])
        self._report(rc, "Архив проверен.")

    def list_archives(self) -> None:
        cfg = self._config()
        rc = self._run(["--backup-root", str(cfg.backup_root()), "list"])
        if rc != EXIT_OK:
            self._report(rc, "")

    def device_info(self) -> None:
        cfg = self._config()
        device = self._device_args(cfg)
        if device is None:
            return
        login = self._login(cfg, device)
        if login is None:
            return
        device_args, password = login
        rc = self._run(device_args + ["info"], password=password)
        self._report(rc, "Информация получена (устройство не изменялось).")

    def settings(self) -> None:
        cfg = self._config()
        while True:
            self.io.say("")
            self.io.say("Настройки программы:")
            self.io.say(f"  1. Каталог резервных копий: {cfg.backup_root()}")
            self.io.say(f"  2. Пользователь SSH: {cfg.ssh.user}")
            self.io.say(f"  3. Проверка ключа хоста: {cfg.ssh.host_key_policy}")
            self.io.say(f"  4. Язык: {cfg.general.language}")
            self.io.say(f"  5. Файл конфигурации: {cfg.source}")
            self.io.say("  0. назад")
            choice = self.io.ask("Что изменить", "0")
            if choice in ("0", ""):
                return
            if choice == "1":
                value = self.io.ask("Новый каталог (пусто — по умолчанию)", cfg.general.backup_root)
                cfg.general.backup_root = value
            elif choice == "2":
                cfg.ssh.user = self.io.ask("Пользователь SSH", cfg.ssh.user) or "root"
            elif choice == "3":
                policy = self.io.ask("Политика (ask/strict)", cfg.ssh.host_key_policy)
                if policy in cfgmod.HOST_KEY_POLICIES:
                    cfg.ssh.host_key_policy = policy
                else:
                    self.io.say("Допустимо: ask или strict.")
                    continue
            elif choice == "4":
                lang = self.io.ask("Язык (ru/en)", cfg.general.language)
                if lang in cfgmod.LANGUAGES:
                    cfg.general.language = lang
                else:
                    self.io.say("Допустимо: ru или en.")
                    continue
            elif choice == "5":
                self.io.say(f"Путь: {cfg.source}")
                self.io.say("Файл создаётся командой owbm config-init; здесь он только показывается.")
                continue
            else:
                self.io.say("Такого пункта нет.")
                continue
            try:
                target = cfgmod.save(cfg)
            except OwbmError as exc:
                self.io.say(exc.render())
                continue
            self.io.say(f"✓ Сохранено: {target}")

    def diagnostics(self) -> None:
        cfg = self._config()
        self.io.say("")
        self.io.say("Проверка окружения и доступности устройства. Ничего не изменяется.")
        rc = self._run(["--backup-root", str(cfg.backup_root()), "doctor"])
        log_dir = cfg.log_dir()
        logs = sorted(log_dir.glob("owbm-*.log"), key=lambda item: item.stat().st_mtime, reverse=True)
        if logs:
            self.io.say("")
            self.io.say(f"Последний журнал: {logs[0]}")
            if self.io.ask_yes_no("Показать последние строки?", default=False):
                try:
                    tail = logs[0].read_text(encoding="utf-8").splitlines()[-30:]
                except OSError as exc:
                    self.io.say(f"Не удалось прочитать журнал: {exc}")
                    tail = []
                for line in tail:
                    self.io.say(f"  {line}")
        else:
            self.io.say("Журналов пока нет.")
        self._report(rc, "Диагностика завершена.")

    # -- loop --------------------------------------------------------------
    def items(self) -> List[Tuple[str, Callable[[], None]]]:
        return [
            ("Создать резервную копию", self.backup),
            ("Восстановить устройство", lambda: self._restore()),
            ("Перенести систему на другое устройство", self.migrate),
            ("Проверить резервную копию", self.check),
            ("Посмотреть список резервных копий", self.list_archives),
            ("Просмотреть информацию об устройстве", self.device_info),
            ("Настройки программы", self.settings),
            ("Диагностика и журнал операций", self.diagnostics),
            ("Выход", self._exit),
        ]

    def _exit(self) -> None:
        self.running = False

    def run(self) -> int:
        self.io.say("")
        self.io.say(f"OWBM {__version__} — резервное копирование и восстановление OpenWrt")
        try:
            cfg = self._config()
        except OwbmError as exc:
            self.io.say(exc.render())
            return exc.exit_code
        self.io.say(f"Хранилище: {cfg.backup_root()}")
        self.io.say(f"Конфигурация: {cfg.source}" + ("" if cfg.loaded else " (нет файла, значения по умолчанию)"))
        while self.running:
            labels = [title for title, _ in self.items()]
            try:
                choice = self.io.choose("Главное меню:", labels, back=False)
            except KeyboardInterrupt:
                self.running = False
                break
            if choice < 0:
                continue
            handler = self.items()[choice][1]
            try:
                handler()
            except KeyboardInterrupt:
                self.io.say("")
                self.io.say(OwbmError("OWBM-E-INT-001").render())
            except OwbmError as exc:
                self.io.say(exc.render())
            except Exception as exc:  # noqa: BLE001 - menu must not die
                self.io.say(f"Непредвиденная ошибка: {exc}")
        self.io.say("")
        self.io.say("До свидания.")
        return EXIT_OK
