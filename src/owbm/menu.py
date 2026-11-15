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
from . import i18n
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
        suffix = i18n.tr("menu.io.yes_default" if default else "menu.io.no_default")
        try:
            answer = input(f"{question} {suffix} ").strip().lower()
        except EOFError:
            raise KeyboardInterrupt
        if not answer:
            return default
        return answer in ("y", "yes", "д", "да")

    def ask_password(self, prompt: str = "") -> str:
        prompt = prompt or i18n.tr("menu.io.password_prompt")
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
            self.say(f"  0. {i18n.tr('menu.io.back')}")
        raw = self.ask(i18n.tr("menu.io.number_prompt"), "0")
        try:
            number = int(raw)
        except ValueError:
            self.say(i18n.tr("menu.io.invalid_number"))
            return -1
        if number == 0:
            return -1
        if 1 <= number <= len(options):
            return number - 1
        self.say(i18n.tr("menu.io.invalid_choice"))
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
        options = [i18n.tr("menu.device.profile", name=name, host=cfg.devices[name].host) for name in names]
        options.append(i18n.tr("menu.device.manual"))
        choice = self.io.choose(i18n.tr("menu.device.prompt"), options)
        if choice < 0:
            return None
        if choice < len(names):
            return ["--device", names[choice]]
        address = self.io.ask(i18n.tr("menu.device.address_prompt"))
        if not address:
            self.io.say(i18n.tr("menu.device.missing_address"))
            return None
        return ["--host", address]

    def _login(self, cfg: cfgmod.Config, device: List[str]) -> Optional[Tuple[List[str], Optional[str]]]:
        """Collect SSH credentials for this operation; the password stays in memory."""
        args = list(device)
        user = self.io.ask(i18n.tr("menu.ssh.user_prompt"), cfg.ssh.user or "root")
        if user and user != (cfg.ssh.user or "root"):
            args.extend(["--user", user])
        port = self.io.ask(i18n.tr("menu.ssh.port_prompt"), str(cfg.ssh.port))
        if port and port.isdigit() and int(port) != cfg.ssh.port:
            args.extend(["--port", port])
        mode = self.io.choose(
            i18n.tr("menu.ssh.mode_prompt"),
            [i18n.tr("menu.ssh.mode_agent"), i18n.tr("menu.ssh.mode_password")],
        )
        if mode < 0:
            return None
        password = None
        if mode == 1:
            password = self.io.ask_password(i18n.tr("menu.io.password_prompt"))
            if not password:
                self.io.say(i18n.tr("menu.ssh.password_missing"))
                return None
        return args, password

    def _pick_archive(self, cfg: cfgmod.Config) -> Optional[str]:
        store = ArchiveStore(cfg.backup_root())
        items = store.list()
        if not items:
            self.io.say(i18n.tr("menu.archive.none", path=store.root))
            return None
        options = [
            f"{item.created_utc or '?'}  {item.device_label}  {item.release}  "
            f"{human_size(item.size)}  {item.status}"
            + ("" if item.valid else i18n.tr("menu.archive.corrupt", error=item.error))
            for item in items
        ]
        choice = self.io.choose(i18n.tr("menu.archive.choose"), options)
        if choice < 0:
            return None
        return str(items[choice].path)

    def _run(self, argv: List[str], password: Optional[str] = None) -> int:
        from . import cli

        return cli.main(["--lang", i18n.get_language(), *argv], password=password)

    def _report(self, rc: int, ok_text: str) -> None:
        if rc == EXIT_OK:
            self.io.say(f"✓ {ok_text}")
        else:
            self.io.say(i18n.tr("menu.operation.failed", code=rc))
        self.io.say("")

    # -- items -------------------------------------------------------------
    def backup(self) -> None:
        self.io.say("")
        self.io.say(i18n.tr("menu.backup.description.1"))
        self.io.say(i18n.tr("menu.backup.description.2"))
        cfg = self._config()
        device = self._device_args(cfg)
        if device is None:
            return
        login = self._login(cfg, device)
        if login is None:
            return
        device_args, password = login
        binaries = self.io.ask_yes_no(i18n.tr("menu.backup.include_binaries"), default=True)
        argv = device_args + ["--backup-root", str(cfg.backup_root()), "backup"]
        if not binaries:
            argv.append("--no-package-binaries")
        rc = self._run(argv, password=password)
        self._report(rc, i18n.tr("menu.backup.completed"))

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
                i18n.tr("menu.restore.exact"),
                i18n.tr("menu.restore.migration"),
                i18n.tr("menu.restore.selective"),
            ]
            choice = self.io.choose(i18n.tr("menu.restore.strategy_prompt"), variants)
            if choice < 0:
                return
            strategy = ("exact", "migration", "selective")[choice]
        argv = device_args + ["--backup-root", str(cfg.backup_root()), "restore", path, "--strategy", strategy]
        if strategy == "selective":
            chosen = self._pick_components()
            if not chosen:
                self.io.say(i18n.tr("menu.restore.no_categories"))
                return
            for component in chosen:
                argv.extend(["--only", component])
        self.io.say("")
        self.io.say(i18n.tr("menu.restore.confirm_plan"))
        rc = self._run(argv + ["--apply"], password=password)
        self._report(rc, i18n.tr("menu.restore.completed"))

    def _pick_components(self) -> List[str]:
        names = {
            "configuration": i18n.tr("menu.restore.category.configuration"),
            "packages_inventory": i18n.tr("menu.restore.category.packages_inventory"),
            "overlay_upper": i18n.tr("menu.restore.category.overlay_upper"),
            "packages_binaries": i18n.tr("menu.restore.category.packages_binaries"),
            "user_data": i18n.tr("menu.restore.category.user_data"),
            "system_state": i18n.tr("menu.restore.category.system_state"),
        }
        order = list(names)
        options = [names[key] for key in order]
        self.io.say("")
        self.io.say(i18n.tr("menu.restore.categories_prompt"))
        for index, option in enumerate(options, start=1):
            self.io.say(f"  {index}. {option}")
        raw = self.io.ask(i18n.tr("menu.restore.numbers_prompt"), "")
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
        self.io.say(i18n.tr("menu.migrate.description.1"))
        self.io.say(i18n.tr("menu.migrate.description.2"))
        self.io.say(i18n.tr("menu.migrate.description.3"))
        self.io.say(i18n.tr("menu.migrate.description.4"))
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
        if self.io.ask_yes_no(i18n.tr("menu.migrate.replace_config"), default=False):
            argv.append("--replace-config")
        self.io.say("")
        self.io.say(i18n.tr("menu.migrate.confirm_plan"))
        rc = self._run(argv + ["--apply"], password=password)
        self._report(rc, i18n.tr("menu.migrate.completed"))

    def check(self) -> None:
        cfg = self._config()
        path = self._pick_archive(cfg)
        if path is None:
            return
        rc = self._run(["--backup-root", str(cfg.backup_root()), "check", path])
        self._report(rc, i18n.tr("menu.check.completed"))

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
        self._report(rc, i18n.tr("menu.info.completed"))

    def settings(self) -> None:
        cfg = self._config()
        while True:
            self.io.say("")
            self.io.say(i18n.tr("menu.settings.title"))
            self.io.say(i18n.tr("menu.settings.backup_root", path=cfg.backup_root()))
            self.io.say(i18n.tr("menu.settings.ssh_user", user=cfg.ssh.user))
            self.io.say(i18n.tr("menu.settings.host_key_policy", policy=cfg.ssh.host_key_policy))
            self.io.say(i18n.tr("menu.settings.language", value=cfg.general.language))
            self.io.say(i18n.tr("menu.settings.config_path", path=cfg.source))
            self.io.say(f"  0. {i18n.tr('menu.io.back')}")
            choice = self.io.ask(i18n.tr("menu.settings.prompt"), "0")
            language_changed = False
            if choice in ("0", ""):
                return
            if choice == "1":
                value = self.io.ask(i18n.tr("menu.settings.backup_root_prompt"), cfg.general.backup_root)
                cfg.general.backup_root = value
            elif choice == "2":
                cfg.ssh.user = self.io.ask(i18n.tr("menu.ssh.user_prompt"), cfg.ssh.user) or "root"
            elif choice == "3":
                policy = self.io.ask(i18n.tr("menu.settings.host_key_prompt"), cfg.ssh.host_key_policy)
                if policy in cfgmod.HOST_KEY_POLICIES:
                    cfg.ssh.host_key_policy = policy
                else:
                    self.io.say(i18n.tr("menu.settings.invalid_host_key_policy"))
                    continue
            elif choice == "4":
                lang = self.io.ask(i18n.tr("menu.settings.language_prompt"), cfg.general.language)
                if lang in cfgmod.LANGUAGES:
                    cfg.general.language = lang
                    language_changed = True
                else:
                    self.io.say(i18n.tr("menu.settings.invalid_language"))
                    continue
            elif choice == "5":
                self.io.say(i18n.tr("menu.settings.path", path=cfg.source))
                self.io.say(i18n.tr("menu.settings.read_only_config"))
                continue
            else:
                self.io.say(i18n.tr("menu.settings.invalid_choice"))
                continue
            try:
                target = cfgmod.save(cfg)
            except OwbmError as exc:
                self.io.say(exc.render())
                continue
            if choice == "4" and language_changed:
                i18n.set_language(cfg.general.language)
            self.io.say(i18n.tr("menu.settings.saved", path=target))

    def diagnostics(self) -> None:
        cfg = self._config()
        self.io.say("")
        self.io.say(i18n.tr("menu.diagnostics.description"))
        rc = self._run(["--backup-root", str(cfg.backup_root()), "doctor"])
        log_dir = cfg.log_dir()
        logs = sorted(log_dir.glob("owbm-*.log"), key=lambda item: item.stat().st_mtime, reverse=True)
        if logs:
            self.io.say("")
            self.io.say(i18n.tr("menu.diagnostics.latest_log", path=logs[0]))
            if self.io.ask_yes_no(i18n.tr("menu.diagnostics.show_tail"), default=False):
                try:
                    tail = logs[0].read_text(encoding="utf-8").splitlines()[-30:]
                except OSError as exc:
                    self.io.say(i18n.tr("menu.diagnostics.read_error", error=exc))
                    tail = []
                for line in tail:
                    self.io.say(f"  {line}")
        else:
            self.io.say(i18n.tr("menu.diagnostics.no_logs"))
        self._report(rc, i18n.tr("menu.diagnostics.completed"))

    # -- loop --------------------------------------------------------------
    def items(self) -> List[Tuple[str, Callable[[], None]]]:
        return [
            (i18n.tr("menu.item.backup"), self.backup),
            (i18n.tr("menu.item.restore"), lambda: self._restore()),
            (i18n.tr("menu.item.migrate"), self.migrate),
            (i18n.tr("menu.item.check"), self.check),
            (i18n.tr("menu.item.list"), self.list_archives),
            (i18n.tr("menu.item.info"), self.device_info),
            (i18n.tr("menu.item.settings"), self.settings),
            (i18n.tr("menu.item.diagnostics"), self.diagnostics),
            (i18n.tr("menu.item.exit"), self._exit),
        ]

    def _exit(self) -> None:
        self.running = False

    def run(self, language_override: Optional[str] = None) -> int:
        try:
            cfg = self._config()
        except OwbmError as exc:
            self.io.say(exc.render())
            return exc.exit_code
        token = i18n.set_language(language_override or cfg.general.language)
        try:
            self.io.say("")
            self.io.say(i18n.tr("menu.title", version=__version__))
            self.io.say(i18n.tr("menu.storage", path=cfg.backup_root()))
            suffix = "" if cfg.loaded else i18n.tr("menu.config_default_suffix")
            self.io.say(i18n.tr("menu.config", path=cfg.source, suffix=suffix))
            while self.running:
                labels = [title for title, _ in self.items()]
                try:
                    choice = self.io.choose(i18n.tr("menu.main.title"), labels, back=False)
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
                    self.io.say(i18n.tr("menu.menu.unexpected_error", error=exc))
            self.io.say("")
            self.io.say(i18n.tr("menu.goodbye"))
            return EXIT_OK
        finally:
            i18n.reset_language(token)
