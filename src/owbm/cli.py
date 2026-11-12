"""Command line interface.

Interactive menu is a thin layer on top of these operations (see menu.py); every
operation here is also usable non-interactively, which is what the tests use.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__, archive, capabilities, config as cfgmod, discovery, manifest as manifest_mod, migrate
from .backup import packager, planner
from .restore import apply as restore_apply
from .restore import compatibility, planner as restore_planner
from .errors import EXIT_OK, EXIT_PARTIAL, EXIT_USAGE, OwbmError, fail
from .log import Logger
from .ssh import SSHClient, SSHTarget, UI
from .storage import ArchiveStore
from .util import clock_sanity, human_size, platform_summary, which


class Runtime:
    def __init__(self, args: argparse.Namespace, password: Optional[str] = None) -> None:
        self.args = args
        self._password = password
        self.ui = UI()
        config_path = Path(args.config).expanduser() if getattr(args, "config", None) else None
        self.cfg = cfgmod.load(config_path)
        if getattr(args, "backup_root", None):
            self.cfg.general.backup_root = os.path.expanduser(args.backup_root)
        if getattr(args, "lang", None):
            self.cfg.general.language = args.lang
        if getattr(args, "accept_host_key", False):
            pass
        self.logger = Logger(
            verbose=getattr(args, "verbose", False),
            quiet=getattr(args, "quiet", False),
            json_mode=getattr(args, "json", False),
            log_dir=None if getattr(args, "json", False) else self.cfg.log_dir(),
        )

    def close(self) -> None:
        self.logger.close()

    # -- target ------------------------------------------------------------
    def target(self) -> SSHTarget:
        args = self.args
        ssh = self.cfg.ssh
        host = ""
        user = ssh.user
        port = ssh.port
        identity = ssh.identity_file
        jump = ssh.proxy_jump
        if getattr(args, "host", None):
            host = args.host
        elif getattr(args, "device", None):
            profile = self.cfg.resolve_device(args.device)
            host = profile.host
            user = profile.user or user
            port = profile.port or port
            identity = profile.identity_file or identity
            jump = profile.proxy_jump or jump
        else:
            raise fail("OWBM-E-CFG-003", name="<не указано устройство>")
        if getattr(args, "user", None):
            user = args.user
        if getattr(args, "port", None):
            port = args.port
        if getattr(args, "identity", None):
            identity = args.identity
        if getattr(args, "jump", None):
            jump = args.jump
        return SSHTarget(
            host=host,
            user=user,
            port=port,
            identity_file=identity or "",
            proxy_jump=jump or "",
            connect_timeout=ssh.connect_timeout,
            known_hosts=self.cfg.known_hosts(),
            host_key_policy=ssh.host_key_policy,
        )

    def password(self) -> Optional[str]:
        if self._password is not None:
            return self._password
        if getattr(self.args, "password_stdin", False):
            line = sys.stdin.readline()
            return line.rstrip("\n") if line else None
        return None

    def client(self) -> SSHClient:
        target = self.target()
        client = SSHClient(target, logger=self.logger, password=self.password())
        info = client.ensure_host_key(accept=getattr(self.args, "accept_host_key", False), ui=self.ui)
        if info:
            self.logger.ok(f"Ключ устройства сохранён: {info['fingerprint']}")
        return client


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
def cmd_migrate(rt: Runtime) -> int:
    """Reproduce the archived device on the target device."""
    args = rt.args
    store = _store(rt)
    path = _resolve_archive(rt, store, getattr(args, "archive", None))
    report = archive.verify_archive(path)
    report.raise_first()
    parsed = manifest_mod.validate(report.manifest or {})

    client = rt.client()
    rt.logger.step(f"Опрос целевого устройства {client.target.describe()} (только чтение)")
    passport = discovery.discover(client, logger=rt.logger)

    options = migrate.MigrateOptions(
        install_packages=not getattr(args, "no_install_packages", False),
        copy_files=not getattr(args, "no_copy_files", False),
        replace_existing_config=bool(getattr(args, "replace_config", False)),
        reload=bool(getattr(args, "reload", False)),
        dry_run=not getattr(args, "apply", False),
    )
    workdir = Path(tempfile.mkdtemp(prefix="owbm-migrate-", dir=os.environ.get("TMPDIR") or None))
    try:
        plan = migrate.build_plan(parsed, passport, path, client, options=options)
        reload_sensitive = {"network", "firewall", "dropbear", "wireless"} & set(plan.configs_copy)
        if not options.dry_run and options.reload and reload_sensitive:
            raise fail(
                "OWBM-E-CMP-003",
                reason=(
                    "--reload запрещён при замене network/firewall/dropbear/wireless без удалённого сторожа; "
                    "сначала выполните перенос без --reload и применяйте сеть только при локальном доступе"
                ),
            )
        if getattr(args, "json", False):
            print(json.dumps({"archive": str(path), "plan": plan.as_dict(), "dry_run": options.dry_run},
                             ensure_ascii=False, indent=2))
            if options.dry_run:
                return EXIT_OK
        else:
            device = parsed.device
            rt.logger.raw("")
            rt.logger.raw(f"Источник: {device.get('board_id') or '?'} "
                          f"({device.get('release') or '?'}, {device.get('arch') or '?'})")
            rt.logger.raw(f"Цель:     {passport.identity.board_id or '?'} "
                          f"({passport.identity.release or '?'}, {passport.identity.arch or '?'})")
            rt.logger.raw("")
            for line in plan.describe():
                rt.logger.raw(line)
            if plan.packages_install:
                rt.logger.raw("")
                label = (
                    "Из репозиториев цели"
                    if options.install_packages
                    else "Есть в репозиториях, установка отключена"
                )
                rt.logger.raw(f"{label} ({len(plan.packages_install)}): "
                              + ", ".join(plan.packages_install[:12])
                              + ("…" if len(plan.packages_install) > 12 else ""))
            if plan.packages_archive_install:
                label = (
                    "Из совместимых файлов архива"
                    if options.install_packages
                    else "Совместимы в архиве, установка отключена"
                )
                rt.logger.raw(f"{label} ({len(plan.packages_archive_install)}): "
                              + ", ".join(plan.packages_archive_install[:12])
                              + ("…" if len(plan.packages_archive_install) > 12 else ""))
            if plan.configs_copy:
                rt.logger.raw(f"Будут скопированы конфиги: {', '.join(plan.configs_copy)}")
            if plan.files_copy:
                rt.logger.raw(f"Будет перенесено файлов приложений: {len(plan.files_copy)}")
            if plan.configs_kept:
                rt.logger.raw(f"Останутся конфиги цели: {', '.join(plan.configs_kept)}")
            for item in plan.warnings:
                rt.logger.raw(f"! {item}")
            if options.dry_run:
                rt.logger.raw("")
                rt.logger.raw("Пробный прогон: устройство не изменялось. Для применения добавьте --apply.")
                return EXIT_OK

        if not getattr(args, "yes", False):
            rt.logger.raw("")
            rt.logger.raw("Перенос изменит целевое устройство. Введите слово MIGRATE для продолжения:")
            try:
                answer = input("> ").strip()
            except EOFError:
                answer = ""
            if answer.upper() != "MIGRATE":
                rt.logger.warn("Отменено пользователем. Устройство не изменялось.")
                return EXIT_OK

        snapshot_path = None
        changes_planned = bool(
            plan.configs_copy
            or plan.files_copy
            or (options.install_packages and (plan.packages_install or plan.packages_archive_install))
        )
        if changes_planned:
            rt.logger.step("Снимок целевого устройства до переноса (pre-restore)")
            snapshot = packager.create_backup(
                client,
                passport,
                capabilities.analyze(passport),
                store,
                packager.BackupOptions(
                    mode="pre-restore",
                    include_package_binaries=False,
                    include_user_data=False,
                ),
                rt.logger,
            )
            if not snapshot.ok:
                raise fail("OWBM-E-RST-001", step="pre-restore", reason="не удалось создать снимок цели")
            snapshot_manifest = manifest_mod.validate(snapshot.manifest or {})
            if snapshot_manifest.component("configuration") is None:
                raise fail(
                    "OWBM-E-RST-001",
                    step="pre-restore",
                    reason="снимок цели не содержит конфигурацию; изменения не начаты",
                )
            snapshot_path = snapshot.path
            rt.logger.ok(f"Снимок цели: {snapshot_path}")

        result = migrate.apply_plan(
            client,
            plan,
            parsed,
            path,
            workdir,
            options,
            rt.logger,
            pre_restore_archive=snapshot_path,
        )
        result.messages.insert(0, f"Снимок pre-restore: {snapshot_path}" if snapshot_path else "")
        result.messages[:] = [message for message in result.messages if message]
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    if getattr(args, "json", False):
        print(json.dumps(result.as_dict(), ensure_ascii=False, indent=2))
    else:
        rt.logger.raw("")
        rt.logger.raw(f"Установлено пакетов: {len(result.installed)}")
        rt.logger.raw(f"Скопировано конфигов: {len(result.configs_written)}")
        rt.logger.raw(f"Перенесено файлов приложений: {len(result.files_written)}")
        if result.installed_from_archive:
            rt.logger.raw(f"Установлено из архива: {len(result.installed_from_archive)}")
        if plan.packages_unavailable:
            rt.logger.raw(f"Нет в репозиториях цели и в архиве пакетов ({len(plan.packages_unavailable)}): "
                          + ", ".join(plan.packages_unavailable[:20])
                          + ("…" if len(plan.packages_unavailable) > 20 else ""))
        if plan.packages_archive_incompatible:
            rt.logger.raw(f"Не установлены: файлы пакетов несовместимы с целью ({len(plan.packages_archive_incompatible)}): "
                          + ", ".join(plan.packages_archive_incompatible[:20])
                          + ("…" if len(plan.packages_archive_incompatible) > 20 else ""))
        for item in result.messages:
            rt.logger.raw(f"! {item}")
    return EXIT_OK if result.ok else EXIT_PARTIAL


def cmd_trust(rt: Runtime) -> int:
    """Re-pin a device key after an intentional reinstall, after an interactive check."""
    if getattr(rt.args, "json", False) or not rt.ui.is_interactive():
        message = "Для смены SSH-ключа нужен интерактивный терминал; JSON и автоматический режим не поддерживаются."
        if getattr(rt.args, "json", False):
            print(json.dumps({"error": message}, ensure_ascii=False), file=sys.stderr)
        else:
            rt.logger.error(message)
        return EXIT_USAGE
    target = rt.target()
    client = SSHClient(target, logger=rt.logger, password=rt.password())
    before = client.known_host_fingerprints()
    keys = client.scan_host_keys()
    fingerprints = [(key_type, client.fingerprint(key_line)) for key_type, key_line in keys]
    fingerprint = fingerprints[0][1]
    if getattr(rt.args, "json", False):
        print(
            json.dumps(
                {"host": target.host, "port": target.port, "before": before, "now": fingerprint},
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        rt.logger.raw("")
        rt.logger.raw(f"Устройство: {target.host}:{target.port}")
        if before:
            for item in before:
                rt.logger.raw(f"  сохранённый отпечаток: {item}")
        else:
            rt.logger.raw("  сохранённого отпечатка нет")
        rt.logger.raw("  полученные отпечатки:")
        for key_type, value in fingerprints:
            rt.logger.raw(f"    {key_type}: {value}")
        rt.logger.raw("")
        rt.logger.raw("Сверьте все отпечатки с устройством, прежде чем принимать их.")
    if not getattr(rt.args, "accept_host_key", False):
        rt.logger.raw("")
        rt.logger.raw("Для принятия добавьте --accept-host-key после ручной сверки.")
        return EXIT_USAGE
    if not rt.ui.ask_yes_no("Все отпечатки сверены с доверенным источником и совпадают?", default=False):
        rt.logger.warn("Ключ не изменён.")
        return EXIT_USAGE
    info = client.repin_host_key(keys=keys)
    if not getattr(rt.args, "json", False):
        rt.logger.ok(f"Ключ обновлён: {info['fingerprint']}")
    return EXIT_OK


def cmd_menu(rt: Runtime) -> int:
    from .menu import Menu

    return Menu().run()


def cmd_version(rt: Runtime) -> int:
    if getattr(rt.args, "json", False):
        print(json.dumps({"version": __version__, "format": "owbm", "format_version": 1}))
    else:
        rt.logger.raw(f"owbm {__version__}")
    return EXIT_OK


def cmd_info(rt: Runtime) -> int:
    client = rt.client()
    rt.logger.step(f"Опрос устройства {client.target.describe()} (только чтение)")
    passport = discovery.discover(client, logger=rt.logger)
    profile = capabilities.analyze(passport)
    if getattr(rt.args, "json", False):
        print(
            json.dumps(
                {
                    "target": client.target.describe(),
                    "passport": passport.as_dict(),
                    "capabilities": profile.as_dict(),
                    "summary": capabilities.narrative(passport, profile),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return EXIT_OK
    _print_info(rt, passport, profile)
    return EXIT_OK


def _print_info(rt: Runtime, passport, profile) -> None:
    ident = passport.identity
    storage = passport.storage
    packages = passport.packages
    log = rt.logger
    log.raw("")
    log.raw(f"Устройство:   {ident.hostname}  ({passport.identity.system_type})")
    log.raw(f"Модель:       {ident.board_name or 'не определена'}"
            + (f"  [{ident.model}]" if ident.model and ident.model != ident.board_name else ""))
    log.raw(f"OpenWrt:      {ident.release or 'не определена'}"
            + (f"  ревизия {ident.revision}" if ident.revision else ""))
    log.raw(f"Target:       {ident.target or 'не определён'}")
    log.raw(f"Архитектура:  {ident.arch or 'не определена'}")
    log.raw(f"Ядро:         {ident.kernel_release or 'не определено'}"
            + (f"  (пакет kernel {ident.kernel_package})" if ident.kernel_package else ""))
    log.raw("")
    log.raw(f"Корневая ФС:  {storage.root_fstype or 'не определена'}  ({storage.root_source})")
    if storage.overlay:
        overlay = storage.overlay
        log.raw(f"OverlayFS:    {overlay.mountpoint}, верхний слой {overlay.upperdir}"
                + ("" if overlay.persistent else "  (в памяти!)"))
    else:
        log.raw("OverlayFS:    не обнаружен")
    log.raw(f"extroot:      {'да' if storage.extroot else 'нет'}")
    log.raw(f"Запись:       {storage.writable_path}  "
            + (f"свободно {human_size(storage.free_bytes_writable)}" if storage.free_bytes_writable else ""))
    log.raw(f"Временный:    {storage.tmp_path}  "
            + (f"свободно {human_size(storage.tmp_free_bytes)}" if storage.tmp_free_bytes else ""))
    manager = packages.manager.upper() if packages.manager != "none" else "не обнаружен"
    log.raw(f"Пакеты:       {manager}"
            + (f", {packages.count} установлено" if packages.count else "")
            + (f", {len(packages.repositories)} источников" if packages.repositories else ""))
    if passport.time.utc:
        log.raw(f"Время:        {passport.time.utc} (UTC устройства)")
    log.raw("")
    log.raw("Что можно сохранить и восстановить:")
    for name, support in profile.categories().items():
        log.raw(f"  {name:<20} {support.level:<15} {support.reason}")
    log.raw("")
    log.raw("Итог: " + capabilities.narrative(passport, profile))
    if profile.warnings:
        log.raw("")
        log.raw("Предупреждения:")
        for item in profile.warnings:
            log.raw(f"  • {item}")
    if profile.notes:
        log.raw("")
        for item in profile.notes:
            log.raw(f"  · {item}")


def cmd_doctor(rt: Runtime) -> int:
    checks: List[tuple] = []
    checks.append(("python", True, platform_summary()))
    for tool in ("ssh", "ssh-keygen", "ssh-keyscan", "tar", "gzip"):
        path = which(tool)
        checks.append((tool, bool(path), path or "не найдено"))
    clock = clock_sanity()
    checks.append(("часы", clock is None, clock or "в порядке"))
    if rt.cfg.loaded:
        checks.append(("конфигурация", True, str(rt.cfg.source)))
    else:
        checks.append(("конфигурация", True, f"нет файла, используются значения по умолчанию ({rt.cfg.source})"))
    root = rt.cfg.backup_root()
    try:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        probe = root / ".owbm-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        checks.append(("хранилище", True, f"{root} доступно для записи"))
    except OSError as exc:
        checks.append(("хранилище", False, f"{root}: {exc.strerror or exc}"))

    device_error: Optional[OwbmError] = None
    if getattr(rt.args, "device", None) or getattr(rt.args, "host", None):
        try:
            client = rt.client()
            passport = discovery.discover(client, logger=rt.logger)
            profile = capabilities.analyze(passport)
            checks.append(
                ("устройство", True, f"{client.target.describe()}: {passport.identity.board_name or 'модель?'}"
                 + (f", OpenWrt {passport.identity.release}" if passport.identity.release else ""))
            )
            checks.append(("точное восстановление", profile.exact_restore,
                           "доступно" if profile.exact_restore else "недоступно для этого устройства"))
        except OwbmError as exc:
            device_error = exc
            checks.append(("устройство", False, exc.message))

    if getattr(rt.args, "json", False):
        print(json.dumps({"checks": [{"name": n, "ok": ok, "detail": d} for n, ok, d in checks]},
                         ensure_ascii=False, indent=2))
    else:
        rt.logger.raw("")
        rt.logger.raw("Диагностика:")
        for name, ok, detail in checks:
            rt.logger.raw(f"  {'✓' if ok else '✗'} {name:<22} {detail}")
        if rt.logger.path:
            rt.logger.raw("")
            rt.logger.raw(f"Журнал: {rt.logger.path}")
    failures = [name for name, ok, _ in checks if not ok]
    if device_error is not None:
        return device_error.exit_code
    return EXIT_USAGE if failures and failures != ["хранилище"] else EXIT_OK


def cmd_config_init(rt: Runtime) -> int:
    target = rt.cfg.source or rt.cfg.paths.config_file
    if target.exists() and not getattr(rt.args, "force", False):
        rt.logger.warn(f"Файл уже существует: {target} (используйте --force, чтобы перезаписать)")
        return EXIT_USAGE
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    target.write_text(cfgmod.EXAMPLE, encoding="utf-8")
    os.chmod(target, 0o600)
    rt.logger.ok(f"Создан пример конфигурации: {target}")
    return EXIT_OK


def cmd_config_show(rt: Runtime) -> int:
    data = cfgmod.to_mapping(rt.cfg)
    data["_source"] = str(rt.cfg.source)
    data["_loaded"] = rt.cfg.loaded
    data["_backup_root"] = str(rt.cfg.backup_root())
    data["_known_hosts"] = str(rt.cfg.known_hosts())
    if getattr(rt.args, "json", False):
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        rt.logger.raw(cfgmod.tomlmini.dumps(cfgmod.to_mapping(rt.cfg)))
        rt.logger.raw(f"# файл: {rt.cfg.source} ({'загружен' if rt.cfg.loaded else 'не найден, значения по умолчанию'})")
        rt.logger.raw(f"# хранилище: {rt.cfg.backup_root()}")
        rt.logger.raw(f"# known_hosts: {rt.cfg.known_hosts()}")
    return EXIT_OK


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------
def _add_common(parser: argparse.ArgumentParser, *, suppress: bool = False) -> None:
    """Options accepted both before and after the subcommand."""

    def default(value):
        return argparse.SUPPRESS if suppress else value

    def flag(names, **kwargs):
        if suppress:
            kwargs["default"] = argparse.SUPPRESS
        parser.add_argument(*names, **kwargs)

    flag(("-d", "--device"), default=default(None),
         help="имя профиля из конфигурации или адрес устройства")
    flag(("--host",), default=default(None), help="адрес или имя устройства (переопределяет профиль)")
    flag(("--user",), default=default(None), help="пользователь SSH (по умолчанию root)")
    flag(("--port",), type=int, default=default(None), help="порт SSH")
    flag(("-i", "--identity"), default=default(None), help="приватный ключ SSH")
    flag(("-J", "--jump"), default=default(None), help="SSH jump host (ProxyJump)")
    flag(("--config",), default=default(None), help="путь к файлу конфигурации")
    flag(("--backup-root",), default=default(None), help="каталог хранения резервных копий")
    flag(("--lang",), choices=cfgmod.LANGUAGES, default=default(None), help="язык интерфейса")
    flag(("--accept-host-key",), action="store_true",
         help="разрешить принятие ключа после ручной сверки; trust дополнительно спрашивает подтверждение")
    flag(("--password-stdin",), action="store_true",
         help="прочитать пароль SSH из stdin (не сохраняется на диск)")
    flag(("--json",), action="store_true", help="машиночитаемый вывод")
    flag(("-q", "--quiet"), action="store_true", help="меньше сообщений")
    flag(("-v", "--verbose"), action="store_true", help="подробный журнал")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="owbm",
        description="OWBM — резервное копирование и восстановление OpenWrt по SSH.",
    )
    parser.add_argument("--version", action="version", version=f"owbm {__version__}")
    _add_common(parser)

    common = argparse.ArgumentParser(add_help=False)
    _add_common(common, suppress=True)

    sub = parser.add_subparsers(dest="command", metavar="команда")
    sub.add_parser("info", parents=[common], help="показать паспорт устройства и возможности")
    sub.add_parser("doctor", parents=[common], help="проверить локальные зависимости и доступ к устройству")
    sub.add_parser("version", parents=[common], help="версия программы")
    sub.add_parser("menu", parents=[common], help="интерактивное меню (главный интерфейс)")
    migrate_cmd = sub.add_parser("migrate", parents=[common],
                                 help="перенести систему из архива на другое устройство")
    migrate_cmd.add_argument("archive", nargs="?", help="архив-источник (по умолчанию последний)")
    migrate_cmd.add_argument("--apply", action="store_true", help="выполнить перенос (по умолчанию только план)")
    migrate_cmd.add_argument("--replace-config", action="store_true",
                             help="заменить и совпадающие конфиги цели (полный клон)")
    migrate_cmd.add_argument("--no-install-packages", action="store_true",
                             help="не устанавливать пакеты источника")
    migrate_cmd.add_argument("--no-copy-files", action="store_true",
                             help="не переносить файлы приложений (только пакеты и конфиги)")
    migrate_cmd.add_argument("--reload", action="store_true", help="применить конфигурацию; сетевые файлы требуют локального доступа")
    migrate_cmd.add_argument("--yes", action="store_true", help="не спрашивать подтверждение")

    sub.add_parser("trust", parents=[common], help="заново закрепить ключ устройства после ручной сверки")
    init = sub.add_parser("config-init", parents=[common], help="создать пример файла конфигурации")
    init.add_argument("--force", action="store_true", help="перезаписать существующий файл")
    sub.add_parser("config-show", parents=[common], help="показать действующую конфигурацию")

    backup = sub.add_parser("backup", parents=[common], help="создать резервную копию устройства")
    backup.add_argument("--dry-run", action="store_true", help="показать план и ничего не делать")
    backup.add_argument("--no-rootfs", action="store_true",
                        help="не копировать файлы системы на устройствах без OverlayFS")
    backup.add_argument("--no-package-binaries", action="store_true",
                        help="не сохранять пакеты (только список)")
    backup.add_argument("--user-data", action="append", metavar="PATH",
                        help="дополнительный каталог пользовательских данных (можно несколько)")
    backup.add_argument("--no-user-data", action="store_true", help="не сохранять пользовательские каталоги")
    backup.add_argument("--package-chunk", type=int, default=25, metavar="N",
                        help="сколько пакетов запрашивать за одну сессию (по умолчанию 25)")
    backup.add_argument("--encrypt", choices=("age", "gpg"), help="зашифровать готовый архив")
    backup.add_argument("--label", help="метка устройства в имени файла")

    sub.add_parser("list", parents=[common], help="список резервных копий (новые сверху)")

    check = sub.add_parser("check", parents=[common], help="проверить архив без восстановления")
    check.add_argument("archive", nargs="?", help="путь к файлу .owbm (по умолчанию последний)")

    restore = sub.add_parser("restore", parents=[common], help="план восстановления (по умолчанию без изменений)")
    restore.add_argument("archive", nargs="?", help="путь к файлу .owbm (по умолчанию последний)")
    restore.add_argument("--strategy", choices=("exact", "migration", "selective"),
                         help="стратегия восстановления (по умолчанию exact)")
    restore.add_argument("--only", action="append", choices=manifest_mod.COMPONENT_IDS,
                         help="категория для Selective Restore (можно несколько)")
    restore.add_argument("--reboot", action="store_true", help="включить в план перезагрузку устройства")
    restore.add_argument("--apply", action="store_true", help="выполнить план (по умолчанию только показать)")
    restore.add_argument("--no-install-packages", action="store_true",
                         help="не устанавливать пакеты из архива (только распаковать)")
    restore.add_argument("--yes", action="store_true", help="не спрашивать подтверждение RESTORE")
    restore.add_argument("--watchdog-timeout", type=int, default=180, metavar="СЕК",
                         help="через сколько секунд сторож вернёт сеть (по умолчанию 180)")
    restore.add_argument("--confirm-timeout", type=int, default=60, metavar="СЕК",
                         help="сколько ждать подтверждения связи после применения сети")
    return parser



def _store(rt: Runtime) -> ArchiveStore:
    return ArchiveStore(rt.cfg.backup_root(), logger=rt.logger)


def _resolve_archive(rt: Runtime, store: ArchiveStore, argument) -> Path:
    """An explicitly named archive is never silently replaced by another one.

    Only a missing argument means "take the newest"; an empty value or a path
    that does not exist is an error, because restoring the wrong archive is
    worse than refusing.
    """
    if argument is None:
        latest = store.latest()
        if latest is None:
            raise fail("OWBM-E-ARC-001", path=str(rt.cfg.backup_root()))
        return latest.path
    text = str(argument).strip()
    if not text:
        raise fail(
            "OWBM-E-ARC-001",
            path="<пустой путь>",
        )
    path = Path(text).expanduser()
    if not path.is_file():
        raise fail("OWBM-E-ARC-001", path=str(path))
    return path


def cmd_backup(rt: Runtime) -> int:
    args = rt.args
    client = rt.client()
    rt.logger.step(f"Опрос устройства {client.target.describe()} (только чтение)")
    passport = discovery.discover(client, logger=rt.logger)
    profile = capabilities.analyze(passport)

    user_paths = tuple(getattr(args, "user_data", None) or ())
    options = packager.BackupOptions(
        include_package_binaries=not getattr(args, "no_package_binaries", False),
        include_rootfs=not getattr(args, "no_rootfs", False),
        include_user_data=not getattr(args, "no_user_data", False) and bool(user_paths),
        user_data_paths=user_paths,
        package_chunk=int(getattr(args, "package_chunk", 25) or 25),
        encrypt=getattr(args, "encrypt", None),
        dry_run=bool(getattr(args, "dry_run", False)),
    )
    plan_obj = planner.plan(
        passport,
        profile,
        include_package_binaries=options.include_package_binaries,
        include_user_data=options.include_user_data,
        user_data_paths=options.user_data_paths,
        include_rootfs=options.include_rootfs,
    )

    if not getattr(args, "json", False):
        rt.logger.raw("")
        rt.logger.raw("План резервного копирования:")
        for line in planner.describe(plan_obj):
            rt.logger.raw(line)
        rt.logger.raw("")
        rt.logger.raw(f"Примерный объём: {human_size(plan_obj.estimate_total)} (оценка до сбора)")
        rt.logger.raw(f"Хранилище: {rt.cfg.backup_root()}")
        if profile.warnings:
            rt.logger.raw("")
            for item in profile.warnings:
                rt.logger.raw(f"! {item}")

    store = _store(rt)
    result = packager.create_backup(
        client,
        passport,
        profile,
        store,
        options,
        rt.logger,
        label=getattr(args, "label", None),
    )

    if getattr(args, "json", False):
        payload = {
            "status": result.status,
            "path": str(result.path) if result.path else None,
            "plan": plan_obj.as_dict(),
            "warnings": result.warnings,
            "stages": result.stages,
            "archive": result.manifest,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return EXIT_OK if result.ok else EXIT_USAGE

    if not result.ok:
        rt.logger.raw("")
        rt.logger.raw("Пробный запуск завершён: архив не создавался.")
        return EXIT_OK

    rt.logger.raw("")
    if result.status != manifest_mod.STATUS_COMPLETE:
        rt.logger.warn("Архив создан частично: часть категорий не сохранена (см. отчёт выше).")
    for line in result.report:
        rt.logger.raw(line)
    rt.logger.raw(
        f"Состав: {', '.join(item.id for item in manifest_mod.validate(result.manifest).components)}"
    )
    for item in result.warnings:
        rt.logger.raw(f"! {item}")
    rt.logger.raw("")
    rt.logger.raw("Предыдущие архивы не изменялись и не удалялись.")
    return EXIT_OK


def cmd_list(rt: Runtime) -> int:
    store = _store(rt)
    items = store.list()
    if getattr(rt.args, "json", False):
        print(
            json.dumps(
                [
                    {
                        "name": item.name,
                        "path": str(item.path),
                        "created_utc": item.created_utc,
                        "device": item.device_label,
                        "release": item.release,
                        "arch": item.arch,
                        "size": item.size,
                        "mode": item.mode,
                        "status": item.status,
                        "components": item.components,
                        "valid": item.valid,
                        "error": item.error,
                    }
                    for item in items
                ],
                ensure_ascii=False,
                indent=2,
            )
        )
        return EXIT_OK
    if not items:
        rt.logger.raw(f"Резервных копий нет: {rt.cfg.backup_root()}")
        return EXIT_OK
    rt.logger.raw(f"Хранилище: {rt.cfg.backup_root()}")
    rt.logger.raw("")
    for item in items:
        marker = "✓" if item.valid else "✗"
        when = item.created_utc or "?"
        rt.logger.raw(
            f"{marker} {when}  {item.device_label:<24} {item.release:<12} {item.arch:<12} "
            f"{human_size(item.size):>10}  {item.status:<8} {item.name}"
        )
        if item.error:
            rt.logger.raw(f"    ! {item.error}")
    return EXIT_OK


def cmd_check(rt: Runtime) -> int:
    store = _store(rt)
    path = _resolve_archive(rt, store, getattr(rt.args, "archive", None))
    args = rt.args

    rt.logger.step(f"Проверка архива {path.name}")
    report = archive.verify_archive(path)
    if not report.ok:
        if getattr(args, "json", False):
            print(json.dumps({"ok": False, "issues": [str(i) for i in report.issues]}, ensure_ascii=False, indent=2))
            report.raise_first()
            return EXIT_OK
        report.raise_first()

    parsed = manifest_mod.validate(report.manifest or {})
    if getattr(args, "json", False):
        print(
            json.dumps(
                {
                    "ok": True,
                    "path": str(path),
                    "members": report.members,
                    "checksums": report.checksums_verified,
                    "payload_bytes": report.payload_bytes,
                    "manifest": report.manifest,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return EXIT_OK

    device = parsed.device
    rt.logger.ok(f"Структура и контрольные суммы в порядке ({report.checksums_verified} элементов).")
    rt.logger.raw("")
    rt.logger.raw(f"Устройство:  {device.get('board_id') or '?'} ({device.get('model') or 'модель не указана'})")
    rt.logger.raw(f"OpenWrt:     {device.get('release') or '?'}  target {device.get('target') or '?'}")
    rt.logger.raw(f"Архитектура: {device.get('arch') or '?'}  ядро {device.get('kernel_release') or '?'}")
    rt.logger.raw(f"Создан:      {parsed.created_utc} (UTC)")
    rt.logger.raw(f"Статус:      {parsed.status}")
    rt.logger.raw("")
    rt.logger.raw("Состав:")
    for component in parsed.components:
        rt.logger.raw(
            f"  {component.id:<20} {component.support_level:<15} {human_size(component.size):>10}  {component.path}"
        )
    if parsed.completeness.get("warnings"):
        rt.logger.raw("")
        rt.logger.raw("Предупреждения при создании:")
        for item in parsed.completeness["warnings"]:
            rt.logger.raw(f"  ! {item}")
    return EXIT_OK



def _source_interfaces(path: Path):
    try:
        data = json.loads(archive.read_member(path, "inventory/interfaces.json").decode("utf-8"))
    except Exception:  # noqa: BLE001 - optional inventory member
        return ()
    return tuple(str(item.get("name")) for item in data if isinstance(item, dict) and item.get("name"))


def cmd_restore(rt: Runtime) -> int:
    args = rt.args
    store = _store(rt)
    path = _resolve_archive(rt, store, getattr(args, "archive", None))

    rt.logger.step(f"Проверка архива {path.name}")
    report = archive.verify_archive(path)
    report.raise_first()
    parsed = manifest_mod.validate(report.manifest or {})
    rt.logger.ok(f"Архив цел: элементов {report.members}, контрольных сумм {report.checksums_verified}")

    client = rt.client()
    rt.logger.step(f"Опрос целевого устройства {client.target.describe()} (только чтение)")
    passport = discovery.discover(client, logger=rt.logger)

    strategy = getattr(args, "strategy", None) or compatibility.STRATEGY_EXACT
    selected = tuple(getattr(args, "only", None) or ())
    if strategy == compatibility.STRATEGY_SELECTIVE and not selected:
        raise fail("OWBM-E-CFG-002", key="--strategy selective", reason="нужно указать --only с категориями")
    if selected and strategy != compatibility.STRATEGY_SELECTIVE:
        strategy = compatibility.STRATEGY_SELECTIVE

    compat = compatibility.compare(parsed, passport, strategy=strategy, selected=selected or None)
    plan = restore_planner.build_plan(
        parsed,
        passport,
        compat,
        strategy=strategy,
        archive_path=path,
        selected=selected or None,
        source_interfaces=_source_interfaces(path),
        reboot=bool(getattr(args, "reboot", False)),
    )

    if getattr(args, "json", False):
        print(
            json.dumps(
                {
                    "archive": str(path),
                    "target": client.target.describe(),
                    "dry_run": True,
                    "compatible": compat.level,
                    "plan": plan.as_dict(),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return EXIT_OK if plan.ok else EXIT_INCOMPATIBLE

    device = parsed.device
    rt.logger.raw("")
    rt.logger.raw(f"Архив:      {path.name}")
    rt.logger.raw(f"Источник:   {device.get('board_id') or '?'} ({device.get('release') or '?'}, {device.get('arch') or '?'})")
    rt.logger.raw(f"Цель:       {passport.identity.board_id or '?'} "
                  f"({passport.identity.release or '?'}, {passport.identity.arch or '?'})")
    rt.logger.raw(f"Стратегия:  {strategy}")
    rt.logger.raw(f"Совместимость: {compat.level}")
    rt.logger.raw("")
    for line in compat.describe():
        rt.logger.raw(line)
    rt.logger.raw("")
    for line in plan.describe():
        rt.logger.raw(line)
    rt.logger.raw("")
    rt.logger.raw(f"Объём данных к распаковке: {human_size(plan.size_total)}")

    if plan.adaptations:
        rt.logger.raw("")
        rt.logger.raw("Адаптация под целевое устройство:")
        for item in plan.adaptations:
            auto = "автоматически" if item.automatic else "требует вашего решения"
            rt.logger.raw(f"  [{item.risk}] {item.title} — {auto}")
            rt.logger.raw(f"        {item.detail}")
    if plan.warnings:
        rt.logger.raw("")
        for item in plan.warnings:
            rt.logger.raw(f"! {item}")
    if plan.blockers:
        rt.logger.raw("")
        for item in plan.blockers:
            rt.logger.error(item)
        rt.logger.raw("")
        rt.logger.raw("План невыполним в текущем виде. Устройство не изменялось.")
        return EXIT_INCOMPATIBLE

    if not getattr(args, "apply", False):
        rt.logger.raw("")
        rt.logger.raw("Пробный прогон: это план, устройство не изменялось.")
        rt.logger.raw("Для применения добавьте --apply (потребуется подтверждение).")
        return EXIT_OK

    if not getattr(args, "yes", False):
        rt.logger.raw("")
        rt.logger.raw("Восстановление изменит устройство. Введите слово RESTORE для продолжения:")
        try:
            answer = input("> ").strip()
        except EOFError:
            answer = ""
        if answer != "RESTORE":
            rt.logger.warn("Отменено пользователем. Устройство не изменялось.")
            return EXIT_OK

    workdir = Path(tempfile.mkdtemp(prefix="owbm-restore-", dir=os.environ.get("TMPDIR") or None))
    try:
        ctx = restore_apply.ApplyContext(
            client=client,
            passport=passport,
            parsed=parsed,
            profile_caps=capabilities.analyze(passport),
            archive_path=path,
            workdir=workdir,
            store=store,
            options=restore_apply.ApplyOptions(
                reboot=bool(getattr(args, "reboot", False)),
                watchdog_timeout=int(getattr(args, "watchdog_timeout", 180) or 180),
                confirm_timeout=int(getattr(args, "confirm_timeout", 60) or 60),
                install_packages=not getattr(args, "no_install_packages", False),
            ),
            logger=rt.logger,
            ui=rt.ui,
        )
        result = restore_apply.apply_plan(ctx, plan)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    rt.logger.raw("")
    if result.ok:
        rt.logger.ok("Восстановление выполнено.")
        rt.logger.raw(f"Шагов выполнено: {len(result.done)}")
        rt.logger.raw("Проверьте сеть, DNS, LuCI и работу приложений — успех команды это не заменяет.")
        return EXIT_OK
    rt.logger.error(f"Восстановление не завершено на шаге: {result.failed}")
    for item in result.messages:
        rt.logger.raw(item)
    rt.logger.raw("")
    rt.logger.raw("Готовый архив pre-restore лежит в хранилище: им можно вернуть устройство.")
    return EXIT_PARTIAL


COMMANDS = {
    "menu": cmd_menu,
    "migrate": cmd_migrate,
    "trust": cmd_trust,
    "backup": cmd_backup,
    "restore": cmd_restore,
    "check": cmd_check,
    "list": cmd_list,
    "info": cmd_info,
    "doctor": cmd_doctor,
    "version": cmd_version,
    "config-init": cmd_config_init,
    "config-show": cmd_config_show,
}


def main(argv: Optional[Sequence[str]] = None, *, password: Optional[str] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        if sys.stdin.isatty():
            from .menu import Menu

            return Menu().run()
        parser.print_help()
        return EXIT_USAGE
    rt: Optional[Runtime] = None
    try:
        rt = Runtime(args, password=password)
        return COMMANDS[args.command](rt)
    except OwbmError as exc:
        if rt is not None:
            rt.logger.error(exc.render())
        else:
            print(exc.render(), file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        error = OwbmError("OWBM-E-INT-001")
        if rt is not None:
            rt.logger.error(error.render())
        else:
            print(error.render(), file=sys.stderr)
        return error.exit_code
    except BrokenPipeError:
        # The reader closed the pipe (for example `owbm list | head`).
        # Silence the interpreter's own flush traceback and exit quietly.
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except OSError:
            pass
        return EXIT_OK
    finally:
        if rt is not None:
            rt.close()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
