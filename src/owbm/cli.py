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
from . import i18n
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
        i18n.set_language(self.cfg.general.language)
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
            raise fail("OWBM-E-CFG-003", name=i18n.tr("cli.target.unspecified"))
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
            self.logger.ok(i18n.tr("cli.runtime.host_key_saved", fingerprint=info['fingerprint']))
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
    rt.logger.step(i18n.tr("cli.migrate.scan_target", target=client.target.describe()))
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
                reason=i18n.tr("cli.migrate.reload_refused"),
            )
        if getattr(args, "json", False):
            print(json.dumps({"archive": str(path), "plan": plan.as_dict(), "dry_run": options.dry_run},
                             ensure_ascii=False, indent=2))
            if options.dry_run:
                return EXIT_OK
        else:
            device = parsed.device
            rt.logger.raw("")
            rt.logger.raw(i18n.tr("cli.migrate.source", board=device.get('board_id') or '?',
                                  release=device.get('release') or '?', arch=device.get('arch') or '?'))
            rt.logger.raw(i18n.tr("cli.migrate.target", board=passport.identity.board_id or '?',
                                  release=passport.identity.release or '?', arch=passport.identity.arch or '?'))
            rt.logger.raw("")
            for line in plan.describe():
                rt.logger.raw(line)
            if plan.packages_install:
                rt.logger.raw("")
                label = i18n.tr("cli.migrate.packages.target_enabled" if options.install_packages
                                else "cli.migrate.packages.target_disabled")
                rt.logger.raw(f"{label} ({len(plan.packages_install)}): "
                              + ", ".join(plan.packages_install[:12])
                              + ("…" if len(plan.packages_install) > 12 else ""))
            if plan.packages_archive_install:
                label = i18n.tr("cli.migrate.packages.archive_enabled" if options.install_packages
                                else "cli.migrate.packages.archive_disabled")
                rt.logger.raw(f"{label} ({len(plan.packages_archive_install)}): "
                              + ", ".join(plan.packages_archive_install[:12])
                              + ("…" if len(plan.packages_archive_install) > 12 else ""))
            if plan.configs_copy:
                rt.logger.raw(i18n.tr("cli.migrate.configs_copy", items=', '.join(plan.configs_copy)))
            if plan.files_copy:
                rt.logger.raw(i18n.tr("cli.migrate.files_copy", count=len(plan.files_copy)))
            if plan.configs_kept:
                rt.logger.raw(i18n.tr("cli.migrate.configs_kept", items=', '.join(plan.configs_kept)))
            for item in plan.warnings:
                rt.logger.raw(f"! {item}")
            if options.dry_run:
                rt.logger.raw("")
                rt.logger.raw(i18n.tr("cli.migrate.dry_run"))
                return EXIT_OK

        if not getattr(args, "yes", False):
            rt.logger.raw("")
            rt.logger.raw(i18n.tr("cli.migrate.confirm"))
            try:
                answer = input("> ").strip()
            except EOFError:
                answer = ""
            if answer.upper() != "MIGRATE":
                rt.logger.warn(i18n.tr("cli.operation.cancelled"))
                return EXIT_OK

        snapshot_path = None
        changes_planned = bool(
            plan.configs_copy
            or plan.files_copy
            or (options.install_packages and (plan.packages_install or plan.packages_archive_install))
        )
        if changes_planned:
            rt.logger.step(i18n.tr("cli.migrate.snapshot_step"))
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
                raise fail("OWBM-E-RST-001", step="pre-restore", reason=i18n.tr("cli.migrate.snapshot_failed"))
            snapshot_manifest = manifest_mod.validate(snapshot.manifest or {})
            if snapshot_manifest.component("configuration") is None:
                raise fail(
                    "OWBM-E-RST-001",
                    step="pre-restore",
                    reason=i18n.tr("cli.migrate.snapshot_missing_config"),
                )
            snapshot_path = snapshot.path
            rt.logger.ok(i18n.tr("cli.migrate.snapshot_label", path=snapshot_path))

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
        result.messages.insert(0, i18n.tr("cli.migrate.snapshot_message", path=snapshot_path) if snapshot_path else "")
        result.messages[:] = [message for message in result.messages if message]
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    if getattr(args, "json", False):
        print(json.dumps(result.as_dict(), ensure_ascii=False, indent=2))
    else:
        rt.logger.raw("")
        rt.logger.raw(i18n.tr("cli.migrate.installed", count=len(result.installed)))
        rt.logger.raw(i18n.tr("cli.migrate.configs_written", count=len(result.configs_written)))
        rt.logger.raw(i18n.tr("cli.migrate.files_written", count=len(result.files_written)))
        if result.installed_from_archive:
            rt.logger.raw(i18n.tr("cli.migrate.installed_from_archive", count=len(result.installed_from_archive)))
        if plan.packages_unavailable:
            items = ", ".join(plan.packages_unavailable[:20]) + ("…" if len(plan.packages_unavailable) > 20 else "")
            rt.logger.raw(i18n.tr("cli.migrate.packages_unavailable", count=len(plan.packages_unavailable), items=items))
        if plan.packages_archive_incompatible:
            items = ", ".join(plan.packages_archive_incompatible[:20]) + ("…" if len(plan.packages_archive_incompatible) > 20 else "")
            rt.logger.raw(i18n.tr("cli.migrate.packages_incompatible", count=len(plan.packages_archive_incompatible), items=items))
        for item in result.messages:
            rt.logger.raw(f"! {item}")
    return EXIT_OK if result.ok else EXIT_PARTIAL


def cmd_trust(rt: Runtime) -> int:
    """Re-pin a device key after an intentional reinstall, after an interactive check."""
    if getattr(rt.args, "json", False) or not rt.ui.is_interactive():
        message = i18n.tr("cli.trust.noninteractive")
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
        rt.logger.raw(i18n.tr("cli.trust.device", host=target.host, port=target.port))
        if before:
            for item in before:
                rt.logger.raw(i18n.tr("cli.trust.saved_fingerprint", fingerprint=item))
        else:
            rt.logger.raw(i18n.tr("cli.trust.no_saved_fingerprint"))
        rt.logger.raw(i18n.tr("cli.trust.received_fingerprints"))
        for key_type, value in fingerprints:
            rt.logger.raw(f"    {key_type}: {value}")
        rt.logger.raw("")
        rt.logger.raw(i18n.tr("cli.trust.verify_before_accept"))
    if not getattr(rt.args, "accept_host_key", False):
        rt.logger.raw("")
        rt.logger.raw(i18n.tr("cli.trust.accept_hint"))
        return EXIT_USAGE
    if not rt.ui.ask_yes_no(i18n.tr("cli.trust.confirm"), default=False):
        rt.logger.warn(i18n.tr("cli.trust.unchanged"))
        return EXIT_USAGE
    info = client.repin_host_key(keys=keys)
    if not getattr(rt.args, "json", False):
        rt.logger.ok(i18n.tr("cli.trust.updated", fingerprint=info['fingerprint']))
    return EXIT_OK


def cmd_menu(rt: Runtime) -> int:
    from .menu import Menu

    return Menu().run(language_override=getattr(rt.args, "lang", None))


def cmd_version(rt: Runtime) -> int:
    if getattr(rt.args, "json", False):
        print(json.dumps({"version": __version__, "format": "owbm", "format_version": 1}))
    else:
        rt.logger.raw(f"owbm {__version__}")
    return EXIT_OK


def cmd_info(rt: Runtime) -> int:
    client = rt.client()
    rt.logger.step(i18n.tr("cli.info.scan", target=client.target.describe()))
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
    unknown = i18n.tr("cli.info.none")
    log.raw("")
    log.raw(i18n.tr("cli.info.device", hostname=ident.hostname, system_type=ident.system_type))
    model = ident.board_name or unknown
    detail = f"  [{ident.model}]" if ident.model and ident.model != ident.board_name else ""
    log.raw(i18n.tr("cli.info.model", model=model, detail=detail))
    revision = i18n.tr("cli.info.revision", revision=ident.revision) if ident.revision else ""
    log.raw(i18n.tr("cli.info.release", release=ident.release or unknown, revision=revision))
    log.raw(i18n.tr("cli.info.target", target=ident.target or i18n.tr("cli.info.target_none")))
    log.raw(i18n.tr("cli.info.architecture", arch=ident.arch or unknown))
    kernel_package = i18n.tr("cli.info.kernel_package", package=ident.kernel_package) if ident.kernel_package else ""
    log.raw(i18n.tr("cli.info.kernel", release=ident.kernel_release or i18n.tr("cli.info.kernel_none"),
                    package=kernel_package))
    log.raw("")
    log.raw(i18n.tr("cli.info.rootfs", fstype=storage.root_fstype or unknown, source=storage.root_source))
    if storage.overlay:
        overlay = storage.overlay
        suffix = "" if overlay.persistent else i18n.tr("cli.info.overlay_memory")
        log.raw(i18n.tr("cli.info.overlay", mountpoint=overlay.mountpoint, upperdir=overlay.upperdir, suffix=suffix))
    else:
        log.raw(i18n.tr("cli.info.overlay_missing"))
    log.raw(f"extroot:      {i18n.tr('cli.info.yes' if storage.extroot else 'cli.info.no')}")
    writable_free = i18n.tr("cli.info.free", size=human_size(storage.free_bytes_writable)) if storage.free_bytes_writable else ""
    temp_free = i18n.tr("cli.info.free", size=human_size(storage.tmp_free_bytes)) if storage.tmp_free_bytes else ""
    log.raw(i18n.tr("cli.info.writable", path=storage.writable_path, free=writable_free))
    log.raw(i18n.tr("cli.info.temporary", path=storage.tmp_path, free=temp_free))
    manager = packages.manager.upper() if packages.manager != "none" else i18n.tr("cli.info.package_manager_missing")
    installed = i18n.tr("cli.info.package_count", count=packages.count) if packages.count else ""
    repositories = i18n.tr("cli.info.repositories", count=len(packages.repositories)) if packages.repositories else ""
    details = i18n.tr("cli.info.package_details", installed=installed, repositories=repositories)
    log.raw(i18n.tr("cli.info.packages", manager=manager, details=details))
    if passport.time.utc:
        log.raw(i18n.tr("cli.info.device_time", time=passport.time.utc))
    log.raw("")
    log.raw(i18n.tr("cli.info.save_restore"))
    for name, support in profile.categories().items():
        log.raw(f"  {name:<20} {support.level:<15} {support.reason}")
    log.raw("")
    log.raw(i18n.tr("cli.info.summary", summary=capabilities.narrative(passport, profile)))
    if profile.warnings:
        log.raw("")
        log.raw(i18n.tr("cli.info.warnings"))
        for item in profile.warnings:
            log.raw(f"  • {item}")
    if profile.notes:
        log.raw("")
        for item in profile.notes:
            log.raw(f"  · {item}")


def _doctor_name(name: str) -> str:
    keys = {
        "часы": "cli.doctor.name.clock",
        "конфигурация": "cli.doctor.name.config",
        "хранилище": "cli.doctor.name.storage",
        "устройство": "cli.doctor.name.device",
        "точное восстановление": "cli.doctor.name.exact_restore",
    }
    return i18n.tr(keys[name]) if name in keys else name


def cmd_doctor(rt: Runtime) -> int:
    checks: List[tuple] = []
    checks.append(("python", True, platform_summary()))
    for tool in ("ssh", "ssh-keygen", "ssh-keyscan", "tar", "gzip"):
        path = which(tool)
        checks.append((tool, bool(path), path or i18n.tr("cli.doctor.not_found")))
    clock = clock_sanity()
    checks.append(("часы", clock is None, clock or i18n.tr("cli.doctor.clock_ok")))
    if rt.cfg.loaded:
        checks.append(("конфигурация", True, str(rt.cfg.source)))
    else:
        checks.append(("конфигурация", True,
                       i18n.tr("cli.doctor.config_default", path=rt.cfg.source)))
    root = rt.cfg.backup_root()
    try:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        probe = root / ".owbm-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        checks.append(("хранилище", True, i18n.tr("cli.doctor.storage_writable", path=root)))
    except OSError as exc:
        checks.append(("хранилище", False, f"{root}: {exc.strerror or exc}"))

    device_error: Optional[OwbmError] = None
    if getattr(rt.args, "device", None) or getattr(rt.args, "host", None):
        try:
            client = rt.client()
            passport = discovery.discover(client, logger=rt.logger)
            profile = capabilities.analyze(passport)
            checks.append(
                ("устройство", True, f"{client.target.describe()}: {passport.identity.board_name or i18n.tr('cli.doctor.model_unknown')}"
                 + (f", OpenWrt {passport.identity.release}" if passport.identity.release else ""))
            )
            checks.append(("точное восстановление", profile.exact_restore,
                           i18n.tr("cli.doctor.available" if profile.exact_restore
                                   else "cli.doctor.unavailable")))
        except OwbmError as exc:
            device_error = exc
            checks.append(("устройство", False, exc.message))

    if getattr(rt.args, "json", False):
        print(json.dumps({"checks": [{"name": _doctor_name(n), "ok": ok, "detail": d} for n, ok, d in checks]},
                         ensure_ascii=False, indent=2))
    else:
        rt.logger.raw("")
        rt.logger.raw(i18n.tr("cli.doctor.title"))
        for name, ok, detail in checks:
            rt.logger.raw(f"  {'✓' if ok else '✗'} {_doctor_name(name):<22} {detail}")
        if rt.logger.path:
            rt.logger.raw("")
            rt.logger.raw(i18n.tr("cli.diagnostics.log", path=rt.logger.path))
    failures = [name for name, ok, _ in checks if not ok]
    if device_error is not None:
        return device_error.exit_code
    return EXIT_USAGE if failures and failures != ["хранилище"] else EXIT_OK


def cmd_config_init(rt: Runtime) -> int:
    target = rt.cfg.source or rt.cfg.paths.config_file
    if target.exists() and not getattr(rt.args, "force", False):
        rt.logger.warn(i18n.tr("cli.config.already_exists", path=target))
        return EXIT_USAGE
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    target.write_text(cfgmod.example_text(), encoding="utf-8")
    os.chmod(target, 0o600)
    rt.logger.ok(i18n.tr("cli.config.created", path=target))
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
        source_status = i18n.tr("cli.config.loaded" if rt.cfg.loaded else "cli.config.not_loaded")
        rt.logger.raw(i18n.tr("cli.config.source", path=rt.cfg.source, status=source_status))
        rt.logger.raw(i18n.tr("cli.config.backup_root", path=rt.cfg.backup_root()))
        rt.logger.raw(i18n.tr("cli.config.known_hosts", path=rt.cfg.known_hosts()))
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

    flag(("-d", "--device"), default=default(None), help=i18n.tr("cli.help.common.device"))
    flag(("--host",), default=default(None), help=i18n.tr("cli.help.common.host"))
    flag(("--user",), default=default(None), help=i18n.tr("cli.help.common.user"))
    flag(("--port",), type=int, default=default(None), help=i18n.tr("cli.help.common.port"))
    flag(("-i", "--identity"), default=default(None), help=i18n.tr("cli.help.common.identity"))
    flag(("-J", "--jump"), default=default(None), help=i18n.tr("cli.help.common.jump"))
    flag(("--config",), default=default(None), help=i18n.tr("cli.help.common.config"))
    flag(("--backup-root",), default=default(None), help=i18n.tr("cli.help.common.backup_root"))
    flag(("--lang",), choices=cfgmod.LANGUAGES, default=default(None), help=i18n.tr("cli.help.common.lang"))
    flag(("--accept-host-key",), action="store_true",
         help=i18n.tr("cli.help.common.accept_host_key"))
    flag(("--password-stdin",), action="store_true",
         help=i18n.tr("cli.help.common.password_stdin"))
    flag(("--json",), action="store_true", help=i18n.tr("cli.help.common.json"))
    flag(("-q", "--quiet"), action="store_true", help=i18n.tr("cli.help.common.quiet"))
    flag(("-v", "--verbose"), action="store_true", help=i18n.tr("cli.help.common.verbose"))


class LocalizedArgumentParser(argparse.ArgumentParser):
    def _translate_boilerplate(self, text: str) -> str:
        replacements = (
            ("usage:", i18n.tr("cli.argparse.usage") + ":"),
            ("positional arguments:", i18n.tr("cli.argparse.positional") + ":"),
            ("optional arguments:", i18n.tr("cli.argparse.optional") + ":"),
            ("options:", i18n.tr("cli.argparse.options") + ":"),
            ("show this help message and exit", i18n.tr("cli.argparse.help")),
        )
        for source, target in replacements:
            text = text.replace(source, target, 1)
        return text

    def format_usage(self) -> str:
        return self._translate_boilerplate(super().format_usage())

    def format_help(self) -> str:
        return self._translate_boilerplate(super().format_help())

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        message = message.replace("invalid int value", i18n.tr("cli.argparse.invalid_integer"), 1)
        message = message.replace("invalid choice", i18n.tr("cli.argparse.invalid_choice"), 1)
        marker = "(choose from "
        index = message.rfind(marker)
        if index >= 0:
            localized = "(" + i18n.tr("cli.argparse.choose_from") + " "
            message = message[:index] + localized + message[index + len(marker):]
        message = message.replace(
            "unrecognized arguments:", i18n.tr("cli.argparse.unrecognized") + ":", 1
        )
        message = message.replace("expected one argument", i18n.tr("cli.argparse.expected_one"), 1)
        self.exit(2, f"{self.prog}: {i18n.tr('cli.argparse.error')}: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = LocalizedArgumentParser(
        prog="owbm",
        description=i18n.tr("cli.description"),
    )
    parser.add_argument("--version", action="version", version=f"owbm {__version__}")
    _add_common(parser)

    common = argparse.ArgumentParser(add_help=False)
    _add_common(common, suppress=True)

    sub = parser.add_subparsers(dest="command", metavar=i18n.tr("cli.metavar.command"))
    sub.add_parser("info", parents=[common], help=i18n.tr("cli.help.info"))
    sub.add_parser("doctor", parents=[common], help=i18n.tr("cli.help.doctor"))
    sub.add_parser("version", parents=[common], help=i18n.tr("cli.help.version"))
    sub.add_parser("menu", parents=[common], help=i18n.tr("cli.help.menu"))
    migrate_cmd = sub.add_parser("migrate", parents=[common], help=i18n.tr("cli.help.migrate"))
    migrate_cmd.add_argument("archive", nargs="?", help=i18n.tr("cli.help.migrate.archive"))
    migrate_cmd.add_argument("--apply", action="store_true", help=i18n.tr("cli.help.migrate.apply"))
    migrate_cmd.add_argument("--replace-config", action="store_true",
                             help=i18n.tr("cli.help.migrate.replace_config"))
    migrate_cmd.add_argument("--no-install-packages", action="store_true",
                             help=i18n.tr("cli.help.migrate.no_install_packages"))
    migrate_cmd.add_argument("--no-copy-files", action="store_true",
                             help=i18n.tr("cli.help.migrate.no_copy_files"))
    migrate_cmd.add_argument("--reload", action="store_true", help=i18n.tr("cli.help.migrate.reload"))
    migrate_cmd.add_argument("--yes", action="store_true", help=i18n.tr("cli.help.no_confirmation"))

    sub.add_parser("trust", parents=[common], help=i18n.tr("cli.help.trust"))
    init = sub.add_parser("config-init", parents=[common], help=i18n.tr("cli.help.config_init"))
    init.add_argument("--force", action="store_true", help=i18n.tr("cli.help.force"))
    sub.add_parser("config-show", parents=[common], help=i18n.tr("cli.help.config_show"))

    backup = sub.add_parser("backup", parents=[common], help=i18n.tr("cli.help.backup"))
    backup.add_argument("--dry-run", action="store_true", help=i18n.tr("cli.help.dry_run"))
    backup.add_argument("--no-rootfs", action="store_true", help=i18n.tr("cli.help.no_rootfs"))
    backup.add_argument("--no-package-binaries", action="store_true",
                         help=i18n.tr("cli.help.no_package_binaries"))
    backup.add_argument("--user-data", action="append", metavar="PATH", help=i18n.tr("cli.help.user_data"))
    backup.add_argument("--no-user-data", action="store_true", help=i18n.tr("cli.help.no_user_data"))
    backup.add_argument("--package-chunk", type=int, default=25, metavar="N",
                        help=i18n.tr("cli.help.package_chunk"))
    backup.add_argument("--encrypt", choices=("age", "gpg"), help=i18n.tr("cli.help.encrypt"))
    backup.add_argument("--label", help=i18n.tr("cli.help.label"))

    sub.add_parser("list", parents=[common], help=i18n.tr("cli.help.list"))

    check = sub.add_parser("check", parents=[common], help=i18n.tr("cli.help.check"))
    check.add_argument("archive", nargs="?", help=i18n.tr("cli.help.archive_path"))

    restore = sub.add_parser("restore", parents=[common], help=i18n.tr("cli.help.restore"))
    restore.add_argument("archive", nargs="?", help=i18n.tr("cli.help.archive_path"))
    restore.add_argument("--strategy", choices=("exact", "migration", "selective"),
                         help=i18n.tr("cli.help.restore.strategy"))
    restore.add_argument("--only", action="append", choices=manifest_mod.COMPONENT_IDS,
                         help=i18n.tr("cli.help.restore.only"))
    restore.add_argument("--reboot", action="store_true", help=i18n.tr("cli.help.restore.reboot"))
    restore.add_argument("--apply", action="store_true", help=i18n.tr("cli.help.restore.apply"))
    restore.add_argument("--no-install-packages", action="store_true",
                         help=i18n.tr("cli.help.restore.no_install_packages"))
    restore.add_argument("--yes", action="store_true", help=i18n.tr("cli.help.restore.yes"))
    restore.add_argument("--watchdog-timeout", type=int, default=180, metavar="SEC",
                         help=i18n.tr("cli.help.restore.watchdog_timeout"))
    restore.add_argument("--confirm-timeout", type=int, default=60, metavar="SEC",
                         help=i18n.tr("cli.help.restore.confirm_timeout"))
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
            path=i18n.tr("cli.archive.empty_path"),
        )
    path = Path(text).expanduser()
    if not path.is_file():
        raise fail("OWBM-E-ARC-001", path=str(path))
    return path


def cmd_backup(rt: Runtime) -> int:
    args = rt.args
    client = rt.client()
    rt.logger.step(i18n.tr("cli.info.scan", target=client.target.describe()))
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
        rt.logger.raw(i18n.tr("cli.backup.plan"))
        for line in planner.describe(plan_obj):
            rt.logger.raw(line)
        rt.logger.raw("")
        rt.logger.raw(i18n.tr("cli.backup.estimate", size=human_size(plan_obj.estimate_total)))
        rt.logger.raw(i18n.tr("cli.storage.root", path=rt.cfg.backup_root()))
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
        rt.logger.raw(i18n.tr("cli.backup.dry_run"))
        return EXIT_OK

    rt.logger.raw("")
    if result.status != manifest_mod.STATUS_COMPLETE:
        rt.logger.warn(i18n.tr("cli.backup.partial"))
    for line in result.report:
        rt.logger.raw(line)
    rt.logger.raw(i18n.tr(
        "cli.backup.contents",
        components=', '.join(item.id for item in manifest_mod.validate(result.manifest).components),
    ))
    for item in result.warnings:
        rt.logger.raw(f"! {item}")
    rt.logger.raw("")
    rt.logger.raw(i18n.tr("cli.backup.previous_unchanged"))
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
        rt.logger.raw(i18n.tr("cli.archive.none", path=rt.cfg.backup_root()))
        return EXIT_OK
    rt.logger.raw(i18n.tr("cli.storage.root", path=rt.cfg.backup_root()))
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

    rt.logger.step(i18n.tr("cli.check.archive", name=path.name))
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
    rt.logger.ok(i18n.tr("cli.check.ok", count=report.checksums_verified))
    rt.logger.raw("")
    rt.logger.raw(i18n.tr("cli.check.device", board=device.get('board_id') or '?',
                          model=device.get('model') or i18n.tr("cli.check.model_missing")))
    rt.logger.raw(i18n.tr("cli.check.openwrt", release=device.get('release') or '?', target=device.get('target') or '?'))
    rt.logger.raw(i18n.tr("cli.check.arch", arch=device.get('arch') or '?', kernel=device.get('kernel_release') or '?'))
    rt.logger.raw(i18n.tr("cli.check.created", time=parsed.created_utc))
    rt.logger.raw(i18n.tr("cli.check.status", status=parsed.status))
    rt.logger.raw("")
    rt.logger.raw(i18n.tr("cli.check.contents"))
    for component in parsed.components:
        rt.logger.raw(
            f"  {component.id:<20} {component.support_level:<15} {human_size(component.size):>10}  {component.path}"
        )
    if parsed.completeness.get("warnings"):
        rt.logger.raw("")
        rt.logger.raw(i18n.tr("cli.check.creation_warnings"))
        for item in parsed.completeness["warnings"]:
            rt.logger.raw(f"  ! {i18n.localize_text(str(item))}")
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

    rt.logger.step(i18n.tr("cli.check.archive", name=path.name))
    report = archive.verify_archive(path)
    report.raise_first()
    parsed = manifest_mod.validate(report.manifest or {})
    rt.logger.ok(i18n.tr("cli.restore.archive_valid", members=report.members, checksums=report.checksums_verified))

    client = rt.client()
    rt.logger.step(i18n.tr("cli.migrate.scan_target", target=client.target.describe()))
    passport = discovery.discover(client, logger=rt.logger)

    strategy = getattr(args, "strategy", None) or compatibility.STRATEGY_EXACT
    selected = tuple(getattr(args, "only", None) or ())
    if strategy == compatibility.STRATEGY_SELECTIVE and not selected:
        raise fail("OWBM-E-CFG-002", key="--strategy selective", reason=i18n.tr("cli.restore.no_only"))
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
    rt.logger.raw(i18n.tr("cli.restore.archive", name=path.name))
    rt.logger.raw(i18n.tr("cli.restore.source", board=device.get('board_id') or '?',
                          release=device.get('release') or '?', arch=device.get('arch') or '?'))
    rt.logger.raw(i18n.tr("cli.restore.target", board=passport.identity.board_id or '?',
                          release=passport.identity.release or '?', arch=passport.identity.arch or '?'))
    rt.logger.raw(i18n.tr("cli.restore.strategy", strategy=strategy))
    rt.logger.raw(i18n.tr("cli.restore.compatibility", level=compat.level))
    rt.logger.raw("")
    for line in compat.describe():
        rt.logger.raw(line)
    rt.logger.raw("")
    for line in plan.describe():
        rt.logger.raw(line)
    rt.logger.raw("")
    rt.logger.raw(i18n.tr("cli.restore.data_size", size=human_size(plan.size_total)))

    if plan.adaptations:
        rt.logger.raw("")
        rt.logger.raw(i18n.tr("cli.restore.adaptation"))
        for item in plan.adaptations:
            auto = i18n.tr("cli.restore.automatic" if item.automatic else "cli.restore.requires_choice")
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
        rt.logger.raw(i18n.tr("cli.restore.blocked"))
        return EXIT_INCOMPATIBLE

    if not getattr(args, "apply", False):
        rt.logger.raw("")
        rt.logger.raw(i18n.tr("cli.restore.dry_run"))
        rt.logger.raw(i18n.tr("cli.restore.apply_hint"))
        return EXIT_OK

    if not getattr(args, "yes", False):
        rt.logger.raw("")
        rt.logger.raw(i18n.tr("cli.restore.confirm"))
        try:
            answer = input("> ").strip()
        except EOFError:
            answer = ""
        if answer != "RESTORE":
            rt.logger.warn(i18n.tr("cli.operation.cancelled"))
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
        rt.logger.ok(i18n.tr("cli.restore.completed"))
        rt.logger.raw(i18n.tr("cli.restore.steps_done", count=len(result.done)))
        rt.logger.raw(i18n.tr("cli.restore.postcheck"))
        return EXIT_OK
    rt.logger.error(i18n.tr("cli.restore.incomplete", step=result.failed))
    for item in result.messages:
        rt.logger.raw(item)
    rt.logger.raw("")
    rt.logger.raw(i18n.tr("cli.restore.pre_restore_hint"))
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


def _detect_language(argv: Sequence[str]) -> str:
    """Resolve the locale before argparse can print help or usage errors."""
    explicit_language: Optional[str] = None
    config_path: Optional[Path] = None
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument.startswith("--lang="):
            explicit_language = argument.partition("=")[2]
        elif argument == "--lang" and index + 1 < len(argv):
            index += 1
            explicit_language = argv[index]
        elif argument.startswith("--config="):
            config_path = Path(argument.partition("=")[2]).expanduser()
        elif argument == "--config" and index + 1 < len(argv):
            index += 1
            config_path = Path(argv[index]).expanduser()
        index += 1
    if explicit_language in cfgmod.LANGUAGES:
        return explicit_language
    try:
        return cfgmod.load(config_path).general.language
    except OwbmError:
        return "ru"


def main(argv: Optional[Sequence[str]] = None, *, password: Optional[str] = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    language_token = i18n.set_language(_detect_language(arguments))
    rt: Optional[Runtime] = None
    try:
        parser = build_parser()
        args = parser.parse_args(arguments)
        if getattr(args, "lang", None):
            i18n.set_language(args.lang)
        if not args.command:
            if sys.stdin.isatty():
                from .menu import Menu

                return Menu().run(language_override=getattr(args, "lang", None))
            parser.print_help()
            return EXIT_USAGE
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
        i18n.reset_language(language_token)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
