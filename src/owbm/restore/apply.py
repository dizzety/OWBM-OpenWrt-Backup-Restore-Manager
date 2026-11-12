"""Apply: execute a restore plan step by step, with a working rollback path.

Invariants enforced here:

* the pre-restore snapshot is the first action; without it nothing is applied;
* the network rollback material is staged and the watchdog is armed *before* the
  first component is written;
* a failure after arming leaves the watchdog armed on purpose — the device then
  returns itself to the previous network instead of staying half-broken;
* success is confirmed by actually connecting, and only then is the watchdog
  disarmed. If the device no longer answers on the known address, the guard
  stays and does its job;
* every step is journaled, so a partial result is described, never guessed.
"""

from __future__ import annotations

import shlex
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .. import archive
from ..backup import collector, packager
from ..discovery import DevicePassport
from ..errors import OwbmError, fail
from ..manifest import Manifest
from ..remote import send_file
from ..storage import ArchiveStore
from ..util import human_size
from . import rollback
from .planner import RestorePlan

STATUS_APPLIED = "applied"
STATUS_FAILED = "failed"
STATUS_ABORTED = "aborted"
STATUS_PARTIAL = "partial"


@dataclass
class ApplyOptions:
    reboot: bool = False
    watchdog_timeout: int = 180
    confirm_timeout: int = 60
    install_packages: bool = True


@dataclass
class ApplyResult:
    status: str = STATUS_APPLIED
    done: List[Dict[str, str]] = field(default_factory=list)
    failed: Optional[str] = None
    armed: bool = False
    messages: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status == STATUS_APPLIED

    def as_dict(self) -> Dict[str, object]:
        return {
            "status": self.status,
            "done": list(self.done),
            "failed": self.failed,
            "armed": self.armed,
            "messages": list(self.messages),
        }


@dataclass
class ApplyContext:
    client: object
    passport: DevicePassport
    parsed: Manifest
    profile_caps: object
    archive_path: Path
    workdir: Path
    store: ArchiveStore
    options: ApplyOptions
    logger: object
    root: str = ""
    ui: Optional[object] = None

    def dest(self) -> str:
        return (self.root or "") + "/"


def apply_plan(ctx: ApplyContext, plan: RestorePlan) -> ApplyResult:
    result = ApplyResult()
    journal = ctx.logger.journal
    state: Dict[str, object] = {"armed": False}

    if plan.blockers:
        result.status = STATUS_ABORTED
        result.messages.extend(plan.blockers)
        return result

    for step in plan.steps:
        ctx.logger.step(step.title)
        journal.start(step.id)
        if state.get("armed"):
            rollback.heartbeat(ctx.client, root=ctx.root, timeout=ctx.options.watchdog_timeout)
        try:
            _dispatch(ctx, plan, step.id, step, state)
        except OwbmError as exc:
            if _recover_host_key(ctx, step.id, state, exc):
                ctx.logger.warn(f"Шаг «{step.title}» повторяется после обновления ключа устройства.")
                journal.ok(f"{step.id}-key-rotated")
                _dispatch(ctx, plan, step.id, step, state)
                journal.ok(step.id)
                result.done.append({"step": step.id, "title": step.title})
                continue
            journal.fail(step.id, exc.message)
            result.status = STATUS_FAILED
            result.failed = step.id
            result.armed = bool(state.get("armed"))
            result.messages.append(exc.render())
            if _rollback_configuration(ctx, state, journal):
                result.messages.append(
                    "Конфигурация устройства возвращена к снимку pre-restore: "
                    "сетевые настройки, firewall и dropbear — прежние."
                )
            if result.armed:
                result.messages.append(
                    "Сторожевой процесс оставлен включённым: если устройство не вернётся "
                    "к прежней сети само, он восстановит её и перезагрузит устройство."
                )
            return result
        except (BrokenPipeError, ConnectionError, OSError) as exc:
            journal.fail(step.id, f"соединение прервано: {exc}")
            result.status = STATUS_FAILED
            result.failed = step.id
            result.armed = bool(state.get("armed"))
            result.messages.append(
                fail(
                    "OWBM-E-RST-001",
                    step=step.id,
                    reason="соединение с устройством прервано во время передачи данных",
                ).render()
            )
            if _rollback_configuration(ctx, state, journal):
                result.messages.append(
                    "Конфигурация устройства возвращена к снимку pre-restore."
                )
            if result.armed:
                result.messages.append(
                    "Сторожевой процесс оставлен включённым: если связь не подтвердится, "
                    "устройство вернётся к прежней сети и перезагрузится."
                )
            return result
        except Exception as exc:  # noqa: BLE001 - report, never pretend
            journal.fail(step.id, str(exc))
            result.status = STATUS_FAILED
            result.failed = step.id
            result.armed = bool(state.get("armed"))
            result.messages.append(f"{step.title}: {exc}")
            return result
        journal.ok(step.id)
        result.done.append({"step": step.id, "title": step.title})
    result.armed = bool(state.get("armed"))
    install = state.get("package_install")
    if install and not install[0]:
        result.status = STATUS_PARTIAL
        result.messages.append(
            f"Пакеты не установлены полностью: {install[1]}. Файлы лежат в {PACKAGE_STAGE_DIR}."
        )
    return result


def _rollback_configuration(ctx: ApplyContext, state: Dict[str, object], journal) -> bool:
    """Undo a half-applied configuration restore.

    A failure after the configuration step is the dangerous case: the target may
    already carry another device's network setup. The pre-restore snapshot taken
    in step 5 is the way back, and it is applied here automatically.
    """
    if not state.get("configuration_applied"):
        return False
    snapshot = state.get("pre_restore_path")
    if not snapshot:
        return False
    try:
        payload = archive.extract_member(Path(snapshot), "payload/configuration.tar.gz", ctx.workdir)
        collector.inspect_tar(payload)
        send_file(ctx.client, "tar -xzpf - -C " + shlex.quote(ctx.dest()), payload)
        journal.ok("rollback-configuration", str(snapshot))
    except Exception as exc:  # noqa: BLE001 - rollback is best effort, never hides the failure
        journal.fail("rollback-configuration", str(exc))
        ctx.logger.warn(f"Не удалось вернуть конфигурацию автоматически: {exc}")
        return False
    state["configuration_applied"] = False
    ctx.logger.warn("Конфигурация возвращена к снимку pre-restore.")
    return True


def _recover_host_key(ctx: ApplyContext, step_id: str, state: Dict[str, object], exc: OwbmError) -> bool:
    """Re-pin a rotated key only after an out-of-band fingerprint check."""
    if exc.code != "OWBM-E-SSH-003":
        return False
    if not state.get("configuration_applied") and step_id not in ("apply-configuration",):
        return False
    ui = ctx.ui
    if (
        ui is None
        or getattr(ctx.logger, "json_mode", False)
        or not getattr(ui, "is_interactive", lambda: False)()
    ):
        return False

    client = ctx.client
    try:
        keys = client.scan_host_keys()
    except OwbmError:
        return False
    if not keys:
        return False

    fingerprints = [(key_type, client.fingerprint(key_line)) for key_type, key_line in keys]
    if any(not fingerprint.startswith("SHA256:") for _key_type, fingerprint in fingerprints):
        return False
    before = client.known_host_fingerprints()
    ui.say("")
    ui.say(f"SSH-ключ {client.target.host}:{client.target.port} изменился во время восстановления.")
    if before:
        ui.say("Сохранённые отпечатки: " + ", ".join(before))
    ui.say("Новые отпечатки:")
    for key_type, fingerprint in fingerprints:
        ui.say(f"  {key_type}: {fingerprint}")
    ui.say("Сверьте все отпечатки с консолью устройства или другим доверенным источником.")
    if not ui.ask_yes_no("Все отпечатки проверены и совпадают?", default=False):
        return False

    try:
        info = client.repin_host_key(keys=keys)
    except OwbmError:
        return False
    ctx.logger.warn(
        "Новый SSH-ключ принят после явной ручной сверки отпечатка "
        f"{info['fingerprint']}; подключение будет повторено."
    )
    return True


def _dispatch(ctx: ApplyContext, plan: RestorePlan, step_id: str, step, state: Dict[str, object]) -> None:
    if step.component:
        applied = {item.component for item in plan.steps if item.component}
        _apply_component(ctx, step.component, applied, state)
        if step.component == "configuration":
            state["configuration_applied"] = True
        return
    handler = _HANDLERS.get(step_id)
    if handler is None:
        raise fail("OWBM-E-RST-001", step=step_id, reason="шаг не реализован")
    handler(ctx, plan, state)


def _pre_restore(ctx: ApplyContext, plan: RestorePlan, state: Dict[str, object]) -> None:
    ctx.logger.info("Создаётся резервная копия целевого устройства…")
    result = packager.create_backup(
        ctx.client,
        ctx.passport,
        ctx.profile_caps,
        ctx.store,
        packager.BackupOptions(mode="pre-restore", include_package_binaries=False),
        ctx.logger,
    )
    if not result.ok:
        raise fail("OWBM-E-RST-001", step="pre-restore", reason="снимок целевого устройства не создан")
    state["pre_restore_path"] = result.path
    ctx.logger.ok(f"Снимок цели: {result.path}")


def _stage(ctx: ApplyContext, plan: RestorePlan, state: Dict[str, object]) -> None:
    rollback.stage(ctx.client, root=ctx.root)


def _arm(ctx: ApplyContext, plan: RestorePlan, state: Dict[str, object]) -> None:
    rollback.arm(ctx.client, root=ctx.root, timeout=ctx.options.watchdog_timeout)
    state["armed"] = True
    ctx.logger.info(
        f"Сторож включён: если связь не подтвердится за {ctx.options.watchdog_timeout} с, "
        "устройство вернётся к прежним сетевым настройкам."
    )


PACKAGE_STAGE_DIR = "/tmp/owbm-packages"
PACKAGE_LOG = "/tmp/owbm-install.log"

INSTALL_APK = (
    'cd "$D" || exit 7; '
    'set -- *.apk; [ -e "$1" ] || { echo "NOFILES=1"; exit 0; }; '
    'apk add --allow-untrusted --force-non-repository --force-reinstall "$@" '
    f'> {PACKAGE_LOG} 2>&1'
)
INSTALL_OPKG = (
    'cd "$D" || exit 7; '
    'set -- *.ipk; [ -e "$1" ] || { echo "NOFILES=1"; exit 0; }; '
    'opkg install --force-reinstall "$@" '
    f'> {PACKAGE_LOG} 2>&1'
)


def _install_packages(ctx: ApplyContext, stage: str, manager: str) -> Tuple[bool, str]:
    """Install the archived packages on the target, without the network."""
    command = INSTALL_APK if manager == "apk" else INSTALL_OPKG
    script = (
        'set -u\nPATH="/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"\n'
        f"D={shlex.quote(stage)}\n"
        f"if {command}; then echo 'INSTALL=ok'; else echo 'INSTALL=fail'; tail -4 {PACKAGE_LOG} 2>/dev/null; fi\n"
    )
    result = ctx.client.run(script, timeout=900, allow_failure=True)
    output = result.out
    if "NOFILES=1" in output:
        return True, "в архиве нет файлов пакетов"
    if "INSTALL=ok" in output:
        return True, ""
    detail = " ".join(line for line in output.splitlines() if line.strip() and "INSTALL=" not in line)[-300:]
    return False, detail or "установщик пакетов завершился с ошибкой"


def _apply_component(ctx: ApplyContext, component_id: str, applied=None, state=None) -> None:
    component = ctx.parsed.component(component_id)
    if component is None:
        raise fail("OWBM-E-CHK-002", reason=f"в архиве нет компонента {component_id}")
    applied = applied or set()

    if component_id == "packages_binaries":
        _apply_packages(ctx, component, applied, state if state is not None else {})
        return

    payload = archive.extract_member(ctx.archive_path, component.path, ctx.workdir)
    members, _size = collector.inspect_tar(payload)
    ctx.logger.debug(f"{component_id}: {members} элементов, {human_size(payload.stat().st_size)}")

    command = "tar -xzpf - -C " + shlex.quote(ctx.dest())
    send_file(ctx.client, command, payload)

    if component_id == "overlay_upper":
        _replay_whiteouts(ctx)


def _apply_packages(ctx: ApplyContext, component, applied, state) -> None:
    """Package archives never go into the root filesystem.

    If the system files were restored, the packages are already in place; the
    archives are only a fallback for devices restored without a filesystem copy.
    """
    if applied & {"rootfs", "overlay_upper"}:
        ctx.logger.info(
            "Файлы пакетов уже восстановлены вместе с системой — отдельная распаковка не нужна."
        )
        return
    payload = archive.extract_member(ctx.archive_path, component.path, ctx.workdir)
    members, _size = collector.inspect_tar(payload)
    stage = f"{ctx.root}{PACKAGE_STAGE_DIR}"
    ctx.client.run(
        'set -u\nPATH="/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"\n'
        f"rm -rf {shlex.quote(stage)} && mkdir -p {shlex.quote(stage)}\n"
        "printf 'STAGE=1\\n'\n",
        timeout=60,
        allow_failure=False,
    )
    send_file(ctx.client, "tar -xzpf - -C " + shlex.quote(stage), payload)
    ctx.logger.info(f"Архивы пакетов распакованы на устройство ({members} файлов).")

    if not ctx.options.install_packages:
        ctx.logger.info("Установка отключена (--no-install-packages): файлы лежат в " + PACKAGE_STAGE_DIR + ".")
        return

    manager = ctx.passport.packages.manager
    if manager not in ("apk", "opkg"):
        ctx.logger.warn("Пакетный менеджер неизвестен: установка невозможна, файлы распакованы.")
        return
    ctx.logger.info(f"Установка пакетов из архива ({manager}, без сети)…")
    ok, detail = _install_packages(ctx, stage, manager)
    state["package_install"] = (ok, detail, members)
    if ok:
        ctx.logger.ok(f"Пакеты установлены из архива: {members} файлов.")
        _cleanup_package_stage(ctx, stage)
    else:
        ctx.logger.warn(f"Установка пакетов не удалась: {detail}")
        ctx.logger.info(f"Файлы пакетов оставлены на устройстве: {stage}")


def _cleanup_package_stage(ctx: ApplyContext, stage: str) -> None:
    """A finished operation leaves no working files on the device."""
    script = (
        'set -u\nPATH="/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"\n'
        f"rm -rf {shlex.quote(stage)} {PACKAGE_LOG} 2>/dev/null || true\n"
        "echo 'PACKAGES-CLEANED=1'\n"
    )
    try:
        ctx.client.run(script, timeout=60, allow_failure=True)
    except Exception:  # noqa: BLE001 - cleanup must not fail the restore
        pass


def _replay_whiteouts(ctx: ApplyContext) -> None:
    try:
        raw = archive.read_member(ctx.archive_path, "inventory/overlay-whiteouts.txt")
    except OwbmError:
        return
    paths = [line.strip() for line in raw.decode("utf-8", "replace").splitlines() if line.strip()]
    if not paths:
        return
    body = rollback.replay_whiteouts_script(paths, root=ctx.root)
    from ..remote import run_probe

    head = run_probe(ctx.client, body, root=ctx.root, timeout=300)
    if not head.has("DONE"):
        raise fail("OWBM-E-RST-001", step="whiteouts", reason="не удалось применить удаления OverlayFS")
    ctx.logger.debug(f"Удалений OverlayFS применено: {len(paths)}")


def _reload(ctx: ApplyContext, plan: RestorePlan, state: Dict[str, object]) -> None:
    script = (
        'set -u\nPATH="/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"\n'
        "if [ -x /etc/init.d/network ]; then /etc/init.d/network reload >/dev/null 2>&1; fi\n"
        "sync\nprintf 'RELOADED=1\\n'\n"
    )
    result = ctx.client.run(script, timeout=120, allow_failure=True)
    if "RELOADED=1" in result.out:
        ctx.logger.info("Сетевые настройки применены.")
        return
    ctx.logger.warn(
        "Соединение прервалось при применении сети. Это ожидаемый риск: "
        "сторожевой процесс вернёт прежние настройки, если связь не восстановится."
    )


def _confirm(ctx: ApplyContext, plan: RestorePlan, state: Dict[str, object]) -> None:
    deadline = time.monotonic() + max(1, ctx.options.confirm_timeout)
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        if state.get("armed"):
            rollback.heartbeat(ctx.client, root=ctx.root, timeout=ctx.options.watchdog_timeout)
        probe = ctx.client.run("printf 'ALIVE=1\\n'", timeout=15, allow_failure=True)
        if "ALIVE=1" in probe.out:
            if state.get("armed"):
                rollback.disarm(ctx.client, root=ctx.root)
                state["armed"] = False
                ctx.logger.ok("Связь подтверждена, сторожевой процесс отключён.")
            return
        time.sleep(2)
    raise fail(
        "OWBM-E-RST-001",
        step="confirm",
        reason=(
            f"устройство не отвечает по прежнему адресу после {attempt} попыток; "
            "сторожевой процесс вернёт прежнюю сеть и перезагрузит устройство"
        ),
    )


def _reboot(ctx: ApplyContext, plan: RestorePlan, state: Dict[str, object]) -> None:
    if state.get("armed"):
        raise fail(
            "OWBM-E-RST-001",
            step="reboot",
            reason="перезагрузка запрещена, пока сторожевой процесс не отключён",
        )
    dest = ctx.root or ""
    script = (
        'set -u\nPATH="/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"\n'
        f"REBOOT={shlex.quote(dest + '/sbin/reboot')}\n"
        'if [ ! -x "$REBOOT" ]; then printf \'NO_REBOOT=1\\n\'; exit 0; fi\n'
        '(sleep 2; sync; "$REBOOT") >/dev/null 2>&1 </dev/null &\n'
        'printf \'REBOOTING=1\\n\'\n'
    )
    ctx.client.run(script, timeout=30, allow_failure=True)


_HANDLERS: Dict[str, Callable[[ApplyContext, RestorePlan, Dict[str, object]], None]] = {
    "pre-restore-backup": _pre_restore,
    "stage-rollback": _stage,
    "arm-watchdog": _arm,
    "reload-network": _reload,
    "confirm": _confirm,
    "reboot": _reboot,
}
