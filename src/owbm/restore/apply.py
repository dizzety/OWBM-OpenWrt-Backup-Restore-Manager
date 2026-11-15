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

from .. import archive, i18n
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
                ctx.logger.warn(i18n.tr("restore.apply.step_retry", title=step.title))
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
                result.messages.append(i18n.tr("restore.apply.rollback_snapshot"))
            if result.armed:
                result.messages.append(i18n.tr("restore.apply.watchdog_armed_failure"))
            return result
        except (BrokenPipeError, ConnectionError, OSError) as exc:
            journal.fail(step.id, i18n.tr("restore.apply.connection_interrupted", error=exc))
            result.status = STATUS_FAILED
            result.failed = step.id
            result.armed = bool(state.get("armed"))
            result.messages.append(
                fail(
                    "OWBM-E-RST-001",
                    step=step.id,
                    reason=i18n.tr("restore.apply.transfer_interrupted"),
                ).render()
            )
            if _rollback_configuration(ctx, state, journal):
                result.messages.append(i18n.tr("restore.apply.rollback_restored"))
            if result.armed:
                result.messages.append(i18n.tr("restore.apply.watchdog_unconfirmed"))
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
            i18n.tr("restore.apply.partial_packages", detail=install[1], path=PACKAGE_STAGE_DIR)
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
        ctx.logger.warn(i18n.tr("restore.apply.rollback_failed", error=exc))
        return False
    state["configuration_applied"] = False
    ctx.logger.warn(i18n.tr("restore.apply.rollback_complete"))
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
    ui.say(i18n.tr("restore.apply.key_changed", host=client.target.host, port=client.target.port))
    if before:
        ui.say(i18n.tr("restore.apply.saved_fingerprints", items=', '.join(before)))
    ui.say(i18n.tr("restore.apply.new_fingerprints"))
    for key_type, fingerprint in fingerprints:
        ui.say(f"  {key_type}: {fingerprint}")
    ui.say(i18n.tr("restore.apply.verify_key"))
    if not ui.ask_yes_no(i18n.tr("restore.apply.confirm_key"), default=False):
        return False

    try:
        info = client.repin_host_key(keys=keys)
    except OwbmError:
        return False
    ctx.logger.warn(i18n.tr("restore.apply.key_accepted", fingerprint=info['fingerprint']))
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
        raise fail("OWBM-E-RST-001", step=step_id, reason=i18n.tr("restore.apply.not_implemented"))
    handler(ctx, plan, state)


def _pre_restore(ctx: ApplyContext, plan: RestorePlan, state: Dict[str, object]) -> None:
    ctx.logger.info(i18n.tr("restore.apply.backup_target"))
    result = packager.create_backup(
        ctx.client,
        ctx.passport,
        ctx.profile_caps,
        ctx.store,
        packager.BackupOptions(mode="pre-restore", include_package_binaries=False),
        ctx.logger,
    )
    if not result.ok:
        raise fail("OWBM-E-RST-001", step="pre-restore", reason=i18n.tr("restore.apply.snapshot_not_created"))
    state["pre_restore_path"] = result.path
    ctx.logger.ok(i18n.tr("restore.apply.snapshot_label", path=result.path))


def _stage(ctx: ApplyContext, plan: RestorePlan, state: Dict[str, object]) -> None:
    rollback.stage(ctx.client, root=ctx.root)


def _arm(ctx: ApplyContext, plan: RestorePlan, state: Dict[str, object]) -> None:
    rollback.arm(ctx.client, root=ctx.root, timeout=ctx.options.watchdog_timeout)
    state["armed"] = True
    ctx.logger.info(i18n.tr("restore.apply.watchdog_enabled", timeout=ctx.options.watchdog_timeout))


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
        return True, i18n.tr("restore.apply.no_package_files")
    if "INSTALL=ok" in output:
        return True, ""
    detail = " ".join(line for line in output.splitlines() if line.strip() and "INSTALL=" not in line)[-300:]
    return False, detail or i18n.tr("restore.apply.package_installer_failed")


def _apply_component(ctx: ApplyContext, component_id: str, applied=None, state=None) -> None:
    component = ctx.parsed.component(component_id)
    if component is None:
        raise fail("OWBM-E-CHK-002", reason=i18n.tr("restore.apply.component_missing", component=component_id))
    applied = applied or set()

    if component_id == "packages_binaries":
        _apply_packages(ctx, component, applied, state if state is not None else {})
        return

    payload = archive.extract_member(ctx.archive_path, component.path, ctx.workdir)
    members, _size = collector.inspect_tar(payload)
    ctx.logger.debug(i18n.tr("restore.apply.member_count", component=component_id,
                              count=members, size=human_size(payload.stat().st_size)))

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
        ctx.logger.info(i18n.tr("restore.apply.packages_in_system"))
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
    ctx.logger.info(i18n.tr("restore.apply.packages_extracted", count=members))

    if not ctx.options.install_packages:
        ctx.logger.info(i18n.tr("restore.apply.install_disabled", path=PACKAGE_STAGE_DIR))
        return

    manager = ctx.passport.packages.manager
    if manager not in ("apk", "opkg"):
        ctx.logger.warn(i18n.tr("restore.apply.manager_unknown"))
        return
    ctx.logger.info(i18n.tr("restore.apply.install_from_archive", manager=manager))
    ok, detail = _install_packages(ctx, stage, manager)
    state["package_install"] = (ok, detail, members)
    if ok:
        ctx.logger.ok(i18n.tr("restore.apply.packages_installed", count=members))
        _cleanup_package_stage(ctx, stage)
    else:
        ctx.logger.warn(i18n.tr("restore.apply.install_failed", detail=detail))
        ctx.logger.info(i18n.tr("restore.apply.packages_left", path=stage))


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
        raise fail("OWBM-E-RST-001", step="whiteouts", reason=i18n.tr("restore.apply.whiteout_failed"))
    ctx.logger.debug(i18n.tr("restore.apply.whiteouts_applied", count=len(paths)))


def _reload(ctx: ApplyContext, plan: RestorePlan, state: Dict[str, object]) -> None:
    script = (
        'set -u\nPATH="/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"\n'
        "if [ -x /etc/init.d/network ]; then /etc/init.d/network reload >/dev/null 2>&1; fi\n"
        "sync\nprintf 'RELOADED=1\\n'\n"
    )
    result = ctx.client.run(script, timeout=120, allow_failure=True)
    if "RELOADED=1" in result.out:
        ctx.logger.info(i18n.tr("restore.apply.network_applied"))
        return
    ctx.logger.warn(i18n.tr("restore.apply.network_disconnect"))


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
                ctx.logger.ok(i18n.tr("restore.apply.watchdog_disabled"))
            return
        time.sleep(2)
    raise fail(
        "OWBM-E-RST-001",
        step="confirm",
        reason=i18n.tr("restore.apply.confirm_timeout", attempts=attempt),
    )


def _reboot(ctx: ApplyContext, plan: RestorePlan, state: Dict[str, object]) -> None:
    if state.get("armed"):
        raise fail(
            "OWBM-E-RST-001",
            step="reboot",
            reason=i18n.tr("restore.apply.reboot_armed"),
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
