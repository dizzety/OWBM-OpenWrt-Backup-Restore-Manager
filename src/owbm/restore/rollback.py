"""Rollback: a watchdog that returns the device to its previous network.

Design constraints that shaped this:

* the risky window is "new network configuration is applied but nobody has
  confirmed it yet". Only that window is guarded;
* the guard must survive the SSH session dying, so it is a detached process;
* it must not survive "forever" either: if we confirm success, the marker file
  is removed and the watchdog exits without touching anything;
* everything lives in tmpfs (``/tmp``), so a reboot — planned or forced by the
  watchdog — leaves nothing behind on the device.
"""

from __future__ import annotations

import shlex
from typing import List

from ..errors import fail
from ..remote import ProbeResult, build_script, run_probe

WATCHDOG_PATH = "/tmp/owbm-watchdog.sh"
ARMED_PATH = "/tmp/owbm-armed"
DEADLINE_PATH = "/tmp/owbm-deadline"
ROLLBACK_DIR = "/tmp/owbm-rollback"
STAGED_FILES = ("network", "firewall", "dropbear")

WATCHDOG_BODY = """#!/bin/sh
PATH="/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
ROOT="__ROOT__"
ARMED="$ROOT__ARMED__"
DEADLINE="$ROOT__DEADLINE__"
while :; do
  [ -f "$ARMED" ] || exit 0
  now=$(date +%s 2>/dev/null || echo 0)
  dl=$(cat "$DEADLINE" 2>/dev/null || echo 0)
  case "$now" in ''|*[!0-9]*) now=0 ;; esac
  case "$dl" in ''|*[!0-9]*) dl=0 ;; esac
  [ "$dl" -gt 0 ] || exit 0
  [ "$now" -lt "$dl" ] || break
  sleep 2
done
D="$ROOT__ROLLBACK__"
for f in __FILES__; do
  if [ -f "$D/$f" ] && [ -e "$ROOT/etc/config/$f" ]; then
    cp -f "$D/$f" "$ROOT/etc/config/$f"
  fi
done
sync
rm -f "$ARMED" "$DEADLINE"
REBOOT="$ROOT/sbin/reboot"
if [ ! -x "$REBOOT" ]; then
  if [ -n "$ROOT" ]; then exit 1; fi
  REBOOT=reboot
fi
"$REBOOT"
"""

STAGE_SCRIPT = """set -u
PATH="/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
PATH="${OWBM_PATH_PREPEND:+${OWBM_PATH_PREPEND}:}${PATH}"
R="${OWBM_ROOT:-}"
mkdir -p "$R/tmp" || exit 60
D="$R@@ROLLBACK@@"
rm -rf "$D"
mkdir -p "$D" || exit 60
for f in @@FILES@@; do
  if [ -f "$R/etc/config/$f" ]; then cp -p "$R/etc/config/$f" "$D/$f" || exit 61; fi
done
printf 'STAGED=1\n'
"""


ARM_SCRIPT = """set -u
PATH="/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
PATH="${OWBM_PATH_PREPEND:+${OWBM_PATH_PREPEND}:}${PATH}"
R="${OWBM_ROOT:-}"
mkdir -p "$R/tmp" || exit 60
cat > "$R@@WATCHDOG_PATH@@" <<'OWBM_WATCHDOG_EOF'
@@WATCHDOG_BODY@@
OWBM_WATCHDOG_EOF
chmod 700 "$R@@WATCHDOG_PATH@@" || exit 62
: > "$R@@ARMED@@" || exit 63
printf '%s' "$(( $(date +%s) + @@TIMEOUT@@ ))" > "$R@@DEADLINE@@" || exit 63
if command -v setsid >/dev/null 2>&1; then
  setsid "$R@@WATCHDOG_PATH@@" @@TIMEOUT@@ >/dev/null 2>&1 < /dev/null &
elif command -v nohup >/dev/null 2>&1; then
  nohup "$R@@WATCHDOG_PATH@@" @@TIMEOUT@@ >/dev/null 2>&1 < /dev/null &
else
  printf 'ERROR=no-detach\\n' >&2
  exit 64
fi
printf 'ARMED=1\\n'
"""

DISARM_SCRIPT = """set -u
PATH="/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
R="${OWBM_ROOT:-}"
rm -f "$R@@ARMED@@" "$R@@DEADLINE@@" "$R@@WATCHDOG_PATH@@"
rm -rf "$R@@ROLLBACK@@"
printf 'DISARMED=1\\n'
"""


def watchdog_source(root: str = "") -> str:
    body = WATCHDOG_BODY
    body = body.replace("__ROOT__", root)
    body = body.replace("__ARMED__", ARMED_PATH)
    body = body.replace("__DEADLINE__", DEADLINE_PATH)
    body = body.replace("__ROLLBACK__", ROLLBACK_DIR)
    body = body.replace("__FILES__", " ".join(STAGED_FILES))
    return body


def _fill(template: str, root: str, timeout: int = 180) -> str:
    text = template
    text = text.replace("@@WATCHDOG_BODY@@", watchdog_source(root))
    text = text.replace("@@WATCHDOG_PATH@@", WATCHDOG_PATH)
    text = text.replace("@@ROLLBACK@@", ROLLBACK_DIR)
    text = text.replace("@@ARMED@@", ARMED_PATH)
    text = text.replace("@@DEADLINE@@", DEADLINE_PATH)
    text = text.replace("@@FILES@@", " ".join(STAGED_FILES))
    text = text.replace("@@TIMEOUT@@", str(max(1, int(timeout))))
    return text


def stage_script(root: str = "") -> str:
    return _fill(STAGE_SCRIPT, root)


def arm_script(root: str = "", timeout: int = 180) -> str:
    return _fill(ARM_SCRIPT, root, timeout)


def disarm_script(root: str = "") -> str:
    text = DISARM_SCRIPT
    text = text.replace("@@WATCHDOG_PATH@@", WATCHDOG_PATH)
    text = text.replace("@@ARMED@@", ARMED_PATH)
    text = text.replace("@@DEADLINE@@", DEADLINE_PATH)
    text = text.replace("@@ROLLBACK@@", ROLLBACK_DIR)
    return text


def stage(client, *, root: str = "") -> ProbeResult:
    head = run_probe(client, stage_script(root), root=root, timeout=60)
    if head.one("STAGED") != "1":
        raise fail("OWBM-E-CMP-003", reason="не удалось сохранить сетевые настройки цели для отката")
    return head


def arm(client, *, root: str = "", timeout: int = 180) -> ProbeResult:
    head = run_probe(client, arm_script(root, timeout), root=root, timeout=30)
    if head.one("ARMED") != "1":
        raise fail("OWBM-E-CMP-003", reason="не удалось включить сторожевой процесс на устройстве")
    return head


def disarm(client, *, root: str = "") -> None:
    run_probe(client, disarm_script(root), root=root, timeout=30)


HEARTBEAT_SCRIPT = """set -u
PATH="/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
R="${OWBM_ROOT:-}"
[ -f "$R@@ARMED@@" ] || { echo 'NOT-ARMED=1'; exit 0; }
printf '%s' "$(( $(date +%s) + @@TIMEOUT@@ ))" > "$R@@DEADLINE@@" || exit 1
echo 'BEAT=1'
"""


def heartbeat(client, *, root: str = "", timeout: int = 180) -> bool:
    """Push the rollback deadline forward; the watchdog only fires on silence."""
    text = HEARTBEAT_SCRIPT
    text = text.replace("@@ARMED@@", ARMED_PATH)
    text = text.replace("@@DEADLINE@@", DEADLINE_PATH)
    text = text.replace("@@TIMEOUT@@", str(max(1, int(timeout))))
    try:
        head = run_probe(client, text, root=root, timeout=30)
    except Exception:  # noqa: BLE001 - a missed beat must not break the restore
        return False
    return head.has("BEAT")


def replay_whiteouts_script(paths: List[str], root: str = "") -> str:
    """Deletions from the lower layer, replayed on the merged filesystem."""
    from ..adapters import overlayfs

    problems = overlayfs.validate_whiteout_paths(paths)
    if problems:
        raise fail("OWBM-E-CHK-003", path=problems[0])
    quoted = " ".join(shlex.quote(item) for item in paths)
    body = (
        'set -u\nPATH="/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"\nR="${OWBM_ROOT:-}"\n'
        f"for p in {quoted}; do\n"
        '  t="$R/$p"\n'
        '  if [ -d "$t" ] && [ ! -L "$t" ]; then printf \'SKIP-DIR=%s\\n\' "$p"; continue; fi\n'
        '  if [ -e "$t" ] || [ -L "$t" ]; then rm -f "$t"; fi\n'
        "done\nsync\nprintf 'DONE=1\\n'\n"
    )
    return body
