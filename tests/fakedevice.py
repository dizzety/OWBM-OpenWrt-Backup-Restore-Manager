"""Materialise fixture devices and run OWBM scripts against them.

The same shell script that runs on a router runs here: only the root prefix and
PATH are redirected, so `sh -s` still parses and executes the real code.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from owbm.remote import ProbeResult, build_script, parse_probe
from owbm.ssh import RunResult, SSHTarget
from tests.fixtures.devices import DEVICES

FAKE_COMMANDS = {
    "uname",
    "df",
    "date",
    "apk",
    "opkg",
    "ubus",
    "sysupgrade",
    "jsonfilter",
    "uci",
    "id",
}


@dataclass
class Device:
    name: str
    spec: Dict[str, Any]
    root: Path
    bindir: Path
    profile: Path
    workdir: Path

    # -- helpers -----------------------------------------------------------
    def env(self) -> Dict[str, str]:
        env = dict(os.environ)
        env["FAKE_PROFILE"] = str(self.profile)
        env["OWBM_PATH_PREPEND"] = str(self.bindir)
        env["PATH"] = f"{self.bindir}:{env.get('PATH', '')}"
        env["TMPDIR"] = str(self.workdir)
        env["FAKE_DEVICE_ROOT"] = str(self.root)
        env.pop("OWBM_ROOT", None)
        return env

    def run_command(self, script: str, timeout: int = 60) -> RunResult:
        proc = subprocess.run(
            ["sh", "-s"],
            input=script,
            text=True,
            capture_output=True,
            env=self.env(),
            timeout=timeout,
        )
        return RunResult(proc.returncode, proc.stdout.encode(), proc.stderr)

    def run(self, body: str, *, root: Optional[str] = None, timeout: int = 60) -> ProbeResult:
        script = build_script(body, root=self.root.as_posix() if root is None else root)
        return parse_probe(self.run_command(script, timeout=timeout).out)

    def rewrite_root(self, script: str) -> str:
        import shlex

        root_line = "OWBM_ROOT=''\n"
        if script.startswith(root_line):
            return f"OWBM_ROOT={shlex.quote(self.root.as_posix())}\n" + script[len(root_line):]
        return script

    def client(self) -> "FakeClient":
        return FakeClient(self)


class FakeClient:
    """Minimal stand-in for owbm.ssh.SSHClient."""

    def __init__(self, device: Device) -> None:
        self.device = device
        self.target = SSHTarget(host=f"{device.name}.fixture", user="root", port=22)

    def run(self, script: str, *, timeout: Optional[int] = None, allow_failure: bool = False, stdin_bytes=None):
        script = self.device.rewrite_root(script)
        result = self.device.run_command(script, timeout=timeout or 60)
        if not allow_failure and result.rc != 0:
            raise AssertionError(f"remote script failed rc={result.rc}: {result.stderr[:400]}")
        return result

    def ensure_host_key(self, *, accept: bool = False, ui=None):
        return None

    def popen_command(self, command: str):
        return subprocess.Popen(
            ["sh", "-c", command],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.device.env(),
        )

    def popen(self, script: str):
        script = self.device.rewrite_root(script)
        proc = subprocess.Popen(
            ["sh", "-s"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.device.env(),
        )
        try:
            assert proc.stdin is not None
            proc.stdin.write(script.encode())
            proc.stdin.close()
        except BrokenPipeError:
            pass
        return proc


def dispatch_links(base: Path, dispatch: Path) -> Path:
    os.chmod(dispatch, 0o755)
    return dispatch


def build(name: str, base: Path, dispatch: Path) -> Device:
    spec = DEVICES[name]
    os.chmod(dispatch, 0o755)
    root = base / f"root-{name}"
    bindir = base / f"bin-{name}"
    bindir.mkdir(parents=True, exist_ok=True)
    root.mkdir(parents=True, exist_ok=True)

    # Only commands whose *output* must be faked are stubbed. Real tools such as
    # tar, gzip, find, mktemp must keep working, so they stay resolvable from PATH.
    stub_tools = (set(spec.get("tools", [])) & FAKE_COMMANDS) | {"uname", "df", "date"}
    for tool in sorted(stub_tools):
        link = bindir / tool
        if not link.exists():
            os.symlink(dispatch, link)

    profile = base / f"profile-{name}.json"
    profile.write_text(json.dumps({"commands": spec.get("commands", {})}), encoding="utf-8")

    for path_text, content in spec.get("files", {}).items():
        path = root / path_text.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    for directory in spec.get("dirs", []):
        (root / directory.lstrip("/")).mkdir(parents=True, exist_ok=True)

    workdir = base / f"tmp-{name}"
    workdir.mkdir(parents=True, exist_ok=True)

    sbin = root / "sbin"
    sbin.mkdir(parents=True, exist_ok=True)
    reboot_stub = sbin / "reboot"
    reboot_stub.write_text(
        "#!/bin/sh\nprintf 'reboot %s\\n' \"$(date +%s)\" >> \"$(dirname \"$0\")/../reboot.log\"\n",
        encoding="utf-8",
    )
    os.chmod(reboot_stub, 0o755)

    for iface, mac in spec.get("net", {}).items():
        netdir = root / "sys" / "class" / "net" / iface
        netdir.mkdir(parents=True, exist_ok=True)
        (netdir / "address").write_text(mac + "\n", encoding="utf-8")
        (netdir / "operstate").write_text("up\n", encoding="utf-8")

    return Device(name=name, spec=spec, root=root, bindir=bindir, profile=profile, workdir=workdir)


def names() -> List[str]:
    return sorted(DEVICES)
