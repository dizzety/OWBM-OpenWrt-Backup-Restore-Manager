"""SSH transport with strict host key pinning and no secrets in argv.

Design rules:
* host key verification is always on; unknown hosts require an explicit
  fingerprint confirmation (or a deliberate ``--accept-host-key``);
* passwords never appear in argv, only in a 0600 file consumed by an askpass
  helper that is deleted right after the connection;
* every failure is classified into a stable OWBM error code.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .errors import fail
from .util import ensure_dir, which

ASKPASS_SCRIPT = "#!/bin/sh\ncat -- \"$OWBM_ASKPASS_FILE\" 2>/dev/null\n"
MAX_CAPTURE_STDOUT_BYTES = 32 * 1024 * 1024
MAX_CAPTURE_STDERR_BYTES = 1 * 1024 * 1024
_CAPTURE_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True)
class SSHTarget:
    host: str
    user: str = "root"
    port: int = 22
    identity_file: str = ""
    proxy_jump: str = ""
    connect_timeout: int = 10
    known_hosts: Path = field(default_factory=lambda: Path.home() / ".ssh" / "known_hosts")
    host_key_policy: str = "ask"

    @property
    def spec(self) -> str:
        return self.host if self.port == 22 else f"[{self.host}]:{self.port}"

    @property
    def destination(self) -> str:
        return f"{self.user}@{self.host}"

    def describe(self) -> str:
        return f"{self.destination}:{self.port}"


@dataclass
class RunResult:
    rc: int
    stdout: bytes
    stderr: str

    @property
    def out(self) -> str:
        return self.stdout.decode("utf-8", "replace")

    @property
    def ok(self) -> bool:
        return self.rc == 0


class UI:
    """Minimal interactive surface, replaceable in tests."""

    def say(self, message: str) -> None:  # pragma: no cover - trivial
        print(message, flush=True)

    def is_interactive(self) -> bool:
        return all(
            bool(getattr(stream, "isatty", lambda: False)())
            for stream in (sys.stdin, sys.stdout)
        )

    def ask_yes_no(self, question: str, default: bool = False) -> bool:  # pragma: no cover
        suffix = "[Y/n]" if default else "[y/N]"
        try:
            answer = input(f"{question} {suffix} ").strip().lower()
        except EOFError:
            return default
        if not answer:
            return default
        return answer in ("y", "yes", "д", "да")


def _classify_failure(stderr: str, target: SSHTarget, rc: int) -> None:
    text = (stderr or "").strip()
    lowered = text.lower()
    if "host key verification failed" in lowered or "identification has changed" in lowered:
        raise fail("OWBM-E-SSH-003", host=target.host, port=target.port, known_hosts=str(target.known_hosts))
    if "permission denied" in lowered or "no supported authentication" in lowered:
        raise fail("OWBM-E-SSH-004", user=target.user, host=target.host)
    if "connection refused" in lowered:
        raise fail("OWBM-E-SSH-002", host=target.host, port=target.port, reason="Порт закрыт: SSH-сервер не принимает подключения.")
    if "no route to host" in lowered or "network is unreachable" in lowered:
        raise fail("OWBM-E-SSH-002", host=target.host, port=target.port, reason="Устройство не отвечает: нет маршрута в сети.")
    if "connection timed out" in lowered or "operation timed out" in lowered:
        raise fail("OWBM-E-SSH-002", host=target.host, port=target.port, reason="Устройство не отвечает за отведённое время.")
    if "could not resolve" in lowered or "name or service not known" in lowered:
        raise fail("OWBM-E-SSH-002", host=target.host, port=target.port, reason="Имя устройства не разрешается в адрес.")
    first = text.splitlines()[-1] if text else "ssh завершился с ошибкой"
    raise fail("OWBM-E-SSH-002", host=target.host, port=target.port, reason=first)


class SSHClient:
    def __init__(
        self,
        target: SSHTarget,
        *,
        logger=None,
        password: Optional[str] = None,
        extra_options: Iterable[str] = (),
    ) -> None:
        self.target = target
        self.logger = logger
        self.password = password
        self.extra_options = tuple(extra_options)
        self._askpass_dir: Optional[Path] = None
        self._askpass_file: Optional[Path] = None
        if not which("ssh"):
            raise fail("OWBM-E-SSH-001")

    # -- argv --------------------------------------------------------------
    def build_argv(self, remote_command: str = "sh -s") -> List[str]:
        target = self.target
        argv = [which("ssh") or "ssh"]
        argv += ["-o", "StrictHostKeyChecking=yes"]
        argv += ["-o", f"UserKnownHostsFile={target.known_hosts}"]
        argv += ["-o", "GlobalKnownHostsFile=/dev/null"]
        argv += ["-o", f"ConnectTimeout={target.connect_timeout}"]
        argv += ["-o", "ServerAliveInterval=15"]
        argv += ["-o", "ServerAliveCountMax=3"]
        argv += ["-o", "LogLevel=ERROR"]
        argv += ["-o", "NumberOfPasswordPrompts=1"]
        argv += ["-o", "ControlMaster=no"] if False else []
        if self.password is None:
            argv += ["-o", "BatchMode=yes"]
        else:
            argv += ["-o", "PreferredAuthentications=password,keyboard-interactive"]
            argv += ["-o", "PubkeyAuthentication=no"]
        if target.identity_file:
            argv += ["-i", os.path.expanduser(target.identity_file)]
        if target.proxy_jump:
            argv += ["-J", target.proxy_jump]
        if target.port != 22:
            argv += ["-p", str(target.port)]
        argv += list(self.extra_options)
        argv += [target.destination, remote_command]
        return argv

    # -- host keys ---------------------------------------------------------
    def _known_hosts_path(self) -> Path:
        return Path(self.target.known_hosts).expanduser()

    def check_known_host(self) -> bool:
        tool = which("ssh-keygen")
        if not tool:
            raise fail("OWBM-E-SSH-007", tool="ssh-keygen")
        path = self._known_hosts_path()
        if not path.exists():
            return False
        proc = subprocess.run(
            [tool, "-F", self.target.spec, "-f", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        return proc.returncode == 0 and bool(proc.stdout.strip())

    def scan_host_keys(self) -> List[Tuple[str, str]]:
        tool = which("ssh-keyscan")
        if not tool:
            raise fail("OWBM-E-SSH-007", tool="ssh-keyscan")
        argv = [tool, "-T", str(self.target.connect_timeout), "-p", str(self.target.port), self.target.host]
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        lines = [
            line
            for line in proc.stdout.decode("utf-8", "replace").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        if not lines:
            reason = proc.stderr.decode("utf-8", "replace").strip() or "устройство не вернуло ключей"
            raise fail("OWBM-E-SSH-008", host=self.target.host, port=self.target.port, reason=reason)
        keys: List[Tuple[str, str]] = []
        for line in lines:
            parts = line.split()
            if len(parts) >= 3:
                keys.append((parts[1], line))
        if not keys:
            raise fail("OWBM-E-SSH-008", host=self.target.host, port=self.target.port, reason="неизвестный формат ключа")
        return keys

    @staticmethod
    def fingerprint(key_line: str) -> str:
        tool = which("ssh-keygen") or "ssh-keygen"
        proc = subprocess.run(
            [tool, "-lf", "-"],
            input=(key_line + "\n").encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        text = proc.stdout.decode("utf-8", "replace").strip()
        if not text:
            return "не удалось вычислить отпечаток"
        fields = text.split()
        for token in fields:
            if token.startswith("SHA256:"):
                return token
        return fields[0]

    def ensure_host_key(self, *, accept: bool = False, ui: Optional[UI] = None) -> Optional[Dict[str, str]]:
        """Pin the host key. Returns details of a newly accepted key, else None."""
        if self.check_known_host():
            return None
        keys = self.scan_host_keys()
        info = {
            "host": self.target.host,
            "port": str(self.target.port),
            "key_type": keys[0][0],
            "fingerprint": self.fingerprint(keys[0][1]),
        }
        if not accept:
            if self.target.host_key_policy == "strict":
                raise fail("OWBM-E-SSH-006")
            ui = ui or UI()
            ui.say("")
            ui.say(f"Первое подключение к {self.target.host}:{self.target.port}")
            ui.say("Отпечатки всех предложенных ключей:")
            for key_type, key_line in keys:
                ui.say(f"  {key_type}: {self.fingerprint(key_line)}")
            ui.say("Сверьте все отпечатки с устройством (LuCI → SSH, или консоль).")
            if not ui.ask_yes_no("Доверять этому ключу?", default=False):
                raise fail("OWBM-E-SSH-006")
        path = self._known_hosts_path()
        ensure_dir(path.parent, 0o700)
        existed = path.exists()
        with open(path, "a", encoding="utf-8") as handle:
            for _key_type, key_line in keys:
                handle.write(key_line + "\n")
        if not existed:
            os.chmod(path, 0o600)
        return info

    def known_host_fingerprints(self) -> List[str]:
        tool = which("ssh-keygen")
        path = self._known_hosts_path()
        if not tool or not path.exists():
            return []
        proc = subprocess.run(
            [tool, "-F", self.target.spec, "-f", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        result = []
        for line in proc.stdout.decode("utf-8", "replace").splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            result.append(self.fingerprint(line))
        return result

    def remove_known_host(self) -> None:
        tool = which("ssh-keygen")
        path = self._known_hosts_path()
        if not tool or not path.exists():
            return
        subprocess.run(
            [tool, "-R", self.target.spec, "-f", str(path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def repin_host_key(
        self, keys: Optional[List[Tuple[str, str]]] = None
    ) -> Dict[str, object]:
        """Replace the pinned key with the already-inspected candidate.

        Callers that display a fingerprint must pass the exact scan result so a
        second scan cannot substitute a different key after confirmation.
        """
        before = self.known_host_fingerprints()
        candidates = list(keys) if keys is not None else self.scan_host_keys()
        if not candidates:
            raise fail(
                "OWBM-E-SSH-008",
                host=self.target.host,
                port=self.target.port,
                reason="устройство не вернуло ключей",
            )
        fingerprints = [(key_type, self.fingerprint(key_line)) for key_type, key_line in candidates]
        if any(not fingerprint.startswith("SHA256:") for _key_type, fingerprint in fingerprints):
            raise fail(
                "OWBM-E-SSH-008",
                host=self.target.host,
                port=self.target.port,
                reason="не удалось проверить отпечаток SSH-ключа",
            )
        self.remove_known_host()
        path = self._known_hosts_path()
        ensure_dir(path.parent, 0o700)
        existed = path.exists()
        with open(path, "a", encoding="utf-8") as handle:
            for _key_type, key_line in candidates:
                handle.write(key_line + "\n")
        if not existed:
            os.chmod(path, 0o600)
        return {
            "before": before,
            "after": self.known_host_fingerprints(),
            "key_type": candidates[0][0],
            "fingerprint": fingerprints[0][1],
            "fingerprints": [fingerprint for _key_type, fingerprint in fingerprints],
        }

    # -- execution ---------------------------------------------------------
    @contextlib.contextmanager
    def _password_env(self):
        if self.password is None:
            yield None
            return
        directory = Path(tempfile.mkdtemp(prefix="owbm-askpass-", dir=os.environ.get("TMPDIR") or None))
        os.chmod(directory, 0o700)
        secret = directory / "secret"
        fd = os.open(str(secret), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(self.password)
        helper = directory / "askpass.sh"
        with open(helper, "w", encoding="utf-8") as handle:
            handle.write(ASKPASS_SCRIPT)
        os.chmod(helper, 0o700)
        env = dict(os.environ)
        env.update(
            {
                "SSH_ASKPASS": str(helper),
                "SSH_ASKPASS_REQUIRE": "force",
                "OWBM_ASKPASS_FILE": str(secret),
                "DISPLAY": env.get("DISPLAY", ":0"),
            }
        )
        try:
            yield env
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    def run(
        self,
        script: str,
        *,
        timeout: Optional[int] = None,
        allow_failure: bool = False,
        stdin_bytes: Optional[bytes] = None,
    ) -> RunResult:
        argv = self.build_argv()
        payload = stdin_bytes if stdin_bytes is not None else script.encode("utf-8")
        if self.logger:
            self.logger.debug(f"ssh {' '.join(argv[1:-1])} (script {len(payload)} байт)")
        with self._password_env() as env:
            try:
                proc = subprocess.Popen(
                    argv,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                )
            except FileNotFoundError:
                raise fail("OWBM-E-SSH-001")

            stdout_data = bytearray()
            stderr_data = bytearray()
            overflow = threading.Event()

            def drain(pipe, sink: bytearray, limit: int) -> None:
                total = 0
                try:
                    while True:
                        block = pipe.read(min(_CAPTURE_CHUNK_BYTES, limit - total + 1))
                        if not block:
                            return
                        remaining = limit - total
                        if len(block) > remaining:
                            if remaining > 0:
                                sink.extend(block[:remaining])
                            overflow.set()
                            try:
                                proc.kill()
                            except OSError:
                                pass
                            return
                        sink.extend(block)
                        total += len(block)
                except OSError:
                    return
                finally:
                    pipe.close()

            readers = [
                threading.Thread(
                    target=drain,
                    args=(proc.stdout, stdout_data, MAX_CAPTURE_STDOUT_BYTES),
                    daemon=True,
                ),
                threading.Thread(
                    target=drain,
                    args=(proc.stderr, stderr_data, MAX_CAPTURE_STDERR_BYTES),
                    daemon=True,
                ),
            ]
            for reader in readers:
                reader.start()

            def write_input() -> None:
                if proc.stdin is None:
                    return
                try:
                    proc.stdin.write(payload)
                    proc.stdin.flush()
                except (BrokenPipeError, OSError):
                    pass
                finally:
                    try:
                        proc.stdin.close()
                    except OSError:
                        pass

            writer = threading.Thread(target=write_input, daemon=True)
            writer.start()
            try:
                rc = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                raise fail("OWBM-E-SSH-005", timeout=timeout or 0)
            finally:
                writer.join()
                for reader in readers:
                    reader.join()

        if overflow.is_set():
            raise fail(
                "OWBM-E-DSC-003",
                reason=(
                    "ответ SSH превысил предел "
                    f"stdout={MAX_CAPTURE_STDOUT_BYTES}, stderr={MAX_CAPTURE_STDERR_BYTES} байт"
                ),
            )
        result = RunResult(rc, bytes(stdout_data), stderr_data.decode("utf-8", "replace"))
        if result.rc != 0 and not allow_failure:
            _classify_failure(result.stderr, self.target, result.rc)
        return result

    def popen(self, script: str) -> subprocess.Popen:
        """Start a remote command whose stdout is streamed (tar over SSH)."""
        return self._spawn(self.build_argv(), script)

    def popen_command(self, command: str) -> subprocess.Popen:
        """Start an explicit remote command; stdin stays open for the caller."""
        return self._spawn(self.build_argv(command), None)

    def _spawn(self, argv: List[str], script: Optional[str]) -> subprocess.Popen:
        env_ctx = self._password_env()
        env = env_ctx.__enter__()
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
        except FileNotFoundError:
            env_ctx.__exit__(None, None, None)
            raise fail("OWBM-E-SSH-001")
        except BaseException:
            env_ctx.__exit__(None, None, None)
            raise
        proc._owbm_env_ctx = env_ctx  # type: ignore[attr-defined]
        if script is not None:
            try:
                proc.stdin.write(script.encode("utf-8"))
                proc.stdin.close()
            except BrokenPipeError:
                pass
        return proc
