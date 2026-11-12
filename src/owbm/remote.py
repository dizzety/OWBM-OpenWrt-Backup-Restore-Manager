"""Remote execution helpers: strict probe protocol and tar streaming.

Every byte coming from the device is untrusted input. The probe parser accepts
only ``KEY=VALUE`` lines with a bounded key alphabet, bounded value length and
no control characters; anything else is counted as malformed instead of being
silently trusted.
"""

from __future__ import annotations

import io
import re
import shlex
import shutil
import threading
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional

from .errors import fail

KEY_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")
MAX_VALUE = 8192
MAX_LINES = 200_000
MAX_TOTAL = 32 * 1024 * 1024
MAX_HEADER_LINE_BYTES = MAX_VALUE + 66
MAX_HEADER_BYTES = 256 * 1024
MAX_STREAM_STDERR_BYTES = 1024 * 1024
MAX_STREAM_BODY_BYTES = 64 * 1024**3
DEFAULT_STREAM_TIMEOUT_SECONDS = 60 * 60
STREAM_DISK_RESERVE_BYTES = 64 * 1024**2
STREAM_DISK_CHECK_BYTES = 1024**2
_STREAM_CAPTURE_CHUNK = 64 * 1024


class _BoundedPipeCapture:
    """Drain a subprocess pipe concurrently while retaining only a fixed prefix."""

    def __init__(self, pipe, limit: Optional[int] = None, on_overflow=None) -> None:
        self.data = bytearray()
        self.overflow = False
        self.on_overflow = on_overflow
        limit = MAX_STREAM_STDERR_BYTES if limit is None else limit
        self.thread = threading.Thread(target=self._drain, args=(pipe, limit), daemon=True)
        self.thread.start()

    def _drain(self, pipe, limit: int) -> None:
        try:
            while True:
                block = pipe.read(_STREAM_CAPTURE_CHUNK)
                if not block:
                    return
                remaining = limit - len(self.data)
                if remaining > 0:
                    self.data.extend(block[:remaining])
                if len(block) > remaining and not self.overflow:
                    self.overflow = True
                    if self.on_overflow is not None:
                        self.on_overflow()
        except OSError:
            return
        finally:
            pipe.close()

    def read(self) -> bytes:
        self.thread.join()
        return bytes(self.data)


def _kill_process(proc) -> None:
    try:
        if proc.poll() is None:
            proc.kill()
    except OSError:
        pass


def _start_deadline(proc, timeout: Optional[int]):
    """Start a hard subprocess deadline and return its timer and expiration flag."""
    expired = threading.Event()
    seconds = DEFAULT_STREAM_TIMEOUT_SECONDS if timeout is None else max(0.0, float(timeout))

    def terminate():
        if proc.poll() is None:
            expired.set()
            _kill_process(proc)

    timer = threading.Timer(seconds, terminate)
    timer.daemon = True
    timer.start()
    return timer, expired


def _check_deadline(expired: threading.Event) -> None:
    if expired.is_set():
        raise fail("OWBM-E-DSC-003", reason="превышено время потоковой SSH-передачи")


def _stderr_capture(proc) -> _BoundedPipeCapture:
    return _BoundedPipeCapture(proc.stderr, on_overflow=lambda: _kill_process(proc))


def _stream_failure(client, rc: int, stderr: bytes, *, stage: str, default: str) -> None:
    text = stderr.decode("utf-8", "replace")
    if rc == 255 or "Permission denied" in text or "Host key verification failed" in text:
        class Result:
            pass

        result = Result()
        result.rc = rc
        result.stderr = text
        _raise_ssh_failure(client, result)
    detail = text.strip().splitlines()
    reason = detail[-1] if detail else default
    raise fail("OWBM-E-DSC-002", stage=stage, reason=reason)


@dataclass
class ProbeResult:
    values: Dict[str, List[str]] = field(default_factory=dict)
    malformed: List[str] = field(default_factory=list)
    total_lines: int = 0

    def one(self, key: str, default: str = "") -> str:
        items = self.values.get(key)
        if not items:
            return default
        return items[-1]

    def all(self, key: str) -> List[str]:
        return list(self.values.get(key, ()))

    def has(self, key: str) -> bool:
        return bool(self.values.get(key))

    def int_or_none(self, key: str) -> Optional[int]:
        raw = self.one(key).strip()
        if not raw:
            return None
        try:
            return int(raw, 10)
        except ValueError:
            return None

    def text(self, key: str, sep: str = "\n") -> str:
        return sep.join(self.values.get(key, ()))

    def keys(self) -> List[str]:
        return sorted(self.values)


def _is_safe_value(value: str) -> bool:
    if len(value) > MAX_VALUE:
        return False
    for char in value:
        code = ord(char)
        if code < 0x20 and char != "\t":
            return False
        if code == 0x7F:
            return False
    return True


def parse_probe(text: str) -> ProbeResult:
    result = ProbeResult()
    total_bytes = 0
    total = 0
    stream = io.StringIO(text)
    while True:
        raw_line = stream.readline(MAX_HEADER_LINE_BYTES + 1)
        if not raw_line:
            break
        total += 1
        if total > MAX_LINES:
            raise fail("OWBM-E-DSC-003", reason=f"слишком много строк ответа (> {MAX_LINES})")
        line_bytes = len(raw_line.encode("utf-8", "replace"))
        total_bytes += line_bytes
        if total_bytes > MAX_TOTAL:
            raise fail("OWBM-E-DSC-003", reason=f"ответ устройства слишком велик (> {MAX_TOTAL} байт)")
        if len(raw_line) > MAX_HEADER_LINE_BYTES:
            if len(result.malformed) < 20:
                result.malformed.append(raw_line[:200])
            while raw_line and not raw_line.endswith("\n"):
                raw_line = stream.readline(MAX_HEADER_LINE_BYTES + 1)
                total_bytes += len(raw_line.encode("utf-8", "replace"))
                if total_bytes > MAX_TOTAL:
                    raise fail("OWBM-E-DSC-003", reason=f"ответ устройства слишком велик (> {MAX_TOTAL} байт)")
            continue
        line = raw_line.rstrip("\n").rstrip("\r")
        if not line:
            continue
        key, sep, value = line.partition("=")
        if not sep or not KEY_RE.match(key) or not _is_safe_value(value):
            if len(result.malformed) < 20:
                result.malformed.append(line[:200])
            continue
        result.values.setdefault(key, []).append(value)
    result.total_lines = total
    return result


def build_script(body: str, *, root: str = "") -> str:
    """Prefix a POSIX shell body with the fake-root variable.

    On a real device ``root`` is empty and every path stays absolute. Tests point
    it at a directory tree so the same script runs unprivileged.
    """
    prelude = "OWBM_ROOT=%s\nexport OWBM_ROOT\n" % shlex.quote(root or "")
    return prelude + body


def _raise_ssh_failure(client, result) -> None:
    """Turn an ssh-level failure into a precise, actionable error."""
    if result.rc == 255 or "Permission denied" in result.stderr or "Host key verification failed" in result.stderr:
        from .ssh import _classify_failure

        _classify_failure(result.stderr, client.target, result.rc)


def run_probe(client, body: str, *, root: str = "", timeout: Optional[int] = 120) -> ProbeResult:
    script = build_script(body, root=root)
    result = client.run(script, timeout=timeout, allow_failure=True)
    if result.rc != 0 and not result.stdout:
        _raise_ssh_failure(client, result)
        message = (result.stderr or "").strip().splitlines()
        detail = message[-1] if message else f"код возврата {result.rc}"
        raise fail("OWBM-E-DSC-002", stage="сбор данных", reason=detail)
    probe = parse_probe(result.out)
    if result.rc != 0:
        probe.values.setdefault("__WARN__", []).append(f"скрипт сбора завершился с кодом {result.rc}")
    return probe


def stream_tar(
    client, body: str, *, root: str = "", timeout: Optional[int] = None
) -> Iterator[bytes]:
    """Yield raw bytes produced by a remote tar command under a deadline."""
    script = build_script(body, root=root)
    proc = client.popen(script)
    timer, expired = _start_deadline(proc, timeout)
    stderr_capture = _stderr_capture(proc)
    total = 0
    try:
        assert proc.stdout is not None
        while True:
            block = proc.stdout.read(1 << 16)
            if not block:
                break
            total += len(block)
            if total > MAX_STREAM_BODY_BYTES:
                raise fail("OWBM-E-DSC-003", reason="поток превышает предел 64 ГиБ")
            yield block
        rc = proc.wait()
        _check_deadline(expired)
        stderr = stderr_capture.read()
        if stderr_capture.overflow:
            raise fail("OWBM-E-DSC-003", reason="stderr SSH превысил предел 1 МиБ")
        if rc != 0:
            _stream_failure(
                client, rc, stderr, stage="передача архива", default=f"код возврата {rc}"
            )
    finally:
        if proc.stdout:
            proc.stdout.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        stderr_capture.read()
        cleanup = getattr(proc, "_owbm_env_ctx", None)
        if cleanup is not None:
            cleanup.__exit__(None, None, None)
        timer.cancel()


BODY_MARKER = "__OWBM_BODY__"


def _write_stream_body(pipe, target, *, max_bytes: Optional[int] = None) -> int:
    """Write a remote body within byte and local free-space limits."""
    from pathlib import Path

    target = Path(target)
    limit = MAX_STREAM_BODY_BYTES if max_bytes is None else min(max_bytes, MAX_STREAM_BODY_BYTES)
    written = 0
    next_disk_check = 0
    try:
        with open(target, "wb") as handle:
            while True:
                block = pipe.read(1 << 16)
                if not block:
                    break
                if written + len(block) > limit:
                    raise fail("OWBM-E-DSC-003", reason=f"поток превышает предел {limit} байт")
                if written == 0 or written + len(block) >= next_disk_check:
                    free = shutil.disk_usage(target.parent).free
                    if free - STREAM_DISK_CHECK_BYTES - len(block) < STREAM_DISK_RESERVE_BYTES:
                        raise fail("OWBM-E-DSC-003", reason="недостаточно места для безопасного приёма потока")
                    next_disk_check = written + STREAM_DISK_CHECK_BYTES
                handle.write(block)
                written += len(block)
    except OSError as exc:
        target.unlink(missing_ok=True)
        raise fail("OWBM-E-DSC-003", reason=f"не удалось сохранить поток локально ({exc})")
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return written


def stream_to_file(
    client, body: str, dest, *, root: str = "", timeout: Optional[int] = None,
    max_body_bytes: Optional[int] = None,
) -> int:
    """Run a remote command and write its bounded stdout to ``dest``."""
    from pathlib import Path

    target = Path(dest)
    script = build_script(body, root=root)
    proc = client.popen(script)
    timer, expired = _start_deadline(proc, timeout)
    stderr_capture = _stderr_capture(proc)
    written = 0
    body_started = False
    completed = False
    try:
        assert proc.stdout is not None
        written = _write_stream_body(proc.stdout, target, max_bytes=max_body_bytes)
        body_started = True
        rc = proc.wait()
        _check_deadline(expired)
        stderr = stderr_capture.read()
        if stderr_capture.overflow:
            raise fail("OWBM-E-DSC-003", reason="stderr SSH превысил предел 1 МиБ")
        if rc != 0:
            _stream_failure(
                client, rc, stderr, stage="передача данных", default=f"код возврата {rc}"
            )
        if written == 0:
            raise fail("OWBM-E-DSC-002", stage="передача данных", reason="устройство вернуло пустой поток")
        completed = True
        return written
    finally:
        if proc.stdout:
            proc.stdout.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        stderr_capture.read()
        cleanup = getattr(proc, "_owbm_env_ctx", None)
        if cleanup is not None:
            cleanup.__exit__(None, None, None)
        timer.cancel()
        if body_started and not completed:
            target.unlink(missing_ok=True)


def stream_framed(
    client, body: str, dest, *, root: str = "", timeout: Optional[int] = None,
    max_body_bytes: Optional[int] = None,
) -> "tuple[ProbeResult, int]":
    """Stream a bounded header/body response in one SSH session."""
    from pathlib import Path

    target = Path(dest)
    script = build_script(body, root=root)
    proc = client.popen(script)
    timer, expired = _start_deadline(proc, timeout)
    stderr_capture = _stderr_capture(proc)
    header: List[str] = []
    header_bytes = 0
    written = 0
    body_started = False
    completed = False
    try:
        assert proc.stdout is not None
        while True:
            line = proc.stdout.readline(MAX_HEADER_LINE_BYTES + 1)
            if not line:
                rc = proc.wait()
                _check_deadline(expired)
                stderr = stderr_capture.read()
                if stderr_capture.overflow:
                    raise fail("OWBM-E-DSC-003", reason="stderr SSH превысил предел 1 МиБ")
                _stream_failure(
                    client,
                    rc,
                    stderr,
                    stage="передача данных",
                    default="поток прерван до начала данных",
                )
            if len(line) > MAX_HEADER_LINE_BYTES:
                raise fail("OWBM-E-DSC-003", reason="строка заголовка потока превышает предел")
            header_bytes += len(line)
            if header_bytes > MAX_HEADER_BYTES:
                raise fail("OWBM-E-DSC-003", reason="заголовок потока превышает предел 256 КиБ")
            text = line.decode("utf-8", "replace").rstrip("\r\n")
            if text == BODY_MARKER:
                break
            if text:
                header.append(text)
        written = _write_stream_body(proc.stdout, target, max_bytes=max_body_bytes)
        body_started = True
        rc = proc.wait()
        _check_deadline(expired)
        stderr = stderr_capture.read()
        if stderr_capture.overflow:
            raise fail("OWBM-E-DSC-003", reason="stderr SSH превысил предел 1 МиБ")
        if rc != 0:
            _stream_failure(
                client, rc, stderr, stage="передача данных", default=f"код возврата {rc}"
            )
        if written == 0:
            raise fail("OWBM-E-DSC-002", stage="передача данных", reason="устройство вернуло пустой поток")
        probe = parse_probe("\n".join(header))
        completed = True
        return probe, written
    finally:
        if proc.stdout:
            proc.stdout.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        stderr_capture.read()
        cleanup = getattr(proc, "_owbm_env_ctx", None)
        if cleanup is not None:
            cleanup.__exit__(None, None, None)
        timer.cancel()
        if body_started and not completed:
            target.unlink(missing_ok=True)


def send_file(
    client, command: str, src, *, timeout: Optional[int] = None, allow_empty: bool = False
) -> None:
    """Run an explicit remote command and feed it a local file on stdin.

    ``allow_empty`` exists because a legitimate configuration file may be
    zero bytes (OpenWrt ships several such files); payload archives may not.
    """
    import shutil
    from pathlib import Path

    source = Path(src)
    if not source.is_file():
        raise fail("OWBM-E-CHK-002", reason=f"файл не найден: {source.name}")
    if source.stat().st_size == 0 and not allow_empty:
        raise fail("OWBM-E-CHK-002", reason=f"пустой файл {source.name}")
    proc = client.popen_command(command)
    timer, expired = _start_deadline(proc, timeout)
    stdout_capture = _BoundedPipeCapture(
        proc.stdout, on_overflow=lambda: _kill_process(proc)
    )
    stderr_capture = _stderr_capture(proc)
    try:
        assert proc.stdin is not None
        try:
            with open(source, "rb") as handle:
                shutil.copyfileobj(handle, proc.stdin, 1 << 20)
            proc.stdin.close()
        except BrokenPipeError:
            # ssh died mid-transfer: usually the host key changed after restoring
            # /etc/config/dropbear. Classify it so the caller can re-pin and retry.
            rc = proc.wait()
            _check_deadline(expired)
            stderr = stderr_capture.read()
            text = stderr.decode("utf-8", "replace")
            if rc == 255 or "Host key verification failed" in text or "Permission denied" in text:
                from .ssh import _classify_failure

                _classify_failure(text, client.target, rc)
            detail = text.strip().splitlines()
            raise fail(
                "OWBM-E-RST-001",
                step="передача данных на устройство",
                reason=detail[-1] if detail else "соединение прервано во время передачи",
            )
        rc = proc.wait()
        _check_deadline(expired)
        stderr = stderr_capture.read()
        stdout_capture.read()
        if stdout_capture.overflow or stderr_capture.overflow:
            raise fail("OWBM-E-DSC-003", reason="ответ SSH превысил предел захвата 1 МиБ")
        if rc != 0:
            text = stderr.decode("utf-8", "replace")
            if rc == 255 or "Host key verification failed" in text or "Permission denied" in text:
                from .ssh import _classify_failure

                _classify_failure(text, client.target, rc)
            lines = text.strip().splitlines()
            raise fail(
                "OWBM-E-RST-001",
                step="передача данных на устройство",
                reason=lines[-1] if lines else f"код возврата {rc}",
            )
    finally:
        if proc.stdin and not proc.stdin.closed:
            try:
                proc.stdin.close()
            except OSError:
                pass
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        timer.cancel()
        stdout_capture.read()
        stderr_capture.read()
        cleanup = getattr(proc, "_owbm_env_ctx", None)
        if cleanup is not None:
            cleanup.__exit__(None, None, None)
