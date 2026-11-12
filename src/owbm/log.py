"""Logging, redaction and the operation journal.

Two sinks: user-facing output (stdout/stderr) and a private debug log with mode
0600. Secrets are redacted at the sink, so no call site can leak them by mistake.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, TextIO

_REDACT_RULES = (
    re.compile(
        r"(?i)\b(password|passwd|passphrase|psk|secret|token|api[_-]?key|private[_-]?key)\b"
        r"(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|\S+)"
    ),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"(?i)\b(ssh-(rsa|ed25519|dss)|ecdsa-sha2-nistp\d+)\s+AAAA[0-9A-Za-z+/=]+"),
)


def redact(text: str) -> str:
    if not text:
        return text
    result = _REDACT_RULES[0].sub(lambda m: f"{m.group(1)}{m.group(2)}***", text)
    result = _REDACT_RULES[1].sub("[приватный ключ скрыт]", result)
    result = _REDACT_RULES[2].sub(lambda m: f"{m.group(1)} AAAA***", result)
    return result


@dataclass
class JournalEntry:
    name: str
    status: str  # start | ok | fail | skip | warn
    detail: str = ""
    at: str = ""

    def as_dict(self) -> Dict[str, str]:
        return {"step": self.name, "status": self.status, "detail": self.detail, "at": self.at}


class Journal:
    """Ordered record of operation steps, used for partial-failure reports."""

    def __init__(self) -> None:
        self.entries: List[JournalEntry] = []

    def _add(self, name: str, status: str, detail: str = "") -> None:
        self.entries.append(
            JournalEntry(
                name=name,
                status=status,
                detail=redact(detail),
                at=datetime.now(timezone.utc).strftime("%H:%M:%SZ"),
            )
        )

    def start(self, name: str, detail: str = "") -> None:
        self._add(name, "start", detail)

    def ok(self, name: str, detail: str = "") -> None:
        self._add(name, "ok", detail)

    def fail(self, name: str, detail: str = "") -> None:
        self._add(name, "fail", detail)

    def skip(self, name: str, detail: str = "") -> None:
        self._add(name, "skip", detail)

    def warn(self, name: str, detail: str = "") -> None:
        self._add(name, "warn", detail)

    def failed_steps(self) -> List[str]:
        return [e.name for e in self.entries if e.status == "fail"]

    def completed_steps(self) -> List[str]:
        return [e.name for e in self.entries if e.status == "ok"]

    def as_list(self) -> List[Dict[str, str]]:
        return [entry.as_dict() for entry in self.entries]


def _prune_logs(directory: Path, keep: int = 20) -> None:
    """Keep the state directory tidy: only the newest logs survive."""
    try:
        logs = sorted(directory.glob("owbm-*.log"), key=lambda item: item.stat().st_mtime, reverse=True)
    except OSError:
        return
    for stale in logs[keep:]:
        try:
            stale.unlink()
        except OSError:
            pass


class Logger:
    def __init__(
        self,
        *,
        verbose: bool = False,
        quiet: bool = False,
        json_mode: bool = False,
        log_dir: Optional[Path] = None,
        stream: Optional[TextIO] = None,
    ) -> None:
        self.verbose = verbose
        self.quiet = quiet
        self.json_mode = json_mode
        self.stream = stream or sys.stderr
        self.journal = Journal()
        self._log_file: Optional[TextIO] = None
        self.path: Optional[Path] = None
        if log_dir is not None and not json_mode:
            try:
                log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                _prune_logs(log_dir)
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                self.path = log_dir / f"owbm-{stamp}-{os.getpid()}.log"
                fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                self._log_file = os.fdopen(fd, "w", encoding="utf-8")
            except OSError:
                self._log_file = None
                self.path = None

    # -- sinks -------------------------------------------------------------
    def _write(self, text: str) -> None:
        message = redact(text)
        if self._log_file is not None:
            try:
                self._log_file.write(
                    f"{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} {message}\n"
                )
                self._log_file.flush()
            except OSError:
                pass
        if not self.json_mode:
            print(message, file=self.stream, flush=True)

    def _emit(self, prefix: str, message: str) -> None:
        if self.json_mode:
            self._write(f"{prefix}{message}")
            return
        for line in message.splitlines() or [""]:
            self._write(f"{prefix}{line}" if prefix else line)

    # -- levels ------------------------------------------------------------
    def debug(self, message: str) -> None:
        if self.verbose:
            self._emit("· ", message)

    def info(self, message: str) -> None:
        if not self.quiet:
            self._emit("", message)

    def ok(self, message: str) -> None:
        self._emit("✓ ", message)

    def warn(self, message: str) -> None:
        self._emit("! ", message)

    def error(self, message: str) -> None:
        self._emit("✗ ", message)

    def step(self, message: str) -> None:
        if not self.quiet:
            self._emit("", "")
            self._emit("▸ ", message)

    def raw(self, message: str) -> None:
        """Output that belongs to the program result (stdout), not diagnostics."""
        if not self.json_mode:
            print(redact(message), flush=True)

    def close(self) -> None:
        if self._log_file is not None:
            try:
                self._log_file.close()
            except OSError:
                pass
            self._log_file = None

    def __enter__(self) -> "Logger":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()
