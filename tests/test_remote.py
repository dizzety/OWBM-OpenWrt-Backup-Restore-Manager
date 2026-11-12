from pathlib import Path
import subprocess
import sys

import pytest

from owbm.errors import OwbmError
from owbm.remote import build_script, parse_probe, send_file, stream_framed, stream_tar, stream_to_file


def test_parses_scalars_and_multivalue():
    probe = parse_probe("A=1\nB=x\nA=2\n")
    assert probe.one("A") == "2"
    assert probe.all("A") == ["1", "2"]
    assert probe.has("B")
    assert not probe.has("C")
    assert probe.one("C", "fallback") == "fallback"


def test_value_may_contain_equals_and_spaces():
    probe = parse_probe("MOUNT=22 1 0:26 / / rw - overlay overlay rw,lowerdir=/rom\n")
    assert probe.one("MOUNT").endswith("lowerdir=/rom")


def test_empty_lines_ignored():
    probe = parse_probe("\n\nA=1\n\n")
    assert probe.one("A") == "1"


def test_malformed_lines_are_recorded_not_trusted():
    probe = parse_probe("A=1\nnot a pair\n=B\nbad key!=v\n")
    assert probe.one("A") == "1"
    assert len(probe.malformed) == 3


def test_control_characters_rejected():
    probe = parse_probe("A=ok\nB=bad\x00value\nC=bad\x1bvalue\n")
    assert probe.all("A") == ["ok"]
    assert not probe.has("B")
    assert not probe.has("C")
    assert len(probe.malformed) == 2


def test_key_length_limited():
    long_key = "K" * 100
    probe = parse_probe(f"{long_key}=v\n")
    assert not probe.has(long_key)
    assert probe.malformed


def test_value_length_limited():
    probe = parse_probe("A=" + "x" * 9000 + "\n")
    assert not probe.has("A")


def test_int_and_text_helpers():
    probe = parse_probe("N=42\nN=bad\nT=a\nT=b\n")
    assert probe.int_or_none("N") is None
    probe2 = parse_probe("N=42\n")
    assert probe2.int_or_none("N") == 42
    assert probe2.int_or_none("missing") is None
    assert parse_probe("T=a\nT=b\n").text("T") == "a\nb"


def test_build_script_prefixes_root():
    script = build_script("echo hi\n", root="/tmp/fake device")
    assert script.startswith("OWBM_ROOT='/tmp/fake device'\n")
    assert "export OWBM_ROOT" in script
    assert script.endswith("echo hi\n")


def test_build_script_without_root_is_empty_prefix():
    script = build_script("echo hi\n")
    assert script.startswith("OWBM_ROOT=''\n")


def test_parser_is_bounded():
    with pytest.raises(OwbmError):
        parse_probe("".join(f"K={i}\n" for i in range(210_000)))


def test_parser_enforces_actual_byte_limit(monkeypatch):
    monkeypatch.setattr("owbm.remote.MAX_TOTAL", 100)
    text = "A=" + "x" * 68 + "\n" + "B=" + "y" * 68 + "\n"
    with pytest.raises(OwbmError) as exc:
        parse_probe(text)
    assert exc.value.code == "OWBM-E-DSC-003"


def test_parser_counts_utf8_bytes(monkeypatch):
    monkeypatch.setattr("owbm.remote.MAX_TOTAL", 10)
    with pytest.raises(OwbmError) as exc:
        parse_probe("A=ééééé\n")
    assert exc.value.code == "OWBM-E-DSC-003"


class _StreamingClient:
    def __init__(self, code):
        self.code = code

    def popen(self, _script):
        return subprocess.Popen(
            [sys.executable, "-c", self.code],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def popen_command(self, command):
        return subprocess.Popen(
            [sys.executable, "-c", command],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )


@pytest.mark.parametrize("framed", [False, True])
def test_disk_streaming_enforces_body_byte_limit(tmp_path, monkeypatch, framed):
    monkeypatch.setattr("owbm.remote.MAX_STREAM_BODY_BYTES", 4)
    monkeypatch.setattr("owbm.remote.STREAM_DISK_RESERVE_BYTES", 0)
    output = tmp_path / "oversized-payload"
    body = "import sys; sys.stdout.buffer.write(b'__OWBM_BODY__\\n12345')" if framed else (
        "import sys; sys.stdout.buffer.write(b'12345')"
    )
    client = _StreamingClient(body)

    with pytest.raises(OwbmError) as exc:
        if framed:
            stream_framed(client, "", output)
        else:
            stream_to_file(client, "", output)

    assert exc.value.code == "OWBM-E-DSC-003"
    assert not output.exists()


def test_disk_streaming_reserves_local_space(tmp_path, monkeypatch):
    class Usage:
        free = 10

    monkeypatch.setattr("owbm.remote.STREAM_DISK_RESERVE_BYTES", 100)
    monkeypatch.setattr("owbm.remote.shutil.disk_usage", lambda _path: Usage())
    client = _StreamingClient("import sys; sys.stdout.buffer.write(b'__OWBM_BODY__\\nx')")
    output = tmp_path / "space-limited-payload"

    with pytest.raises(OwbmError) as exc:
        stream_framed(client, "", output)

    assert exc.value.code == "OWBM-E-DSC-003"
    assert not output.exists()


def test_stream_framed_rejects_oversized_header_line(tmp_path, monkeypatch):
    monkeypatch.setattr("owbm.remote.MAX_HEADER_LINE_BYTES", 16)
    client = _StreamingClient("import sys; sys.stdout.buffer.write(b'A=' + b'x'*100 + b'\\n')")

    with pytest.raises(OwbmError) as exc:
        stream_framed(client, "", tmp_path / "payload")

    assert exc.value.code == "OWBM-E-DSC-003"
    assert not (tmp_path / "payload").exists()


def test_stream_framed_rejects_oversized_header_total(tmp_path, monkeypatch):
    monkeypatch.setattr("owbm.remote.MAX_HEADER_LINE_BYTES", 128)
    monkeypatch.setattr("owbm.remote.MAX_HEADER_BYTES", 32)
    client = _StreamingClient(
        "import sys; sys.stdout.buffer.write(b'A=' + b'x'*20 + b'\\nB=' + b'y'*20 + b'\\n')"
    )

    with pytest.raises(OwbmError) as exc:
        stream_framed(client, "", tmp_path / "payload")

    assert exc.value.code == "OWBM-E-DSC-003"


def test_stderr_overflow_aborts_stream_process(tmp_path, monkeypatch):
    killed = []
    monkeypatch.setattr("owbm.remote.MAX_STREAM_STDERR_BYTES", 64)
    monkeypatch.setattr("owbm.remote._kill_process", lambda proc: killed.append(proc))
    client = _StreamingClient(
        "import sys; sys.stderr.buffer.write(b'x'*100000); sys.stderr.flush(); "
        "sys.stdout.buffer.write(b'__OWBM_BODY__\\nx')"
    )

    with pytest.raises(OwbmError) as exc:
        stream_framed(client, "", tmp_path / "stderr-overflow")

    assert exc.value.code == "OWBM-E-DSC-003"
    assert killed


def test_stream_timeout_kills_stalled_command(tmp_path, monkeypatch):
    monkeypatch.setattr("owbm.remote.DEFAULT_STREAM_TIMEOUT_SECONDS", 0.02)
    client = _StreamingClient("import time; time.sleep(5)")

    with pytest.raises(OwbmError) as exc:
        stream_framed(client, "", tmp_path / "stalled-payload")

    assert exc.value.code == "OWBM-E-DSC-003"
    assert "время" in exc.value.what.lower()
    assert not (tmp_path / "stalled-payload").exists()


def test_send_file_enforces_timeout(tmp_path, monkeypatch):
    monkeypatch.setattr("owbm.remote.DEFAULT_STREAM_TIMEOUT_SECONDS", 0.02)
    source = tmp_path / "source.bin"
    source.write_bytes(b"x")
    client = _StreamingClient("import time; time.sleep(5)")

    with pytest.raises(OwbmError) as exc:
        send_file(client, "import time; time.sleep(5)", source)

    assert exc.value.code == "OWBM-E-DSC-003"


def test_stream_stderr_is_drained_and_bounded(monkeypatch):
    monkeypatch.setattr("owbm.remote.MAX_STREAM_STDERR_BYTES", 64)
    client = _StreamingClient("import sys; sys.stderr.buffer.write(b'x'*1000000); sys.stderr.flush()")

    with pytest.raises(OwbmError) as exc:
        list(stream_tar(client, ""))

    assert exc.value.code == "OWBM-E-DSC-003"


def test_ssh_failure_is_classified_not_masked():
    """A permission error must not be reported as a discovery failure."""
    from owbm.remote import run_probe
    from owbm.ssh import RunResult, SSHTarget

    class FailingClient:
        target = SSHTarget(host="192.0.2.1", known_hosts=Path("/tmp/kh"))

        def run(self, script, *, timeout=None, allow_failure=False, stdin_bytes=None):
            return RunResult(255, b"", "root@192.0.2.1: Permission denied (publickey,password).")

    with pytest.raises(OwbmError) as exc:
        run_probe(FailingClient(), "echo hi")
    assert exc.value.code == "OWBM-E-SSH-004"
    assert "аутентификац" in exc.value.what.lower()
