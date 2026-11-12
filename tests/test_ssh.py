import os
import subprocess
import sys
from pathlib import Path

import pytest

from owbm.errors import OwbmError
from owbm.ssh import SSHClient, SSHTarget, UI


class NoUI(UI):
    def __init__(self, answer: bool = False):
        self.answer = answer
        self.messages = []

    def say(self, message: str) -> None:
        self.messages.append(message)

    def ask_yes_no(self, question: str, default: bool = False) -> bool:
        return self.answer


@pytest.fixture
def target(tmp_path) -> SSHTarget:
    return SSHTarget(
        host="192.0.2.10",
        user="root",
        port=2222,
        known_hosts=tmp_path / "known_hosts",
    )


def test_argv_is_strict_by_default(target):
    argv = SSHClient(target).build_argv()
    joined = " ".join(argv)
    assert "StrictHostKeyChecking=yes" in joined
    assert "BatchMode=yes" in joined
    assert "GlobalKnownHostsFile=/dev/null" in joined
    assert f"UserKnownHostsFile={target.known_hosts}" in joined
    assert argv[-2:] == ["root@192.0.2.10", "sh -s"]
    assert "-p" in argv and "2222" in argv


def test_argv_never_contains_password(target):
    client = SSHClient(target, password="super-secret")
    argv = client.build_argv()
    assert "super-secret" not in " ".join(argv)
    assert "BatchMode=yes" not in " ".join(argv)
    assert "PreferredAuthentications=password,keyboard-interactive" in " ".join(argv)


def test_identity_and_jump_options(tmp_path):
    target = SSHTarget(
        host="example.lan", identity_file="~/.ssh/id_test", proxy_jump="jump.lan", known_hosts=tmp_path / "kh"
    )
    argv = SSHClient(target).build_argv()
    assert "-i" in argv
    assert "-J" in argv and "jump.lan" in argv


def test_host_spec_format(tmp_path):
    assert SSHTarget(host="a.lan", port=22, known_hosts=tmp_path / "kh").spec == "a.lan"
    assert SSHTarget(host="a.lan", port=2222, known_hosts=tmp_path / "kh").spec == "[a.lan]:2222"


def test_password_helper_is_private_and_removed(target):
    client = SSHClient(target, password="p@ss")
    with client._password_env() as env:
        assert env is not None
        secret = Path(env["OWBM_ASKPASS_FILE"])
        helper = Path(env["SSH_ASKPASS"])
        assert secret.read_text() == "p@ss"
        assert (secret.stat().st_mode & 0o077) == 0
        assert helper.exists()
        assert env["SSH_ASKPASS_REQUIRE"] == "force"
    assert not secret.exists()
    assert not helper.exists()
    assert not helper.parent.exists()


@pytest.fixture
def key_line(tmp_path):
    keyPath = tmp_path / "testkey"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "test@owbm", "-f", str(keyPath)],
        check=True,
        capture_output=True,
    )
    return (tmp_path / "testkey.pub").read_text().strip()


def test_ensure_host_key_requires_confirmation(target, key_line, monkeypatch):
    client = SSHClient(target)
    monkeypatch.setattr(
        SSHClient, "scan_host_keys", lambda self: [("ssh-ed25519", f"{target.spec} {key_line}")]
    )
    with pytest.raises(OwbmError) as exc:
        client.ensure_host_key(ui=NoUI(answer=False))
    assert exc.value.code == "OWBM-E-SSH-006"
    assert not target.known_hosts.exists()


def test_ensure_host_key_pins_on_acceptance(target, key_line, monkeypatch):
    client = SSHClient(target)
    monkeypatch.setattr(
        SSHClient, "scan_host_keys", lambda self: [("ssh-ed25519", f"{target.spec} {key_line}")]
    )
    info = client.ensure_host_key(ui=NoUI(answer=True))
    assert info["fingerprint"].startswith("SHA256:")
    assert target.known_hosts.exists()
    assert (target.known_hosts.stat().st_mode & 0o077) == 0
    assert client.check_known_host() is True
    # second call is a no-op
    assert client.ensure_host_key(ui=NoUI(answer=False)) is None


def test_initial_trust_displays_and_pins_all_scanned_keys(target, key_line, monkeypatch):
    client = SSHClient(target)
    candidate = f"{target.spec} {key_line}"
    monkeypatch.setattr(
        SSHClient,
        "scan_host_keys",
        lambda self: [("ssh-ed25519", candidate), ("ssh-ed25519", candidate + " other")],
    )
    ui = NoUI(answer=True)

    client.ensure_host_key(ui=ui)

    assert target.known_hosts.read_text(encoding="utf-8").splitlines() == [candidate, candidate + " other"]
    assert sum("SHA256:" in message for message in ui.messages) == 2


def test_repin_uses_all_exact_confirmed_keys_without_rescanning(target, key_line, monkeypatch):
    client = SSHClient(target)
    candidates = [
        ("ssh-ed25519", f"{target.spec} {key_line}"),
        ("ssh-ed25519", f"{target.spec} {key_line} other"),
    ]
    monkeypatch.setattr(client, "scan_host_keys", lambda: pytest.fail("unexpected rescan"))

    info = client.repin_host_key(keys=candidates)

    assert info["fingerprint"].startswith("SHA256:")
    assert len(info["fingerprints"]) == 2
    assert target.known_hosts.read_text(encoding="utf-8").splitlines() == [line for _kind, line in candidates]


def test_strict_policy_refuses_without_accept(target, key_line, monkeypatch):
    strict = SSHTarget(host=target.host, port=target.port, known_hosts=target.known_hosts, host_key_policy="strict")
    client = SSHClient(strict)
    monkeypatch.setattr(
        SSHClient, "scan_host_keys", lambda self: [("ssh-ed25519", f"{strict.spec} {key_line}")]
    )
    with pytest.raises(OwbmError) as exc:
        client.ensure_host_key(ui=NoUI(answer=True))
    assert exc.value.code == "OWBM-E-SSH-006"


def test_known_hosts_check_on_empty_file(target):
    assert SSHClient(target).check_known_host() is False
    target.known_hosts.write_text("", encoding="utf-8")
    assert SSHClient(target).check_known_host() is False


@pytest.mark.parametrize("stream_name", ("stdout", "stderr"))
def test_run_stops_when_ssh_output_exceeds_limit(target, tmp_path, monkeypatch, stream_name):
    fake_ssh = tmp_path / "fake-ssh"
    destination = "sys.stdout" if stream_name == "stdout" else "sys.stderr"
    fake_ssh.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "sys.stdin.buffer.read()\n"
        f"{destination}.buffer.write(b'x' * 128)\n",
        encoding="utf-8",
    )
    fake_ssh.chmod(0o755)
    monkeypatch.setattr("owbm.ssh.which", lambda name: str(fake_ssh) if name == "ssh" else None)
    monkeypatch.setattr("owbm.ssh.MAX_CAPTURE_STDOUT_BYTES", 32)
    monkeypatch.setattr("owbm.ssh.MAX_CAPTURE_STDERR_BYTES", 32)

    with pytest.raises(OwbmError) as exc:
        SSHClient(target).run("printf test")

    assert exc.value.code == "OWBM-E-DSC-003"


def test_failure_classification():
    from owbm.ssh import _classify_failure

    target = SSHTarget(host="192.0.2.10", known_hosts=Path("/tmp/kh"))
    with pytest.raises(OwbmError) as exc:
        _classify_failure("Host key verification failed.", target, 255)
    assert exc.value.code == "OWBM-E-SSH-003"

    with pytest.raises(OwbmError) as exc:
        _classify_failure("root@192.0.2.10: Permission denied (publickey).", target, 255)
    assert exc.value.code == "OWBM-E-SSH-004"

    with pytest.raises(OwbmError) as exc:
        _classify_failure("ssh: connect to host 192.0.2.10 port 22: Connection refused", target, 255)
    assert exc.value.code == "OWBM-E-SSH-002"
    assert "Порт закрыт" in exc.value.why
