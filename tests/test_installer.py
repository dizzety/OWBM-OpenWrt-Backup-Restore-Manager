import hashlib
import os
import pty
import select
import signal
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install.sh"


def make_fake_wget(tmp_path):
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    script = fake_bin / "wget"
    script.write_text(
        r'''#!/bin/sh
out=''
url=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        -q) shift ;;
        -O) out=$2; shift 2 ;;
        *) url=$1; shift ;;
    esac
done
name=${url##*/}
if [ "$name" = owbm.pyz.sha256 ] && [ "${OWBM_TEST_BAD_CHECKSUM:-0}" = 1 ]; then
    printf '%064d  owbm.pyz\\n' 0 > "$out"
else
    cp "$OWBM_TEST_RELEASE_DIR/$name" "$out"
fi
''',
        encoding="utf-8",
    )
    script.chmod(0o755)
    return fake_bin


def release_assets(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    release_dir = tmp_path / "release"
    release_dir.mkdir()
    artifact = release_dir / "owbm.pyz"
    subprocess.run(
        ["python3", str(ROOT / "tools" / "build.py"), "--output", str(artifact)],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return release_dir


def run_installer(tmp_path, *, bad_checksum=False):
    release_dir = release_assets(tmp_path)
    fake_bin = make_fake_wget(tmp_path)
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["PATH"] = f"{fake_bin}{os.pathsep}{env.get('PATH', '')}"
    env["OWBM_TEST_RELEASE_DIR"] = str(release_dir)
    if bad_checksum:
        env["OWBM_TEST_BAD_CHECKSUM"] = "1"
    return subprocess.run(
        ["sh", str(INSTALLER)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    ), home


def test_build_writes_sha256_sidecar(tmp_path):
    artifact = tmp_path / "owbm.pyz"
    subprocess.run(
        ["python3", str(ROOT / "tools" / "build.py"), "--output", str(artifact)],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    sidecar = Path(f"{artifact}.sha256")
    expected = hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert sidecar.read_text(encoding="ascii") == f"{expected}  owbm.pyz\n"


def test_installer_has_valid_posix_shell_syntax():
    subprocess.run(["sh", "-n", str(INSTALLER)], check=True, capture_output=True, text=True)


def test_installer_downloads_verifies_and_installs_for_current_user(tmp_path):
    result, home = run_installer(tmp_path)
    installed = home / ".local" / "bin" / "owbm"
    assert result.returncode == 0, result.stderr
    assert installed.is_file()
    assert os.access(installed, os.X_OK)
    assert "OWBM установлен" in result.stdout
    version = subprocess.run([str(installed), "--version"], capture_output=True, text=True, timeout=30)
    assert version.returncode == 0, version.stderr
    assert version.stdout.startswith("owbm ")


def test_bad_checksum_does_not_replace_existing_install(tmp_path):
    run_root = tmp_path / "run"
    home = run_root / "home"
    installed = home / ".local" / "bin" / "owbm"
    installed.parent.mkdir(parents=True)
    installed.write_text("existing user file\n", encoding="utf-8")

    result, returned_home = run_installer(run_root, bad_checksum=True)

    assert returned_home == home
    assert result.returncode != 0
    assert "контрольная сумма не совпала" in result.stderr
    assert installed.read_text(encoding="utf-8") == "existing user file\n"


def run_in_terminal(env, answer="y"):
    pid, terminal = pty.fork()
    if pid == 0:
        os.environ.update(env)
        os.execv("/bin/sh", ["sh", str(INSTALLER)])

    os.write(terminal, f"{answer}\n".encode())
    output = bytearray()
    deadline = time.monotonic() + 120
    status = None
    while status is None and time.monotonic() < deadline:
        readable, _, _ = select.select([terminal], [], [], 0.2)
        if readable:
            try:
                output.extend(os.read(terminal, 4096))
            except OSError:
                pass
        finished, child_status = os.waitpid(pid, os.WNOHANG)
        if finished == pid:
            status = child_status
    if status is None:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        os.close(terminal)
        raise TimeoutError("installer did not finish in the allotted time")
    while True:
        try:
            chunk = os.read(terminal, 4096)
        except OSError:
            break
        if not chunk:
            break
        output.extend(chunk)
    os.close(terminal)
    return os.waitstatus_to_exitcode(status), output.decode("utf-8", "replace")


def dependency_test_env(tmp_path, os_release):
    release_dir = release_assets(tmp_path)
    fake_bin = make_fake_wget(tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    os_release_file = tmp_path / "os-release"
    os_release_file.write_text(os_release, encoding="utf-8")
    package_log = tmp_path / "package-manager.log"
    ready_file = tmp_path / "python-ready"

    (fake_bin / "python3").write_text(
        r'''#!/bin/sh
if [ "${OWBM_TEST_PYTHON_ALWAYS_FAIL:-0}" = 1 ]; then
  exit 1
fi
if [ "${1-}" = -c ] && [ ! -f "$OWBM_TEST_PYTHON_READY" ]; then
  : > "$OWBM_TEST_PYTHON_READY"
  exit 1
fi
exec "$OWBM_TEST_REAL_PYTHON" "$@"
''',
        encoding="utf-8",
    )
    (fake_bin / "python3").chmod(0o755)
    for command in ("apt-get", "dnf", "pacman", "apk"):
        path = fake_bin / command
        path.write_text(
            f'''#!/bin/sh
printf '%s %s\\n' '{command}' "$*" >> "$OWBM_TEST_PACKAGE_LOG"
''',
            encoding="utf-8",
        )
        path.chmod(0o755)
    (fake_bin / "sudo").write_text(
        '''#!/bin/sh
printf 'sudo %s\\n' "$*" >> "$OWBM_TEST_PACKAGE_LOG"
exec "$@"
''',
        encoding="utf-8",
    )
    (fake_bin / "sudo").chmod(0o755)
    (fake_bin / "nix").write_text(
        '''#!/bin/sh
printf 'nix %s\\n' "$*" >> "$OWBM_TEST_PACKAGE_LOG"
if [ -n "${OWBM_TEST_NIX_PROFILE:-}" ]; then
  mkdir -p "$OWBM_TEST_NIX_PROFILE"
  ln -s "$OWBM_TEST_REAL_PYTHON" "$OWBM_TEST_NIX_PROFILE/python3"
  ln -s "$OWBM_TEST_REAL_SSH" "$OWBM_TEST_NIX_PROFILE/ssh"
fi
''',
        encoding="utf-8",
    )
    (fake_bin / "nix").chmod(0o755)

    state_home = tmp_path / "xdg-state"
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(home),
            "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
            "XDG_STATE_HOME": str(state_home),
            "OWBM_OS_RELEASE_FILE": str(os_release_file),
            "OWBM_TEST_NIX_PROFILE": str(state_home / "nix" / "profiles" / "profile" / "bin"),
            "OWBM_TEST_PACKAGE_LOG": str(package_log),
            "OWBM_TEST_PYTHON_READY": str(ready_file),
            "OWBM_TEST_REAL_PYTHON": sys.executable,
            "OWBM_TEST_REAL_SSH": shutil.which("ssh") or "",
            "OWBM_TEST_RELEASE_DIR": str(release_dir),
        }
    )
    if os_release.startswith("ID=nixos"):
        env["OWBM_TEST_PYTHON_ALWAYS_FAIL"] = "1"
    return env, home, package_log


@pytest.mark.parametrize(
    ("os_release", "manager", "expected"),
    [
        ("ID=debian\nVERSION_ID=12\n", "apt-get", "apt-get install -y python3 openssh-client"),
        ("ID=ubuntu\nVERSION_ID=22.04\n", "apt-get", "apt-get install -y python3 openssh-client"),
        ("ID=fedora\nVERSION_ID=42\n", "dnf", "dnf install -y python3 openssh-clients"),
        ("ID=arch\nVERSION_ID=rolling\n", "pacman", "pacman -S --needed --noconfirm python openssh"),
        ("ID=alpine\nVERSION_ID=3.22\n", "apk", "apk add --no-cache python3 openssh-client-default"),
        (
            "ID=nixos\nVERSION_ID=26.05\n",
            "nix",
            "profile install nixpkgs#python3 nixpkgs#openssh",
        ),
    ],
)
def test_installer_uses_expected_dependency_manager(tmp_path, os_release, manager, expected):
    if os.getuid() == 0:
        pytest.skip("installer intentionally refuses to run as root")
    env, home, package_log = dependency_test_env(tmp_path, os_release)
    returncode, output = run_in_terminal(env)
    assert returncode == 0, output
    log = package_log.read_text(encoding="utf-8")
    assert manager in log
    assert expected in log
    assert (home / ".local" / "bin" / "owbm").is_file()


def test_declining_dependency_install_changes_nothing(tmp_path):
    if os.getuid() == 0:
        pytest.skip("installer intentionally refuses to run as root")
    env, _, package_log = dependency_test_env(tmp_path, "ID=debian\nVERSION_ID=12\n")
    returncode, output = run_in_terminal(env, answer="n")
    assert returncode != 0
    assert "установка зависимостей отменена" in output
    assert not package_log.exists()


def test_unsupported_old_ubuntu_stops_before_package_changes(tmp_path):
    if os.getuid() == 0:
        pytest.skip("installer intentionally refuses to run as root")
    env, _, package_log = dependency_test_env(tmp_path, "ID=ubuntu\nVERSION_ID=20.04\n")
    result = subprocess.run(
        ["sh", str(INSTALLER)],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode != 0
    assert "Ubuntu 22.04" in result.stderr
    assert not package_log.exists()


def test_unsupported_derivative_does_not_guess_package_manager(tmp_path):
    if os.getuid() == 0:
        pytest.skip("installer intentionally refuses to run as root")
    env, _, package_log = dependency_test_env(
        tmp_path,
        'ID=linuxmint\nID_LIKE="ubuntu debian"\nVERSION_ID=21.3\n',
    )
    result = subprocess.run(
        ["sh", str(INSTALLER)],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode != 0
    assert "не поддерживается" in result.stderr
    assert not package_log.exists()
