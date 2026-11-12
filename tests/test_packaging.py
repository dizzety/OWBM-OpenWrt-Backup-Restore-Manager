import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import build as builder  # noqa: E402

from owbm import __version__, config as cfgmod  # noqa: E402


@pytest.fixture(scope="module")
def artifact(tmp_path_factory):
    target = tmp_path_factory.mktemp("dist") / "owbm.pyz"
    return builder.build(target)


def test_artifact_is_single_executable_file(artifact):
    assert artifact.is_file()
    assert os.access(artifact, os.X_OK)
    assert artifact.read_bytes().startswith(b"#!/usr/bin/env python3\n")


def test_artifact_contains_only_the_package(artifact):
    with zipfile.ZipFile(artifact) as zf:
        names = zf.namelist()
    assert "__main__.py" in names
    assert "owbm/cli.py" in names
    assert "owbm/menu.py" in names
    assert all(name.startswith("owbm/") or name == "__main__.py" for name in names)
    assert not any("__pycache__" in name or name.endswith(".pyc") for name in names)


def test_artifact_has_no_build_machine_paths(artifact):
    assert builder.inspect(artifact) == []


def test_smoke_test_passes(artifact):
    assert builder.smoke(artifact) == []


def test_runs_from_directory_with_spaces(tmp_path, artifact):
    workdir = tmp_path / "каталог с пробелами"
    workdir.mkdir()
    target = workdir / "owbm.pyz"
    target.write_bytes(artifact.read_bytes())
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(tmp_path / "home"),
        "XDG_CONFIG_HOME": str(tmp_path / "cfg"),
        "XDG_DATA_HOME": str(tmp_path / "data"),
        "XDG_STATE_HOME": str(tmp_path / "state"),
        "XDG_CACHE_HOME": str(tmp_path / "cache"),
    }
    (tmp_path / "home").mkdir()
    proc = subprocess.run(
        [sys.executable, "owbm.pyz", "version"],
        cwd=str(workdir),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert __version__ in proc.stdout


def test_runs_without_source_tree(tmp_path, artifact):
    """The artifact must not need the repository, the venv or the config file."""
    isolated = tmp_path / "elsewhere"
    isolated.mkdir()
    shutil_target = isolated / "owbm.pyz"
    shutil_target.write_bytes(artifact.read_bytes())
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(tmp_path / "home2"),
        "XDG_CONFIG_HOME": str(tmp_path / "cfg2"),
        "XDG_DATA_HOME": str(tmp_path / "data2"),
        "XDG_STATE_HOME": str(tmp_path / "state2"),
        "XDG_CACHE_HOME": str(tmp_path / "cache2"),
    }
    (tmp_path / "home2").mkdir()
    proc = subprocess.run(
        [sys.executable, str(shutil_target), "config-show"],
        cwd=str(isolated),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert "[general]" in proc.stdout
    assert "не найден" in proc.stdout  # no config file is a normal state


def test_menu_runs_from_artifact(tmp_path, artifact):
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(tmp_path / "home"),
        "XDG_CONFIG_HOME": str(tmp_path / "cfg"),
        "XDG_DATA_HOME": str(tmp_path / "data"),
        "XDG_STATE_HOME": str(tmp_path / "state"),
        "XDG_CACHE_HOME": str(tmp_path / "cache"),
    }
    (tmp_path / "home").mkdir()
    proc = subprocess.run(
        [sys.executable, str(artifact), "menu"],
        input="9\n",
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert "Главное меню" in proc.stdout
    assert "До свидания" in proc.stdout


def test_example_config_is_in_sync():
    example = ROOT / "config.example.toml"
    assert example.is_file()
    assert example.read_text(encoding="utf-8") == cfgmod.EXAMPLE
    parsed = cfgmod.tomlmini.loads(example.read_text(encoding="utf-8"))
    assert cfgmod.from_mapping(parsed).devices["example"].host == "192.0.2.1"


def test_pyproject_metadata_matches_version():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert f'version = "{__version__}"' in text
    assert "requires-python = \">=3.9\"" in text


def test_entry_script_is_portable():
    text = (ROOT / "openwrt-brm").read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env python3")
    assert "/home/" not in text
    assert str(ROOT) not in text


def test_sources_have_no_build_machine_paths():
    local_paths = {str(Path.home()), str(ROOT.resolve())}
    for path in (ROOT / "src").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for local_path in local_paths:
            if local_path and local_path != "/":
                assert local_path not in text, path


def test_piped_output_is_quiet(tmp_path, artifact):
    """`owbm list | head` must not print a traceback."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(tmp_path / "home"),
        "XDG_CONFIG_HOME": str(tmp_path / "cfg"),
        "XDG_DATA_HOME": str(tmp_path / "data"),
        "XDG_STATE_HOME": str(tmp_path / "state"),
        "XDG_CACHE_HOME": str(tmp_path / "cache"),
    }
    (tmp_path / "home").mkdir()
    pipeline = f'"{sys.executable}" "{artifact}" config-show | head -n 2'
    proc = subprocess.run(pipeline, shell=True, env=env, capture_output=True, text=True, timeout=120)
    assert "[general]" in proc.stdout
    assert "Traceback" not in proc.stderr
    assert "BrokenPipeError" not in proc.stderr


def test_launcher_finds_python(tmp_path, artifact):
    launcher = builder.build_launcher(artifact)
    assert launcher.is_file()
    assert os.access(launcher, os.X_OK)
    launcher_text = launcher.read_text(encoding="utf-8")
    assert launcher_text.startswith("#!/bin/sh")
    assert "$HOME/" not in launcher_text
    assert "/home/" not in launcher_text
    assert "/Users/" not in launcher_text

    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(tmp_path / "home"),
        "XDG_CONFIG_HOME": str(tmp_path / "cfg"),
        "XDG_DATA_HOME": str(tmp_path / "data"),
        "XDG_STATE_HOME": str(tmp_path / "state"),
        "XDG_CACHE_HOME": str(tmp_path / "cache"),
    }
    (tmp_path / "home").mkdir()
    proc = subprocess.run([str(launcher), "--version"], env=env, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert __version__ in proc.stdout


def test_launcher_explains_missing_python(tmp_path, artifact):
    launcher = builder.build_launcher(artifact)
    env = {"PATH": "/nonexistent", "HOME": str(tmp_path / "empty-home")}
    (tmp_path / "empty-home").mkdir()
    proc = subprocess.run([str(launcher), "--version"], env=env, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 127
    assert "не найден Python 3" in proc.stderr
    assert "apt install python3" in proc.stderr
