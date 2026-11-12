#!/usr/bin/env python3
"""Build a single-file OWBM distribution (zipapp) and smoke-test it.

The result is one executable file that needs nothing but python3: no source
tree, no virtualenv, no dependencies, no files from the build machine.

    python3 tools/build.py            -> dist/owbm.pyz
    python3 tools/build.py --check    -> also run it from a temporary directory
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
DEFAULT_OUTPUT = ROOT / "dist" / "owbm.pyz"
IGNORED = ("__pycache__", "*.pyc", "*.pyo", ".DS_Store")


def build(output: Path) -> Path:
    if not (SRC / "owbm" / "cli.py").is_file():
        raise SystemExit(f"не найден пакет owbm в {SRC}")
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    checksum = Path(f"{output}.sha256")
    for stale in (output, output.with_suffix(".pyz.tmp"), checksum):
        if stale.exists():
            stale.unlink()
    with tempfile.TemporaryDirectory(prefix="owbm-build-") as tmp:
        staging = Path(tmp) / "app"
        shutil.copytree(SRC, staging, ignore=shutil.ignore_patterns(*IGNORED))
        zipapp.create_archive(
            staging,
            target=output,
            interpreter="/usr/bin/env python3",
            main="owbm.cli:main",
            compressed=True,
        )
    os.chmod(output, 0o755)
    digest = hashlib.sha256()
    with output.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    checksum.write_text(f"{digest.hexdigest()}  {output.name}\n", encoding="ascii")
    return output


LAUNCHER = """#!/bin/sh
# OWBM launcher: находит Python 3 и запускает приложение рядом с собой.
# Создаётся tools/build.py; приложение — соседний файл owbm.pyz.
set -u
case "$0" in
    */*) here=$(CDPATH= cd -- "${0%/*}" && pwd) ;;
    *)   here=$(CDPATH= cd -- . && pwd) ;;
esac

for candidate in python3 python3.13 python3.12 python3.11 python3.10 python3.9; do
    if command -v "$candidate" >/dev/null 2>&1; then
        exec "$candidate" "$here/owbm.pyz" "$@"
    fi
done

for candidate in /usr/bin/python3 /usr/local/bin/python3; do
    if [ -x "$candidate" ]; then
        exec "$candidate" "$here/owbm.pyz" "$@"
    fi
done

printf '%s\n' \
    "OWBM: не найден Python 3 (нужен 3.9 или новее)." \
    "" \
    "Установите его:" \
    "  Debian/Ubuntu:  sudo apt install python3" \
    "  Fedora:         sudo dnf install python3" \
    "  Arch:           sudo pacman -S python" \
    "  Alpine:         sudo apk add python3" \
    "  NixOS:          nix profile install nixpkgs#python3" \
    "" \
    "После установки проверьте: python3 --version" >&2
exit 127
"""


def build_launcher(output: Path) -> Path:
    launcher = Path(output).with_name("owbm")
    launcher.write_text(LAUNCHER, encoding="utf-8")
    os.chmod(launcher, 0o755)
    return launcher


def inspect(archive: Path) -> list[str]:
    problems: list[str] = []
    with zipfile.ZipFile(archive) as zf:
        names = zf.namelist()
        if "__main__.py" not in names:
            problems.append("нет __main__.py: архив не запускается как программа")
        handlers = [name for name in names if not name.startswith("owbm/") and name != "__main__.py"]
        if handlers:
            problems.append(f"посторонние элементы: {handlers[:3]}")
        for name in names:
            if name.endswith(".pyc") or "__pycache__" in name:
                problems.append(f"в сборку попал кэш: {name}")
        for name in names:
            if not name.endswith(".py"):
                continue
            text = zf.read(name).decode("utf-8", "replace")
            for marker in ("/home/", "/Users/", "C:\\Users", str(ROOT)):
                if marker in text:
                    problems.append(f"{name} содержит путь сборочной машины: {marker}")
                    break
    return problems


def smoke(archive: Path) -> list[str]:
    problems: list[str] = []
    with tempfile.TemporaryDirectory(prefix="owbm smoke test ") as tmp:
        workspace = Path(tmp) / "with spaces" / "owbm.pyz"
        workspace.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(archive, workspace)
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(Path(tmp) / "home"),
            "TMPDIR": str(Path(tmp)),
            "XDG_CONFIG_HOME": str(Path(tmp) / "cfg"),
            "XDG_DATA_HOME": str(Path(tmp) / "data"),
            "XDG_STATE_HOME": str(Path(tmp) / "state"),
            "XDG_CACHE_HOME": str(Path(tmp) / "cache"),
        }
        Path(env["HOME"]).mkdir(parents=True, exist_ok=True)
        checks = (
            (["--version"], "owbm "),
            (["config-show"], "[general]"),
            (["doctor"], "Диагностика"),
        )
        for args, expected in checks:
            proc = subprocess.run(
                [sys.executable, str(workspace)] + args,
                capture_output=True,
                text=True,
                env=env,
                cwd=str(workspace.parent),
                timeout=120,
            )
            output = proc.stdout + proc.stderr
            if expected not in output:
                problems.append(f"{' '.join(args)}: неожиданный вывод ({output[:120]!r})")
            if proc.returncode not in (0, 2, 3):
                problems.append(f"{' '.join(args)}: код {proc.returncode}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Сборка одиночного файла OWBM")
    parser.add_argument("-o", "--output", default=str(DEFAULT_OUTPUT), help="путь к результату")
    parser.add_argument("--check", action="store_true", help="проверить сборку запуском")
    args = parser.parse_args(argv)

    archive = build(Path(args.output))
    launcher = build_launcher(archive)
    size = archive.stat().st_size
    problems = inspect(archive)
    if not os.access(launcher, os.X_OK):
        problems.append(f"обёртка {launcher} не исполняемая")
    if args.check:
        problems.extend(smoke(archive))

    if problems:
        print("Сборка не прошла проверку:", file=sys.stderr)
        for item in problems:
            print(f"  ✗ {item}", file=sys.stderr)
        return 1
    checksum = Path(f"{archive}.sha256")
    print(f"Готово: {archive} ({size / 1024:.0f} КиБ), SHA-256 {checksum} и обёртка {launcher}")
    print(f"Запуск: {launcher}    (сама находит python3)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
