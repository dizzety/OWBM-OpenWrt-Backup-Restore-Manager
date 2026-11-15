#!/bin/sh
# Install the latest published OWBM release for the current user.
set -eu
umask 077

REPOSITORY='dizzety/OWBM-OpenWrt-Backup-Restore-Manager'
RELEASE_BASE="https://github.com/$REPOSITORY/releases/latest/download"

locale_hint=${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}
case "$locale_hint" in
    ru*|RU*) UI_LANG=ru ;;
    en*|EN*) UI_LANG=en ;;
    *) UI_LANG=ru ;;
esac

message() {
    key=$1
    shift || true
    case "$key" in
        linux) ru='установщик поддерживает Linux.'; en='the installer supports Linux.' ;;
        not_root) ru='запустите установщик обычным пользователем, не через sudo.'; en='run the installer as a regular user, not through sudo.' ;;
        home) ru='не найдена домашняя папка пользователя.'; en='the user home directory was not found.' ;;
        wget) ru='для загрузки нужен wget.'; en='wget is required for downloading.' ;;
        mktemp) ru='не найдена команда mktemp.'; en='mktemp was not found.' ;;
        temp_dir) ru='не удалось создать временную папку.'; en='could not create a temporary directory.' ;;
        archive_download) ru='не удалось скачать owbm.pyz; проверьте, опубликован ли релиз.'; en='could not download owbm.pyz; check whether a release is published.' ;;
        checksum_download) ru='не удалось скачать контрольную сумму релиза.'; en='could not download the release checksum.' ;;
        os_release) if [ "$UI_LANG" = en ]; then printf 'could not read %s.' "$1"; else printf 'не удалось прочитать %s.' "$1"; fi; return ;;
        unsupported_os) if [ "$UI_LANG" = en ]; then printf 'automatic dependency installation for %s is unsupported; supported systems: NixOS, Debian, Ubuntu, Fedora, Arch, and Alpine.' "$1"; else printf 'автоустановка зависимостей для %s не поддерживается; поддерживаются NixOS, Debian, Ubuntu, Fedora, Arch и Alpine.' "$1"; fi; return ;;
        ubuntu_version) ru='для автоматической установки требуется Ubuntu 22.04 или новее.'; en='automatic installation requires Ubuntu 22.04 or later.' ;;
        debian_version) ru='для автоматической установки требуется Debian 11 или новее.'; en='automatic installation requires Debian 11 or later.' ;;
        fedora_version) ru='для автоматической установки требуется Fedora с Python 3.9 или новее (Fedora 34+).'; en='automatic installation requires Fedora with Python 3.9 or later (Fedora 34+).' ;;
        alpine_version) ru='для автоматической установки требуется Alpine 3.15 или новее.'; en='automatic installation requires Alpine 3.15 or later.' ;;
        missing_command) if [ "$UI_LANG" = en ]; then printf 'required command not found: %s.' "$1"; else printf 'не найдена обязательная команда %s.' "$1"; fi; return ;;
        privilege) ru='нужна команда sudo или doas для установки системных зависимостей.'; en='sudo or doas is required to install system dependencies.' ;;
        tty) ru='для подтверждения установки нужен терминал; скачайте install.sh в файл и запустите его вручную.'; en='a terminal is required for confirmation; download install.sh and run it manually.' ;;
        requirements) ru='Для OWBM нужны Python 3.9+ и SSH-клиент.'; en='OWBM requires Python 3.9+ and an SSH client.' ;;
        confirm_install) if [ "$UI_LANG" = en ]; then printf 'Install missing dependencies for the detected system (%s)? [y/N] ' "$1"; else printf 'Установить недостающие зависимости для обнаруженной системы (%s)? [д/Н] ' "$1"; fi; return ;;
        confirmation_read) ru='не удалось прочитать подтверждение.'; en='could not read the confirmation.' ;;
        cancelled) ru='установка зависимостей отменена.'; en='dependency installation was cancelled.' ;;
        nix_install) ru='не удалось установить зависимости через nix profile.'; en='could not install dependencies through the Nix profile.' ;;
        python_after) ru='после установки не найден Python 3.9 или новее.'; en='Python 3.9 or later was not found after installation.' ;;
        ssh_after) ru='после установки не найден SSH-клиент.'; en='an SSH client was not found after installation.' ;;
        launch_download) ru='загруженный файл не прошёл проверку запуска.'; en='the downloaded file failed its startup check.' ;;
        destination) if [ "$UI_LANG" = en ]; then printf '%s exists and is not a regular file.' "$1"; else printf '%s существует и не является обычным файлом.' "$1"; fi; return ;;
        mkdir) if [ "$UI_LANG" = en ]; then printf 'could not create %s.' "$1"; else printf 'не удалось создать %s.' "$1"; fi; return ;;
        prepare) ru='не удалось подготовить файл программы.'; en='could not prepare the program file.' ;;
        chmod) ru='не удалось сделать программу исполняемой.'; en='could not make the program executable.' ;;
        launch_installed) ru='установленный файл не прошёл проверку запуска.'; en='the installed file failed its startup check.' ;;
        install) ru='не удалось установить программу.'; en='could not install the program.' ;;
        installed) if [ "$UI_LANG" = en ]; then printf 'OWBM installed: %s' "$1"; else printf 'OWBM установлен: %s' "$1"; fi; return ;;
        launch_hint) ru='Запуск: owbm menu'; en='Run: owbm menu' ;;
        path_hint) if [ "$UI_LANG" = en ]; then printf 'Run: %s menu\nAdd %s to PATH to run the owbm command.' "$1" "$2"; else printf 'Запуск: %s menu\nДобавьте %s в PATH, чтобы запускать командой owbm.' "$1" "$2"; fi; return ;;
        *) ru=$key; en=$key ;;
    esac
    if [ "$UI_LANG" = en ]; then printf '%s' "$en"; else printf '%s' "$ru"; fi
}

fail() {
    printf 'OWBM installer: %s\n' "$(message "$@")" >&2
    exit 1
}

cleanup() {
    if [ -n "${TEMPORARY_INSTALL:-}" ]; then
        rm -f "$TEMPORARY_INSTALL"
    fi
    if [ -n "${WORK_DIR:-}" ] && [ -d "$WORK_DIR" ]; then
        rm -rf "$WORK_DIR"
    fi
}
trap cleanup 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[ "$(uname -s)" = Linux ] || fail linux
[ "$(id -u)" -ne 0 ] || fail not_root
[ -n "${HOME:-}" ] && [ -d "$HOME" ] || fail home
command -v wget >/dev/null 2>&1 || fail wget
command -v mktemp >/dev/null 2>&1 || fail mktemp

python_ok() {
    command -v python3 >/dev/null 2>&1 &&
        python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1
}

ssh_ok() {
    command -v ssh >/dev/null 2>&1 || return 1
    ssh_version=$(ssh -V 2>&1 || :)
    case "$ssh_version" in
        OpenSSH_*) return 0 ;;
        *) return 1 ;;
    esac
}

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/owbm-install.XXXXXX") || fail temp_dir
archive="$WORK_DIR/owbm.pyz"
checksum="$WORK_DIR/owbm.pyz.sha256"
wget -q -O "$archive" "$RELEASE_BASE/owbm.pyz" || fail archive_download
wget -q -O "$checksum" "$RELEASE_BASE/owbm.pyz.sha256" || fail checksum_download

install_dependencies() {
    os_id=''
    os_version=''
    os_release_file=${OWBM_OS_RELEASE_FILE:-/etc/os-release}
    if [ ! -r "$os_release_file" ]; then
        fail os_release "$os_release_file"
    fi
    while IFS='=' read -r key value; do
        case "$key" in
            ID)
                os_id=${value#\"}
                os_id=${os_id%\"}
                ;;
            VERSION_ID)
                os_version=${value#\"}
                os_version=${os_version%\"}
                ;;
        esac
    done < "$os_release_file"

    case "$os_id" in
        nixos) package_manager=nix ;;
        debian|ubuntu) package_manager=apt ;;
        fedora) package_manager=dnf ;;
        arch) package_manager=pacman ;;
        alpine) package_manager=apk ;;
        *) fail unsupported_os "$os_id" ;;
    esac

    version_major=${os_version%%.*}
    version_minor=${os_version#*.}
    version_minor=${version_minor%%.*}
    case "$version_major" in ''|*[!0-9]*) version_major=0 ;; esac
    case "$version_minor" in ''|*[!0-9]*) version_minor=0 ;; esac
    case "$os_id" in
        ubuntu) [ "$version_major" -ge 22 ] || fail ubuntu_version ;;
        debian) [ "$version_major" -ge 11 ] || fail debian_version ;;
        fedora) [ "$version_major" -ge 34 ] || fail fedora_version ;;
        alpine)
            { [ "$version_major" -gt 3 ] || { [ "$version_major" -eq 3 ] && [ "$version_minor" -ge 15 ]; }; } ||
                fail alpine_version
            ;;
    esac

    case "$package_manager" in
        nix) command -v nix >/dev/null 2>&1 || fail missing_command nix ;;
        apt) command -v apt-get >/dev/null 2>&1 || fail missing_command apt-get ;;
        dnf) command -v dnf >/dev/null 2>&1 || fail missing_command dnf ;;
        pacman) command -v pacman >/dev/null 2>&1 || fail missing_command pacman ;;
        apk) command -v apk >/dev/null 2>&1 || fail missing_command apk ;;
    esac

    if [ "$package_manager" != nix ]; then
        if command -v sudo >/dev/null 2>&1; then
            privileged=sudo
        elif command -v doas >/dev/null 2>&1; then
            privileged=doas
        else
            fail privilege
        fi
    fi

    if [ ! -r /dev/tty ]; then
        fail tty
    fi
    message requirements > /dev/tty
    printf '\n' > /dev/tty
    message confirm_install "${os_id:-unknown}" > /dev/tty
    IFS= read -r answer < /dev/tty || fail confirmation_read
    case "$answer" in
        y|Y|yes|YES|Yes|д|Д|да|Да|ДА) ;;
        *) fail cancelled ;;
    esac

    case "$package_manager" in
        nix)
            nix --extra-experimental-features 'nix-command flakes' profile install nixpkgs#python3 nixpkgs#openssh || fail nix_install
            for nix_bin in "$HOME/.nix-profile/bin" "${XDG_STATE_HOME:-$HOME/.local/state}/nix/profiles/profile/bin"; do
                if [ -d "$nix_bin" ]; then PATH="$nix_bin:$PATH"; fi
            done
            export PATH
            ;;
        apt)
            "$privileged" apt-get update
            "$privileged" apt-get install -y python3 openssh-client
            ;;
        dnf)
            "$privileged" dnf install -y python3 openssh-clients
            ;;
        pacman)
            "$privileged" pacman -S --needed --noconfirm python openssh
            ;;
        apk)
            "$privileged" apk add --no-cache python3 openssh-client-default
            ;;
    esac
}

if ! python_ok || ! ssh_ok; then
    install_dependencies
fi

python_ok || fail python_after
ssh_ok || fail ssh_after

python3 - "$archive" "$checksum" "$UI_LANG" <<'PY'
import hashlib
import re
import sys
from pathlib import Path

archive = Path(sys.argv[1])
checksum_file = Path(sys.argv[2])
language = sys.argv[3]
try:
    fields = checksum_file.read_text(encoding="ascii").split()
    expected = fields[0]
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
        raise ValueError("invalid SHA-256 format" if language == "en" else "некорректный формат SHA-256")
    digest = hashlib.sha256()
    with archive.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest().lower() != expected.lower():
        raise ValueError("checksum mismatch" if language == "en" else "контрольная сумма не совпала")
except (IndexError, OSError, UnicodeError, ValueError) as exc:
    prefix = "download verification failed" if language == "en" else "проверка загрузки не пройдена"
    print(f"OWBM installer: {prefix}: {exc}", file=sys.stderr)
    raise SystemExit(1)
PY

python3 "$archive" --version >/dev/null 2>&1 || fail launch_download

bin_dir="$HOME/.local/bin"
destination="$bin_dir/owbm"
[ ! -e "$destination" ] || [ -f "$destination" ] || fail destination "$destination"
mkdir -p "$bin_dir" || fail mkdir "$bin_dir"
TEMPORARY_INSTALL="$bin_dir/.owbm-install.$$"
cp "$archive" "$TEMPORARY_INSTALL" || fail prepare
chmod 755 "$TEMPORARY_INSTALL" || fail chmod
"$TEMPORARY_INSTALL" --version >/dev/null 2>&1 || fail launch_installed
mv -f "$TEMPORARY_INSTALL" "$destination" || fail install
TEMPORARY_INSTALL=''

message installed "$destination"
printf '\n'
"$destination" --version
case ":${PATH:-}:" in
    *":$bin_dir:"*) message launch_hint; printf '\n' ;;
    *) message path_hint "$destination" "$bin_dir"; printf '\n' ;;
esac
