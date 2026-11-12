#!/bin/sh
# Install the latest published OWBM release for the current user.
set -eu
umask 077

REPOSITORY='dizzety/OWBM-OpenWrt-Backup-Restore-Manager'
RELEASE_BASE="https://github.com/$REPOSITORY/releases/latest/download"

fail() {
    printf 'OWBM installer: %s\n' "$*" >&2
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

[ "$(uname -s)" = Linux ] || fail 'установщик поддерживает Linux.'
[ "$(id -u)" -ne 0 ] || fail 'запустите установщик обычным пользователем, не через sudo.'
[ -n "${HOME:-}" ] && [ -d "$HOME" ] || fail 'не найдена домашняя папка пользователя.'
command -v wget >/dev/null 2>&1 || fail 'для загрузки нужен wget.'
command -v mktemp >/dev/null 2>&1 || fail 'не найдена команда mktemp.'

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

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/owbm-install.XXXXXX") || fail 'не удалось создать временную папку.'
archive="$WORK_DIR/owbm.pyz"
checksum="$WORK_DIR/owbm.pyz.sha256"
wget -q -O "$archive" "$RELEASE_BASE/owbm.pyz" || fail 'не удалось скачать owbm.pyz; проверьте, опубликован ли релиз.'
wget -q -O "$checksum" "$RELEASE_BASE/owbm.pyz.sha256" || fail 'не удалось скачать контрольную сумму релиза.'

install_dependencies() {
    os_id=''
    os_version=''
    os_release_file=${OWBM_OS_RELEASE_FILE:-/etc/os-release}
    if [ ! -r "$os_release_file" ]; then
        fail "не удалось прочитать $os_release_file."
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
        *) fail "автоустановка зависимостей для '$os_id' не поддерживается; поддерживаются NixOS, Debian, Ubuntu, Fedora, Arch и Alpine." ;;
    esac

    version_major=${os_version%%.*}
    version_minor=${os_version#*.}
    version_minor=${version_minor%%.*}
    case "$version_major" in ''|*[!0-9]*) version_major=0 ;; esac
    case "$version_minor" in ''|*[!0-9]*) version_minor=0 ;; esac
    case "$os_id" in
        ubuntu) [ "$version_major" -ge 22 ] || fail 'для автоматической установки требуется Ubuntu 22.04 или новее.' ;;
        debian) [ "$version_major" -ge 11 ] || fail 'для автоматической установки требуется Debian 11 или новее.' ;;
        fedora) [ "$version_major" -ge 34 ] || fail 'для автоматической установки требуется Fedora с Python 3.9 или новее (Fedora 34+).' ;;
        alpine)
            { [ "$version_major" -gt 3 ] || { [ "$version_major" -eq 3 ] && [ "$version_minor" -ge 15 ]; }; } ||
                fail 'для автоматической установки требуется Alpine 3.15 или новее.'
            ;;
    esac

    case "$package_manager" in
        nix) command -v nix >/dev/null 2>&1 || fail 'в NixOS не найдена команда nix.' ;;
        apt) command -v apt-get >/dev/null 2>&1 || fail 'не найдена команда apt-get.' ;;
        dnf) command -v dnf >/dev/null 2>&1 || fail 'не найдена команда dnf.' ;;
        pacman) command -v pacman >/dev/null 2>&1 || fail 'не найдена команда pacman.' ;;
        apk) command -v apk >/dev/null 2>&1 || fail 'не найдена команда apk.' ;;
    esac

    if [ "$package_manager" != nix ]; then
        if command -v sudo >/dev/null 2>&1; then
            privileged=sudo
        elif command -v doas >/dev/null 2>&1; then
            privileged=doas
        else
            fail 'нужна команда sudo или doas для установки системных зависимостей.'
        fi
    fi

    if [ ! -r /dev/tty ]; then
        fail 'для подтверждения установки нужен терминал; скачайте install.sh в файл и запустите его вручную.'
    fi
    printf '%s\n' 'Для OWBM нужны Python 3.9+ и SSH-клиент.'
    printf 'Установить недостающие зависимости для обнаруженной системы (%s)? [y/N] ' "${os_id:-неизвестно}" > /dev/tty
    IFS= read -r answer < /dev/tty || fail 'не удалось прочитать подтверждение.'
    case "$answer" in
        y|Y|yes|YES|Yes) ;;
        *) fail 'установка зависимостей отменена.' ;;
    esac

    case "$package_manager" in
        nix)
            nix --extra-experimental-features 'nix-command flakes' profile install nixpkgs#python3 nixpkgs#openssh || fail 'не удалось установить зависимости через nix profile.'
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

python_ok || fail 'после установки не найден Python 3.9 или новее.'
ssh_ok || fail 'после установки не найден SSH-клиент.'

python3 - "$archive" "$checksum" <<'PY'
import hashlib
import re
import sys
from pathlib import Path

archive = Path(sys.argv[1])
checksum_file = Path(sys.argv[2])
try:
    fields = checksum_file.read_text(encoding="ascii").split()
    expected = fields[0]
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
        raise ValueError("некорректный формат SHA-256")
    digest = hashlib.sha256()
    with archive.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest().lower() != expected.lower():
        raise ValueError("контрольная сумма не совпала")
except (IndexError, OSError, UnicodeError, ValueError) as exc:
    print(f"OWBM installer: проверка загрузки не пройдена: {exc}", file=sys.stderr)
    raise SystemExit(1)
PY

python3 "$archive" --version >/dev/null 2>&1 || fail 'загруженный файл не прошёл проверку запуска.'

bin_dir="$HOME/.local/bin"
destination="$bin_dir/owbm"
[ ! -e "$destination" ] || [ -f "$destination" ] || fail "$destination существует и не является обычным файлом."
mkdir -p "$bin_dir" || fail "не удалось создать $bin_dir."
TEMPORARY_INSTALL="$bin_dir/.owbm-install.$$"
cp "$archive" "$TEMPORARY_INSTALL" || fail 'не удалось подготовить файл программы.'
chmod 755 "$TEMPORARY_INSTALL" || fail 'не удалось сделать программу исполняемой.'
"$TEMPORARY_INSTALL" --version >/dev/null 2>&1 || fail 'установленный файл не прошёл проверку запуска.'
mv -f "$TEMPORARY_INSTALL" "$destination" || fail 'не удалось установить программу.'
TEMPORARY_INSTALL=''

printf 'OWBM установлен: %s\n' "$destination"
"$destination" --version
case ":${PATH:-}:" in
    *":$bin_dir:"*) printf 'Запуск: owbm menu\n' ;;
    *) printf 'Запуск: %s menu\nДобавьте %s в PATH, чтобы запускать командой owbm.\n' "$destination" "$bin_dir" ;;
esac
