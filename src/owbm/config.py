"""Configuration, XDG paths and connection profiles.

Nothing here depends on where OWBM was built or who built it: every path is
resolved at runtime from the environment, and a missing config file is normal.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import tomlmini
from .errors import fail
from .util import ensure_dir, looks_like_address

LANGUAGES = ("ru", "en")
HOST_KEY_POLICIES = ("ask", "strict")


@dataclass(frozen=True)
class Paths:
    config_dir: Path
    data_dir: Path
    state_dir: Path
    cache_dir: Path

    @property
    def config_file(self) -> Path:
        return self.config_dir / "config.toml"

    @property
    def backup_root(self) -> Path:
        return self.data_dir / "backups"

    @property
    def known_hosts(self) -> Path:
        return self.state_dir / "known_hosts"

    @property
    def log_dir(self) -> Path:
        return self.state_dir / "logs"

    def ensure(self) -> "Paths":
        for directory in (self.config_dir, self.data_dir, self.state_dir, self.cache_dir):
            ensure_dir(directory, 0o700)
        return self


def _xdg(env: str, default: str) -> Path:
    value = os.environ.get(env, "").strip()
    if value and os.path.isabs(value):
        return Path(value)
    return Path.home() / default


def xdg_paths() -> Paths:
    return Paths(
        config_dir=_xdg("XDG_CONFIG_HOME", ".config") / "owbm",
        data_dir=_xdg("XDG_DATA_HOME", ".local/share") / "owbm",
        state_dir=_xdg("XDG_STATE_HOME", ".local/state") / "owbm",
        cache_dir=_xdg("XDG_CACHE_HOME", ".cache") / "owbm",
    )


@dataclass
class General:
    language: str = "ru"
    backup_root: str = ""  # empty -> <data_dir>/backups
    lock_timeout: int = 30
    keep_pre_restore: int = 5


@dataclass
class SSHSettings:
    user: str = "root"
    port: int = 22
    identity_file: str = ""
    proxy_jump: str = ""
    known_hosts: str = ""  # empty -> <state_dir>/known_hosts
    connect_timeout: int = 10
    host_key_policy: str = "ask"


@dataclass
class DeviceProfile:
    name: str
    host: str = ""
    user: Optional[str] = None
    port: Optional[int] = None
    identity_file: Optional[str] = None
    proxy_jump: Optional[str] = None
    label: Optional[str] = None


@dataclass
class Config:
    general: General = field(default_factory=General)
    ssh: SSHSettings = field(default_factory=SSHSettings)
    devices: Dict[str, DeviceProfile] = field(default_factory=dict)
    paths: Paths = field(default_factory=xdg_paths)
    source: Optional[Path] = None
    loaded: bool = False

    # -- derived values ----------------------------------------------------
    def backup_root(self) -> Path:
        if self.general.backup_root:
            return Path(os.path.expanduser(self.general.backup_root))
        return self.paths.backup_root

    def known_hosts(self) -> Path:
        if self.ssh.known_hosts:
            return Path(os.path.expanduser(self.ssh.known_hosts))
        return self.paths.known_hosts

    def log_dir(self) -> Path:
        return self.paths.log_dir

    # -- devices -----------------------------------------------------------
    def resolve_device(self, name_or_host: str) -> DeviceProfile:
        """Turn 'profile-name' or 'host/IP' into concrete settings."""
        if name_or_host in self.devices:
            profile = self.devices[name_or_host]
            if not profile.host:
                raise fail("OWBM-E-CFG-002", key=f"devices.{name_or_host}.host", reason="адрес не задан")
            return profile
        if looks_like_address(name_or_host):
            return DeviceProfile(name=name_or_host, host=name_or_host)
        raise fail("OWBM-E-CFG-003", name=name_or_host)

    def device_names(self) -> List[str]:
        return sorted(self.devices)


def _as_int(value: Any, key: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise fail("OWBM-E-CFG-002", key=key, reason=f"ожидалось целое число, получено {value!r}")
    if not low <= value <= high:
        raise fail("OWBM-E-CFG-002", key=key, reason=f"допустимый диапазон {low}..{high}")
    return value


def _as_str(value: Any, key: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise fail("OWBM-E-CFG-002", key=key, reason=f"ожидалась строка, получено {type(value).__name__}")
    return value


def from_mapping(data: Dict[str, Any], paths: Optional[Paths] = None) -> Config:
    paths = paths or xdg_paths()
    cfg = Config(paths=paths)

    general = data.get("general", {}) or {}
    if not isinstance(general, dict):
        raise fail("OWBM-E-CFG-002", key="general", reason="ожидалась таблица")
    cfg.general.language = _as_str(general.get("language", cfg.general.language), "general.language") or "ru"
    if cfg.general.language not in LANGUAGES:
        raise fail("OWBM-E-CFG-002", key="general.language", reason=f"допустимо: {', '.join(LANGUAGES)}")
    cfg.general.backup_root = _as_str(general.get("backup_root", ""), "general.backup_root")
    if cfg.general.backup_root:
        cfg.general.backup_root = os.path.expanduser(cfg.general.backup_root)
        if not os.path.isabs(cfg.general.backup_root):
            raise fail("OWBM-E-CFG-002", key="general.backup_root", reason="нужен абсолютный путь или ~")
    if "lock_timeout" in general:
        cfg.general.lock_timeout = _as_int(general["lock_timeout"], "general.lock_timeout", 0, 3600)
    if "keep_pre_restore" in general:
        cfg.general.keep_pre_restore = _as_int(general["keep_pre_restore"], "general.keep_pre_restore", 0, 1000)

    ssh = data.get("ssh", {}) or {}
    if not isinstance(ssh, dict):
        raise fail("OWBM-E-CFG-002", key="ssh", reason="ожидалась таблица")
    cfg.ssh.user = _as_str(ssh.get("user", cfg.ssh.user), "ssh.user") or "root"
    if "port" in ssh:
        cfg.ssh.port = _as_int(ssh["port"], "ssh.port", 1, 65535)
    cfg.ssh.identity_file = _as_str(ssh.get("identity_file", ""), "ssh.identity_file")
    cfg.ssh.proxy_jump = _as_str(ssh.get("proxy_jump", ""), "ssh.proxy_jump")
    cfg.ssh.known_hosts = _as_str(ssh.get("known_hosts", ""), "ssh.known_hosts")
    if "connect_timeout" in ssh:
        cfg.ssh.connect_timeout = _as_int(ssh["connect_timeout"], "ssh.connect_timeout", 1, 600)
    policy = _as_str(ssh.get("host_key_policy", cfg.ssh.host_key_policy), "ssh.host_key_policy") or "ask"
    if policy not in HOST_KEY_POLICIES:
        raise fail("OWBM-E-CFG-002", key="ssh.host_key_policy", reason=f"допустимо: {', '.join(HOST_KEY_POLICIES)}")
    cfg.ssh.host_key_policy = policy

    devices = data.get("devices", {}) or {}
    if not isinstance(devices, dict):
        raise fail("OWBM-E-CFG-002", key="devices", reason="ожидалась таблица")
    for name, raw in devices.items():
        if not isinstance(raw, dict):
            raise fail("OWBM-E-CFG-002", key=f"devices.{name}", reason="ожидалась таблица")
        profile = DeviceProfile(name=name)
        profile.host = _as_str(raw.get("host", ""), f"devices.{name}.host")
        if "user" in raw:
            profile.user = _as_str(raw["user"], f"devices.{name}.user") or None
        if "port" in raw:
            profile.port = _as_int(raw["port"], f"devices.{name}.port", 1, 65535)
        if "identity_file" in raw:
            profile.identity_file = _as_str(raw["identity_file"], f"devices.{name}.identity_file") or None
        if "proxy_jump" in raw:
            profile.proxy_jump = _as_str(raw["proxy_jump"], f"devices.{name}.proxy_jump") or None
        if "label" in raw:
            profile.label = _as_str(raw["label"], f"devices.{name}.label") or None
        cfg.devices[name] = profile
    return cfg


def load(path: Optional[Path] = None, paths: Optional[Paths] = None) -> Config:
    """Load configuration. A missing file is normal, not an error."""
    paths = paths or xdg_paths()
    explicit = path or (Path(os.environ["OWBM_CONFIG"]) if os.environ.get("OWBM_CONFIG") else None)
    target = explicit or paths.config_file
    if not target.exists():
        cfg = Config(paths=paths, source=target, loaded=False)
        return cfg
    try:
        with open(target, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise fail("OWBM-E-CFG-001", path=str(target), reason=exc.strerror or "нет доступа")
    try:
        data = tomlmini.loads(text)
    except ValueError as exc:
        raise fail("OWBM-E-CFG-001", path=str(target), reason=str(exc))
    cfg = from_mapping(data, paths)
    cfg.source = target
    cfg.loaded = True
    return cfg


def to_mapping(cfg: Config) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "general": {
            "language": cfg.general.language,
            "backup_root": cfg.general.backup_root,
            "lock_timeout": cfg.general.lock_timeout,
            "keep_pre_restore": cfg.general.keep_pre_restore,
        },
        "ssh": {
            "user": cfg.ssh.user,
            "port": cfg.ssh.port,
            "identity_file": cfg.ssh.identity_file,
            "proxy_jump": cfg.ssh.proxy_jump,
            "known_hosts": cfg.ssh.known_hosts,
            "connect_timeout": cfg.ssh.connect_timeout,
            "host_key_policy": cfg.ssh.host_key_policy,
        },
    }
    if cfg.devices:
        data["devices"] = {
            name: {
                key: value
                for key, value in {
                    "host": profile.host,
                    "user": profile.user,
                    "port": profile.port,
                    "identity_file": profile.identity_file,
                    "proxy_jump": profile.proxy_jump,
                    "label": profile.label,
                }.items()
                if value is not None
            }
            for name, profile in cfg.devices.items()
        }
    return data


def save(cfg: Config, path: Optional[Path] = None) -> Path:
    target = path or cfg.source or cfg.paths.config_file
    ensure_dir(target.parent, 0o700)
    text = tomlmini.dumps(to_mapping(cfg))
    tmp = target.with_name(target.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, target)
    return target


EXAMPLE = """# OWBM — пример конфигурации.
# Скопируйте файл в $XDG_CONFIG_HOME/owbm/config.toml и отредактируйте.
# Отсутствие этого файла не является ошибкой: программа работает без него.

[general]
# Язык интерфейса: ru или en
language = "ru"
# Каталог хранения резервных копий. Пусто = $XDG_DATA_HOME/owbm/backups
backup_root = ""
# Сколько секунд ждать освобождения блокировки хранилища
lock_timeout = 30
# Сколько снапшотов pre-restore хранить (0 = не удалять автоматически)
keep_pre_restore = 5

[ssh]
# Используйте ключ или SSH agent. Пароль запрашивается интерактивно и никогда не пишется на диск.
user = "root"
port = 22
identity_file = ""
proxy_jump = ""
# Пусто = $XDG_STATE_HOME/owbm/known_hosts
known_hosts = ""
connect_timeout = 10
# ask  — спрашивать подтверждение отпечатка при первом подключении
# strict — отказывать при любом неизвестном отпечатке
host_key_policy = "ask"

# Профиль устройства. Имя профиля используется как --device <имя>.
# Адрес — только пример из диапазона документации (RFC 5737), замените своим.
[devices.example]
host = "192.0.2.1"
label = "мой роутер"
"""
