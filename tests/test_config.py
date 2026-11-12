from pathlib import Path

import pytest

from owbm import config as cfgmod
from owbm.errors import OwbmError


@pytest.fixture
def xdg(tmp_path, monkeypatch):
    for name, sub in (
        ("XDG_CONFIG_HOME", "config"),
        ("XDG_DATA_HOME", "data"),
        ("XDG_STATE_HOME", "state"),
        ("XDG_CACHE_HOME", "cache"),
    ):
        monkeypatch.setenv(name, str(tmp_path / sub))
    monkeypatch.delenv("OWBM_CONFIG", raising=False)
    return tmp_path


def test_missing_config_is_not_an_error(xdg):
    cfg = cfgmod.load()
    assert cfg.loaded is False
    assert cfg.general.language == "ru"
    assert cfg.backup_root() == xdg / "data" / "owbm" / "backups"
    assert cfg.known_hosts() == xdg / "state" / "owbm" / "known_hosts"


def test_load_example(xdg):
    path = cfgmod.xdg_paths().config_file
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(cfgmod.EXAMPLE, encoding="utf-8")
    cfg = cfgmod.load()
    assert cfg.loaded is True
    assert cfg.source == path
    assert cfg.devices["example"].host == "192.0.2.1"


def test_invalid_language(xdg):
    path = cfgmod.xdg_paths().config_file
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('[general]\nlanguage = "klingon"\n', encoding="utf-8")
    with pytest.raises(OwbmError) as exc:
        cfgmod.load()
    assert exc.value.code == "OWBM-E-CFG-002"


def test_broken_toml(xdg):
    path = cfgmod.xdg_paths().config_file
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("[general\nlanguage = 5\n", encoding="utf-8")
    with pytest.raises(OwbmError) as exc:
        cfgmod.load()
    assert exc.value.code == "OWBM-E-CFG-001"


def test_relative_backup_root_rejected(xdg):
    path = cfgmod.xdg_paths().config_file
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('[general]\nbackup_root = "backups"\n', encoding="utf-8")
    with pytest.raises(OwbmError):
        cfgmod.load()


def test_resolve_device_by_profile_and_address(xdg):
    cfg = cfgmod.load()
    cfg.devices["home"] = cfgmod.DeviceProfile(name="home", host="192.0.2.10", port=2222)
    assert cfg.resolve_device("home").port == 2222
    adhoc = cfg.resolve_device("192.0.2.99")
    assert adhoc.host == "192.0.2.99"
    with pytest.raises(OwbmError) as exc:
        cfg.resolve_device("no-such-profile")
    assert exc.value.code == "OWBM-E-CFG-003"


def test_save_and_reload(xdg):
    cfg = cfgmod.load()
    cfg.general.language = "en"
    cfg.devices["lab"] = cfgmod.DeviceProfile(name="lab", host="198.51.100.7", user="root")
    target = cfgmod.save(cfg)
    assert target.exists()
    assert (target.stat().st_mode & 0o077) == 0
    again = cfgmod.load()
    assert again.general.language == "en"
    assert again.devices["lab"].host == "198.51.100.7"


def test_config_path_has_no_developer_paths(xdg):
    cfg = cfgmod.load()
    mapping = cfgmod.to_mapping(cfg)
    text = repr(mapping)
    assert "/home/" not in text
