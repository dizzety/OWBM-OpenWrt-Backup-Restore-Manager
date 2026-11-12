import sys

import pytest

from owbm import tomlmini


def test_reads_scalars_and_comments():
    data = tomlmini.loads(
        """
        # comment
        name = "value"   # trailing
        count = 42
        ratio = 0.5
        enabled = true
        quoted = 'single'
        """
    )
    assert data == {"name": "value", "count": 42, "ratio": 0.5, "enabled": True, "quoted": "single"}


def test_reads_tables_and_dotted_keys():
    data = tomlmini.loads(
        """
        [general]
        language = "ru"

        [devices.home]
        host = "192.0.2.1"
        port = 2222
        """
    )
    assert data["general"]["language"] == "ru"
    assert data["devices"]["home"]["port"] == 2222


def test_reads_arrays():
    data = tomlmini.loads('hosts = ["a.example", "b.example"]\nempty = []\n')
    assert data["hosts"] == ["a.example", "b.example"]
    assert data["empty"] == []


def test_hash_inside_string_is_not_comment():
    data = tomlmini.loads('label = "router #1"\n')
    assert data["label"] == "router #1"


def test_escapes():
    data = tomlmini.loads('path = "a\\\\b\\"c"\n')
    assert data["path"] == 'a\\b"c'


@pytest.mark.parametrize(
    "text",
    [
        "no equals sign",
        'broken = "unterminated',
        "[[array_of_tables]]\n",
        "= 5\n",
    ],
)
def test_rejects_invalid(text):
    with pytest.raises(tomlmini.TomlError):
        tomlmini.loads(text)


def test_dump_load_roundtrip():
    data = {
        "general": {"language": "ru", "backup_root": "", "lock_timeout": 30, "flag": True},
        "devices": {"home": {"host": "192.0.2.1", "label": "мой роутер"}},
    }
    assert tomlmini.loads(tomlmini.dumps(data)) == data


def test_example_config_is_valid_toml():
    from owbm.config import EXAMPLE, from_mapping

    data = tomlmini.loads(EXAMPLE)
    cfg = from_mapping(data)
    assert cfg.general.language == "ru"
    assert "example" in cfg.devices
    assert cfg.devices["example"].host == "192.0.2.1"


@pytest.mark.skipif(sys.version_info < (3, 11), reason="tomllib availability")
def test_matches_stdlib_tomllib():
    import tomllib

    from owbm.config import EXAMPLE, to_mapping, Config

    mine = tomlmini.loads(EXAMPLE)
    theirs = tomllib.loads(EXAMPLE)
    assert mine == theirs
    assert tomlmini.loads(tomlmini.dumps(to_mapping(Config()))) == to_mapping(Config())
