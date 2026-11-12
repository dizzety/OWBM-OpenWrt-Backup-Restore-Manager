from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from owbm import util
from owbm.errors import OwbmError


def test_safe_component_normalises():
    assert util.safe_component("Xiaomi Redmi AX6S") == "xiaomi-redmi-ax6s"
    assert util.safe_component("xiaomi,redmi-router-ax6s") == "xiaomi-redmi-router-ax6s"
    assert util.safe_component("../../etc/passwd") == "etc-passwd"
    assert util.safe_component("") == "device"
    assert util.safe_component("...") == "device"
    assert util.safe_component("Роутер") == "device"


def test_safe_component_limits_length():
    long_name = "a" * 200
    assert len(util.safe_component(long_name, maxlen=10)) == 10
    assert util.safe_component(long_name).startswith("aaaa")


def test_utc_stamp_is_sortable():
    early = util.utc_stamp(datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc))
    late = util.utc_stamp(datetime(2026, 1, 2, 3, 4, 6, tzinfo=timezone.utc))
    assert early == "2026-01-02T030405Z"
    assert early < late


def test_human_size():
    assert util.human_size(0) == "0 Б"
    assert util.human_size(1024) == "1.0 КиБ"
    assert util.human_size(5 * 1024 * 1024) == "5.0 МиБ"


def test_parse_size():
    assert util.parse_size("512K") == 512 * 1024
    assert util.parse_size("10M") == 10 * 1024 * 1024
    assert util.parse_size("1024") == 1024
    with pytest.raises(OwbmError):
        util.parse_size("много")


def test_atomic_publish_never_overwrites(tmp_path: Path):
    target = tmp_path / "archive.owbm"
    first = tmp_path / ".part1"
    first.write_bytes(b"first")
    util.atomic_publish(first, target)
    assert target.read_bytes() == b"first"
    assert not first.exists()

    second = tmp_path / ".part2"
    second.write_bytes(b"second")
    with pytest.raises(OwbmError) as exc:
        util.atomic_publish(second, target)
    assert exc.value.code == "OWBM-E-STO-002"
    assert target.read_bytes() == b"first", "existing archive must stay untouched"
    assert second.exists(), "failed publish must not destroy the candidate"


def test_atomic_publish_permissions(tmp_path: Path):
    target = tmp_path / "archive.owbm"
    part = tmp_path / ".part"
    part.write_bytes(b"x")
    util.atomic_publish(part, target, mode=0o600)
    assert (target.stat().st_mode & 0o777) == 0o600


def test_clock_sanity():
    assert util.clock_sanity(datetime(2019, 1, 1, tzinfo=timezone.utc)) is not None
    assert util.clock_sanity(datetime.now(timezone.utc)) is None
    assert util.clock_sanity(datetime.now(timezone.utc) + timedelta(days=30)) is not None


def test_looks_like_address():
    assert util.looks_like_address("192.0.2.1")
    assert util.looks_like_address("fe80::1")
    assert util.looks_like_address("router.lan")
    assert not util.looks_like_address("home-router")
    assert not util.looks_like_address("")


def test_parse_iso():
    assert util.parse_iso("2026-11-09T09:15:00Z").year == 2026
    assert util.parse_iso("") is None
    assert util.parse_iso("nonsense") is None


def test_sha256_file(tmp_path: Path):
    path = tmp_path / "x"
    path.write_bytes(b"abc")
    assert util.sha256_file(path) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
