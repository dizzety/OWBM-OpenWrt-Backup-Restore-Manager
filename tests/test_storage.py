import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from owbm import archive, manifest, storage
from owbm.errors import OwbmError


def _manifest_data(*, created: str, board: str = "generic", status: str = "complete") -> dict:
    component = manifest.Component(
        id="configuration",
        path="payload/configuration.tar.gz",
        support_level="exact",
        portability="portable",
        critical=True,
        sha256="b" * 64,
        size=10,
        restore_order=10,
    )
    data = manifest.build(
        archive_id="11111111-2222-3333-4444-555555555555",
        created_utc=created,
        mode="backup",
        device={"board_id": board, "arch": "x86_64", "release": "24.10.0", "label": board},
        capabilities_snapshot={},
        components=[component],
        inventory={},
        status=status,
    ).as_dict()
    return data


def test_new_paths_are_unique(tmp_path):
    store = storage.ArchiveStore(tmp_path).ensure()
    moment = datetime(2026, 11, 9, 9, 15, 0, tzinfo=timezone.utc)
    first = store.new_path("generic", moment=moment)
    second = store.new_path("generic", moment=moment)
    assert first != second
    assert first.parent == tmp_path / "2026" / "11"
    assert first.name.startswith("2026-11-09T091500Z_generic_")
    assert first.suffix == ".owbm"


def test_label_is_sanitised(tmp_path):
    store = storage.ArchiveStore(tmp_path).ensure()
    path = store.new_path("Xiaomi Redmi/AX6S ../evil")
    assert "/" not in path.name
    assert path.parent.parent.parent == tmp_path


def test_publish_never_overwrites(tmp_path):
    store = storage.ArchiveStore(tmp_path).ensure()
    target = store.new_path("generic")
    src1 = tmp_path / "a.part"
    src1.write_bytes(b"one")
    store.publish(src1, target)
    src2 = tmp_path / "b.part"
    src2.write_bytes(b"two")
    with pytest.raises(OwbmError) as exc:
        store.publish(src2, target)
    assert exc.value.code == "OWBM-E-STO-002"
    assert target.read_bytes() == b"one"
    assert (target.stat().st_mode & 0o777) == 0o600


def test_listing_is_newest_first(tmp_path):
    store = storage.ArchiveStore(tmp_path).ensure()
    payload = tmp_path / "cfg.bin"
    payload.write_bytes(b"x")
    older = store.new_path("alpha", moment=datetime(2026, 1, 5, 10, 0, 0, tzinfo=timezone.utc))
    newer = store.new_path("beta", moment=datetime(2026, 5, 5, 10, 0, 0, tzinfo=timezone.utc))
    for path, created, board in (
        (older, "2026-01-05T10:00:00Z", "alpha"),
        (newer, "2026-05-05T10:00:00Z", "beta"),
    ):
        data = _manifest_data(created=created, board=board)
        archive.write_archive(
            path,
            [
                archive.Member("manifest.json", data=json.dumps(data).encode()),
                archive.Member("payload/configuration.tar.gz", source=payload),
            ],
        )
    items = store.list()
    assert [item.name for item in items] == [newer.name, older.name]
    assert items[0].device_label == "beta"
    assert all(item.valid for item in items)
    assert store.latest().name == newer.name


def test_broken_archive_does_not_break_listing(tmp_path):
    store = storage.ArchiveStore(tmp_path).ensure()
    good = store.new_path("good", moment=datetime(2026, 2, 2, tzinfo=timezone.utc))
    data = _manifest_data(created="2026-02-02T00:00:00Z")
    payload = tmp_path / "p.bin"
    payload.write_bytes(b"x")
    archive.write_archive(
        good,
        [
            archive.Member("manifest.json", data=json.dumps(data).encode()),
            archive.Member("payload/configuration.tar.gz", source=payload),
        ],
    )
    broken = store.new_path("broken", moment=datetime(2026, 3, 3, tzinfo=timezone.utc))
    broken.write_bytes(b"garbage")
    items = store.list()
    assert len(items) == 2
    by_name = {item.name: item for item in items}
    assert by_name[good.name].valid
    assert not by_name[broken.name].valid
    assert by_name[broken.name].error


def test_lock_blocks_second_writer(tmp_path):
    first = storage.ArchiveStore(tmp_path).ensure()
    second = storage.ArchiveStore(tmp_path).ensure()
    with first.lock(timeout=0):
        with pytest.raises(OwbmError) as exc:
            with second.lock(timeout=0):
                pass
    assert exc.value.code == "OWBM-E-STO-004"


def test_stale_lock_is_reclaimed(tmp_path):
    store = storage.ArchiveStore(tmp_path).ensure()
    lock_path = store.tmp_dir / storage.LOCK_NAME
    lock_path.write_text("999999 1\n", encoding="utf-8")
    os.utime(lock_path, (time.time() - storage.STALE_LOCK_SECONDS - 10,) * 2)
    with store.lock(timeout=0):
        assert lock_path.exists()
    assert not lock_path.exists()


def test_cleanup_temp_removes_old_parts(tmp_path):
    store = storage.ArchiveStore(tmp_path).ensure()
    old = store.tmp_dir / "dead.owbm.part"
    old.write_bytes(b"partial")
    os.utime(old, (time.time() - storage.STALE_TMP_SECONDS - 60,) * 2)
    fresh = store.tmp_dir / "live.owbm.part"
    fresh.write_bytes(b"partial")
    removed = store.cleanup_temp()
    assert old in removed
    assert not old.exists()
    assert fresh.exists()


def test_require_space_reports_shortage(tmp_path):
    store = storage.ArchiveStore(tmp_path).ensure()
    with pytest.raises(OwbmError) as exc:
        store.require_space(10**18)
    assert exc.value.code == "OWBM-E-STO-001"


def test_unwritable_root_is_reported(tmp_path):
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    os.chmod(blocked, 0o500)
    try:
        store = storage.ArchiveStore(blocked / "sub")
        with pytest.raises(OwbmError) as exc:
            store.ensure()
        assert exc.value.code == "OWBM-E-STO-003"
    finally:
        os.chmod(blocked, 0o700)


def test_pre_restore_archives_are_separate(tmp_path):
    store = storage.ArchiveStore(tmp_path).ensure()
    path = store.new_path("generic", mode="pre-restore")
    assert storage.PRE_RESTORE_DIRNAME in path.parts
