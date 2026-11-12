import io
import json
import os
import shlex
import tarfile
from pathlib import Path

import pytest

from owbm import archive, capabilities, discovery, manifest as manifest_mod, storage
from owbm.backup import collector, packager
from owbm.errors import OwbmError
from owbm.log import Logger


@pytest.fixture
def logger():
    return Logger(json_mode=True)


def test_package_archive_name_uses_longest_match():
    assert collector._package_name_for_file("foo-bar-1.2-r0.apk", ["foo", "foo-bar"]) == "foo-bar"
    assert collector._package_name_for_file("foo_1.2.ipk", ["foo"]) == "foo"
    assert collector._package_name_for_file("unrelated-1.apk", ["foo", "bar"]) is None


def _setup(dev, tmp_path, name="backups"):
    client = dev.client()
    passport = discovery.discover(client)
    profile = capabilities.analyze(passport)
    store = storage.ArchiveStore(tmp_path / name)
    return client, passport, profile, store


def test_backup_creates_complete_verified_archive(device, tmp_path, logger):
    dev = device("apk_overlay_x86")
    client, passport, profile, store = _setup(dev, tmp_path)
    result = packager.create_backup(client, passport, profile, store, packager.BackupOptions(), logger)

    assert result.ok and result.path is not None
    assert result.path.exists()
    assert result.path.suffix == ".owbm"
    assert (result.path.stat().st_mode & 0o777) == 0o600
    assert result.path.parent.parent.parent == tmp_path / "backups"

    report = archive.verify_archive(result.path)
    assert report.ok, report.issues

    parsed = manifest_mod.validate(report.manifest or {})
    ids = {item.id for item in parsed.components}
    assert {"configuration", "packages_inventory", "overlay_upper"} <= ids
    assert parsed.status == manifest_mod.STATUS_COMPLETE
    assert parsed.device["board_id"] == "generic"
    assert parsed.device["arch"] == "x86_64"
    assert parsed.compatibility_key["writable_layer"] == "overlayfs"


def test_archive_contains_expected_members(device, tmp_path, logger):
    dev = device("apk_overlay_x86")
    client, passport, profile, store = _setup(dev, tmp_path)
    result = packager.create_backup(client, passport, profile, store, packager.BackupOptions(), logger)
    names = set()
    import zipfile

    with zipfile.ZipFile(result.path) as zf:
        names = set(zf.namelist())
    assert "manifest.json" in names
    assert "payload/configuration.tar.gz" in names
    assert "payload/overlay-upper.tar.gz" in names
    assert "inventory/packages.json" in names
    assert "inventory/device-passport.json" in names
    assert "meta/restore-instructions.ru.txt" in names
    assert "checksums/SHA256SUMS" in names


def test_configuration_payload_is_readable_tar(device, tmp_path, logger):
    dev = device("apk_overlay_x86")
    client, passport, profile, store = _setup(dev, tmp_path)
    result = packager.create_backup(client, passport, profile, store, packager.BackupOptions(), logger)
    work = tmp_path / "extract"
    work.mkdir()
    payload = archive.extract_member(result.path, "payload/configuration.tar.gz", work)
    members, size = collector.inspect_tar(payload)
    assert members >= 1
    assert size > 0


def test_second_backup_never_touches_the_first(device, tmp_path, logger):
    dev = device("apk_overlay_x86")
    client, passport, profile, store = _setup(dev, tmp_path)
    first = packager.create_backup(client, passport, profile, store, packager.BackupOptions(), logger)
    digest_before = __import__("hashlib").sha256(first.path.read_bytes()).hexdigest()
    stat_before = first.path.stat()

    second = packager.create_backup(client, passport, profile, store, packager.BackupOptions(), logger)
    assert second.path != first.path
    digest_after = __import__("hashlib").sha256(first.path.read_bytes()).hexdigest()
    assert digest_before == digest_after
    assert first.path.stat().st_size == stat_before.st_size
    assert len(store.list()) == 2


def test_dry_run_writes_nothing(device, tmp_path, logger):
    dev = device("apk_overlay_x86")
    client, passport, profile, store = _setup(dev, tmp_path)
    result = packager.create_backup(
        client, passport, profile, store, packager.BackupOptions(dry_run=True), logger
    )
    assert result.path is None
    assert not store.root.exists() or not store.list()
    assert result.plan is not None and result.plan.steps


def test_critical_failure_publishes_nothing(device, tmp_path, logger, monkeypatch):
    dev = device("apk_overlay_x86")
    client, passport, profile, store = _setup(dev, tmp_path)

    def boom(*_args, **_kwargs):
        raise OwbmError("OWBM-E-DSC-002", stage="configuration", reason="обрыв связи")

    monkeypatch.setattr(collector, "collect_configuration", boom)
    with pytest.raises(OwbmError):
        packager.create_backup(client, passport, profile, store, packager.BackupOptions(), logger)

    assert store.list() == []
    leftovers = list(store.tmp_dir.iterdir()) if store.tmp_dir.exists() else []
    assert [item.name for item in leftovers if item.name.endswith(".part")] == []


def test_lock_conflict_is_reported(device, tmp_path, logger):
    dev = device("apk_overlay_x86")
    client, passport, profile, store = _setup(dev, tmp_path)
    store.ensure()
    with store.lock(timeout=0):
        with pytest.raises(OwbmError) as exc:
            packager.create_backup(
                client, passport, profile, store, packager.BackupOptions(lock_timeout=0), logger
            )
    assert exc.value.code == "OWBM-E-STO-004"


def test_device_without_overlay_is_still_backed_up(device, tmp_path, logger):
    dev = device("opkg_no_overlay")
    client, passport, profile, store = _setup(dev, tmp_path)
    result = packager.create_backup(client, passport, profile, store, packager.BackupOptions(), logger)
    parsed = manifest_mod.validate(result.manifest)
    ids = {item.id for item in parsed.components}
    assert "configuration" in ids
    assert "overlay_upper" not in ids
    assert parsed.capabilities_snapshot["overlay_upper"]["level"] == "unsupported"
    report = archive.verify_archive(result.path)
    assert report.ok


def test_package_statuses_are_recorded(device, tmp_path, logger):
    dev = device("apk_overlay_x86")
    client, passport, profile, store = _setup(dev, tmp_path)
    result = packager.create_backup(client, passport, profile, store, packager.BackupOptions(), logger)
    payload = json.loads(archive.read_member(result.path, "inventory/packages.json"))
    statuses = {entry["name"]: entry["status"] for entry in payload["entries"]}
    assert statuses["base-files"] == "exact"
    assert statuses["luci"] == "unavailable"
    assert payload["manager"] == "apk"


def test_packages_can_be_disabled(device, tmp_path, logger):
    dev = device("apk_overlay_x86")
    client, passport, profile, store = _setup(dev, tmp_path)
    result = packager.create_backup(
        client, passport, profile, store, packager.BackupOptions(include_package_binaries=False), logger
    )
    parsed = manifest_mod.validate(result.manifest)
    assert "packages_binaries" not in {item.id for item in parsed.components}
    skipped = json.loads(archive.read_member(result.path, "inventory/excluded.json"))
    assert any(item["id"] == "packages_binaries" for item in skipped)


def test_user_data_paths(device, tmp_path, logger):
    dev = device("apk_overlay_x86")
    (dev.root / "srv" / "data").mkdir(parents=True)
    (dev.root / "srv" / "data" / "notes.txt").write_text("hello", encoding="utf-8")
    client, passport, profile, store = _setup(dev, tmp_path)
    result = packager.create_backup(
        client,
        passport,
        profile,
        store,
        packager.BackupOptions(user_data_paths=("/srv/data",)),
        logger,
    )
    parsed = manifest_mod.validate(result.manifest)
    assert "user_data" in {item.id for item in parsed.components}
    work = tmp_path / "u"
    work.mkdir()
    payload = archive.extract_member(result.path, "payload/user-data.tar.gz", work)
    members, _ = collector.inspect_tar(payload)
    assert members >= 1


def test_inspect_tar_rejects_aggregate_extended_headers(tmp_path, monkeypatch):
    payload = tmp_path / "many-pax.tar.gz"
    with tarfile.open(payload, "w:gz", format=tarfile.PAX_FORMAT) as tf:
        for index in range(4):
            info = tarfile.TarInfo(f"file-{index}.txt")
            info.size = 1
            info.pax_headers = {"comment": "x" * 400}
            tf.addfile(info, io.BytesIO(b"x"))
    monkeypatch.setattr(archive.BoundedTarInfo, "MAX_EXTENDED_HEADER_TOTAL_BYTES", 1024)

    with pytest.raises(OwbmError) as exc:
        collector.inspect_tar(payload)

    assert exc.value.code == "OWBM-E-CHK-002"


def test_inspect_tar_verifies_gzip_trailer(tmp_path):
    payload = tmp_path / "bad-gzip-trailer.tar.gz"
    with tarfile.open(payload, "w:gz") as tf:
        info = tarfile.TarInfo("file.txt")
        info.size = 1
        tf.addfile(info, io.BytesIO(b"x"))
    data = bytearray(payload.read_bytes())
    data[-8] ^= 0x01
    payload.write_bytes(data)

    with pytest.raises(OwbmError) as exc:
        collector.inspect_tar(payload)

    assert exc.value.code == "OWBM-E-CHK-002"


def test_inspect_tar_enforces_total_decompressed_bytes(tmp_path, monkeypatch):
    payload = tmp_path / "oversized-expanded.tar.gz"
    data = b"x" * 2048
    with tarfile.open(payload, "w:gz") as tf:
        info = tarfile.TarInfo("large.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    monkeypatch.setattr(archive, "MAX_TAR_STREAM_BYTES", 1024)

    with pytest.raises(OwbmError) as exc:
        collector.inspect_tar(payload)

    assert exc.value.code == "OWBM-E-CHK-002"


def test_inspect_tar_rejects_excessive_path_depth(tmp_path):
    payload = tmp_path / "deep-path.tar.gz"
    with tarfile.open(payload, "w:gz") as tf:
        info = tarfile.TarInfo("/".join(["d"] * (archive.MAX_TAR_PATH_DEPTH + 2)))
        info.size = 0
        tf.addfile(info)

    with pytest.raises(OwbmError) as exc:
        collector.inspect_tar(payload)

    assert exc.value.code == "OWBM-E-CHK-002"


def test_inspect_tar_rejects_oversized_pax_header(tmp_path, monkeypatch):
    payload = tmp_path / "oversized-pax.tar.gz"
    with tarfile.open(payload, "w:gz", format=tarfile.PAX_FORMAT) as tf:
        info = tarfile.TarInfo("file.txt")
        info.size = 1
        info.pax_headers = {"comment": "x" * (archive.BoundedTarInfo.MAX_EXTENDED_HEADER_BYTES + 1)}
        tf.addfile(info, io.BytesIO(b"x"))

    with pytest.raises(OwbmError) as exc:
        collector.inspect_tar(payload)

    assert exc.value.code == "OWBM-E-CHK-002"


def test_extract_tar_safely_reports_file_count_once(tmp_path):
    payload = tmp_path / "one-file.tar.gz"
    with tarfile.open(payload, "w:gz") as tf:
        directory = tarfile.TarInfo("etc/config")
        directory.type = tarfile.DIRTYPE
        tf.addfile(directory)
        data = b"x"
        info = tarfile.TarInfo("etc/config/network")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))

    count = collector.extract_tar_safely(payload, tmp_path / "out")

    assert count == 1
    assert (tmp_path / "out/etc/config/network").read_bytes() == b"x"


def test_extract_tar_safely_enforces_shared_staging_member_budget(tmp_path):
    budget = collector.ExtractionBudget(max_members=1, max_paths=10, max_uncompressed_bytes=100)
    for index in range(2):
        payload = tmp_path / f"chunk-{index}.tar.gz"
        with tarfile.open(payload, "w:gz") as tf:
            info = tarfile.TarInfo(f"package-{index}.ipk")
            info.size = 1
            tf.addfile(info, io.BytesIO(b"x"))
        if index == 0:
            assert collector.extract_tar_safely(payload, tmp_path / "staging", budget=budget) == 1
        else:
            with pytest.raises(OwbmError) as exc:
                collector.extract_tar_safely(payload, tmp_path / "staging", budget=budget)
            assert exc.value.code == "OWBM-E-CHK-002"

    assert not (tmp_path / "staging/package-1.ipk").exists()


def test_extract_tar_safely_enforces_created_path_budget(tmp_path):
    payload = tmp_path / "nested.tar.gz"
    with tarfile.open(payload, "w:gz") as tf:
        info = tarfile.TarInfo("nested/package.ipk")
        info.size = 1
        tf.addfile(info, io.BytesIO(b"x"))
    budget = collector.ExtractionBudget(max_members=10, max_paths=1, max_uncompressed_bytes=100)

    with pytest.raises(OwbmError) as exc:
        collector.extract_tar_safely(payload, tmp_path / "staging", budget=budget)

    assert exc.value.code == "OWBM-E-CHK-002"
    assert not (tmp_path / "staging/nested").exists()


def test_extract_tar_safely_respects_remaining_staging_budget(tmp_path):
    payload = tmp_path / "over-budget.tar.gz"
    data = b"1234"
    with tarfile.open(payload, "w:gz") as tf:
        info = tarfile.TarInfo("package.ipk")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))

    with pytest.raises(OwbmError) as exc:
        collector.extract_tar_safely(payload, tmp_path / "staging", max_uncompressed_bytes=3)

    assert exc.value.code == "OWBM-E-CHK-002"
    assert not (tmp_path / "staging/package.ipk").exists()


def test_extract_tar_safely_checks_inode_reserve_before_mkdir(tmp_path, monkeypatch):
    class Usage:
        free = 1 << 30

    class Stats:
        f_favail = 2
        f_ffree = 2
        f_frsize = 4096

    payload = tmp_path / "inode-limited.tar.gz"
    with tarfile.open(payload, "w:gz") as tf:
        info = tarfile.TarInfo("nested/package.ipk")
        info.size = 1
        tf.addfile(info, io.BytesIO(b"x"))
    monkeypatch.setattr(collector.shutil, "disk_usage", lambda _path: Usage())
    monkeypatch.setattr(collector.os, "statvfs", lambda _path: Stats())
    monkeypatch.setattr(collector, "EXTRACT_INODE_RESERVE", 1)

    with pytest.raises(OwbmError) as exc:
        collector.extract_tar_safely(payload, tmp_path / "staging")

    assert exc.value.code == "OWBM-E-CHK-002"
    assert not (tmp_path / "staging/nested").exists()


def test_extract_tar_safely_preserves_local_disk_reserve(tmp_path, monkeypatch):
    class Usage:
        free = 10

    payload = tmp_path / "low-space.tar.gz"
    data = b"x"
    with tarfile.open(payload, "w:gz") as tf:
        info = tarfile.TarInfo("package.ipk")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    monkeypatch.setattr(collector.shutil, "disk_usage", lambda _path: Usage())
    monkeypatch.setattr(collector, "EXTRACT_DISK_RESERVE_BYTES", 100)

    with pytest.raises(OwbmError) as exc:
        collector.extract_tar_safely(payload, tmp_path / "staging")

    assert exc.value.code == "OWBM-E-CHK-002"
    assert not (tmp_path / "staging/package.ipk").exists()


def test_user_data_path_cannot_inject_shell(device, tmp_path):
    dev = device("apk_overlay_x86")
    marker = tmp_path / "injected-command-ran"
    path = f"/'; touch {shlex.quote(str(marker))}; exit; #"

    result = collector.collect_user_data(dev.client(), tmp_path / "data.tar.gz", (path,))

    assert result is None
    assert not marker.exists()


def test_user_data_path_rejects_newline_list_injection(tmp_path):
    with pytest.raises(OwbmError) as exc:
        collector.collect_user_data(
            object(), tmp_path / "data.tar.gz", ("/valid\n--directory=/etc/passwd",)
        )

    assert exc.value.code == "OWBM-E-CFG-002"


def test_user_data_tar_list_entries_cannot_be_tar_directives(tmp_path, monkeypatch):
    captured = {}

    class Header:
        def one(self, _key, default=""):
            return default

    def fake_stream(_client, script, _dest):
        captured["script"] = script
        return Header(), 0

    monkeypatch.setattr(collector, "stream_framed", fake_stream)

    result = collector.collect_user_data(object(), tmp_path / "data.tar.gz", ("/--directory=/etc",))

    assert result is None
    assert "printf './%s\\n' \"${p#/}\"" in captured["script"]


def test_restore_instructions_present(device, tmp_path, logger):
    dev = device("apk_overlay_x86")
    client, passport, profile, store = _setup(dev, tmp_path)
    result = packager.create_backup(client, passport, profile, store, packager.BackupOptions(), logger)
    text = archive.read_member(result.path, "meta/restore-instructions.ru.txt").decode("utf-8")
    assert "OpenWrt" in text
    assert "owbm" in text


def test_temporary_workdir_is_removed(device, tmp_path, logger, monkeypatch):
    sandbox = tmp_path / "tmpdir"
    sandbox.mkdir()
    monkeypatch.setenv("TMPDIR", str(sandbox))
    dev = device("apk_overlay_x86")
    client, passport, profile, store = _setup(dev, tmp_path)
    result = packager.create_backup(client, passport, profile, store, packager.BackupOptions(), logger)
    assert result.ok
    leftovers = [item for item in sandbox.iterdir() if item.name.startswith("owbm-")]
    assert leftovers == [], f"временные каталоги не удалены: {leftovers}"


def test_cli_backup_and_list_roundtrip(device, tmp_path, monkeypatch, capsys):
    import json as _json

    from owbm import cli

    dev = device("apk_overlay_x86")
    monkeypatch.setattr(cli, "SSHClient", lambda *a, **kw: dev.client())
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    root = tmp_path / "archives"

    rc = cli.main(["--backup-root", str(root), "backup", "--host", "192.0.2.1", "--json"])
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    payload = _json.loads(captured.out)
    assert payload["status"] == "complete"
    assert Path(payload["path"]).exists()

    rc = cli.main(["--backup-root", str(root), "list", "--json"])
    captured = capsys.readouterr()
    assert rc == 0
    items = _json.loads(captured.out)
    assert len(items) == 1
    assert items[0]["valid"] is True

    rc = cli.main(["--backup-root", str(root), "check", "--json"])
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    checked = _json.loads(captured.out)
    assert checked["ok"] is True


def test_manifest_has_no_paths_of_the_controlling_machine(device, tmp_path, logger):
    dev = device("apk_overlay_x86")
    client, passport, profile, store = _setup(dev, tmp_path)
    result = packager.create_backup(client, passport, profile, store, packager.BackupOptions(), logger)
    text = json.dumps(result.manifest, ensure_ascii=False)
    assert str(dev.root) not in text
    assert str(tmp_path) not in text
    assert "/tmp/pytest" not in text
    assert "/home/" not in text


def test_rootfs_component_for_device_without_overlay(device, tmp_path, logger):
    dev = device("ext4_root_no_overlay")
    client, passport, profile, store = _setup(dev, tmp_path)
    assert profile.rootfs.level == "exact"
    assert profile.exact_restore is True
    result = packager.create_backup(client, passport, profile, store, packager.BackupOptions(), logger)
    parsed = manifest_mod.validate(result.manifest)
    ids = {item.id for item in parsed.components}
    assert "rootfs" in ids

    work = tmp_path / "rootfs"
    work.mkdir()
    payload = archive.extract_member(result.path, "payload/rootfs.tar.gz", work)
    members, size = collector.inspect_tar(payload)
    assert members > 0 and size > 0

    import tarfile

    with tarfile.open(payload, "r:gz") as tf:
        names = tf.getnames()
    assert any(name.startswith("./etc/config") for name in names)
    for excluded in ("./proc", "./sys", "./dev", "./tmp", "./boot"):
        assert not any(name == excluded or name.startswith(excluded + "/") for name in names), excluded


def test_rootfs_can_be_disabled(device, tmp_path, logger):
    dev = device("ext4_root_no_overlay")
    client, passport, profile, store = _setup(dev, tmp_path)
    result = packager.create_backup(
        client, passport, profile, store, packager.BackupOptions(include_rootfs=False), logger
    )
    parsed = manifest_mod.validate(result.manifest)
    assert "rootfs" not in {item.id for item in parsed.components}
    skipped = json.loads(archive.read_member(result.path, "inventory/excluded.json"))
    assert any(item["id"] == "rootfs" for item in skipped)


def test_rootfs_not_collected_when_overlay_exists(device, tmp_path, logger):
    dev = device("apk_overlay_x86")
    client, passport, profile, store = _setup(dev, tmp_path)
    assert profile.rootfs.level == "unsupported"
    result = packager.create_backup(client, passport, profile, store, packager.BackupOptions(), logger)
    assert "rootfs" not in {item.id for item in manifest_mod.validate(result.manifest).components}
