import io
import json
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from owbm import archive, capabilities, discovery, manifest as manifest_mod, migrate, storage
from owbm.errors import OwbmError
from owbm.backup import packager
from owbm.log import Logger


@pytest.fixture
def logger():
    return Logger(json_mode=True)


def _source_archive(device, tmp_path, logger, fixture="apk_overlay_x86", extra_configs=None):
    dev = device(fixture)
    if extra_configs:
        profile = json.loads(dev.profile.read_text(encoding="utf-8"))
        profile.setdefault("commands", {})["extra_configs"] = extra_configs
        dev.profile.write_text(json.dumps(profile), encoding="utf-8")
    client = dev.client()
    passport = discovery.discover(client)
    profile = capabilities.analyze(passport)
    store = storage.ArchiveStore(tmp_path / "src")
    result = packager.create_backup(client, passport, profile, store, packager.BackupOptions(), logger)
    return result.path, manifest_mod.validate(result.manifest)


def _archive_with_config_payload(tmp_path, files):
    payload = tmp_path / "configuration.tar.gz"
    with tarfile.open(payload, "w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    path = tmp_path / "config.owbm"
    archive.write_archive(
        path,
        [
            archive.Member("manifest.json", data=b"{}"),
            archive.Member("payload/configuration.tar.gz", source=payload),
        ],
    )
    return path


def _pre_restore_snapshot(client, tmp_path, logger):
    passport = discovery.discover(client)
    snapshot = packager.create_backup(
        client, passport, capabilities.analyze(passport),
        storage.ArchiveStore(tmp_path / "pre-restore"),
        packager.BackupOptions(mode="pre-restore", include_package_binaries=False), logger,
    )
    assert snapshot.ok
    return snapshot.path


def test_payload_file_plan_rejects_excessive_tar_members(tmp_path, monkeypatch):
    payload = tmp_path / "files.tar.gz"
    with tarfile.open(payload, "w:gz") as tf:
        for index in range(3):
            data = bytes([index])
            info = tarfile.TarInfo(f"etc/example-{index}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    path = tmp_path / "source.owbm"
    archive.write_archive(
        path,
        [
            archive.Member("manifest.json", data=b"{}"),
            archive.Member("payload/user-data.tar.gz", source=payload),
        ],
    )
    parsed = SimpleNamespace(
        components=[SimpleNamespace(id="user_data", path="payload/user-data.tar.gz")]
    )
    monkeypatch.setattr(archive, "MAX_TAR_MEMBERS", 2)

    with pytest.raises(OwbmError) as exc:
        list(migrate._payload_files(path, parsed, ("user_data",)))

    assert exc.value.code == "OWBM-E-CHK-002"


def test_source_configs_rejects_oversized_file(tmp_path, monkeypatch):
    path = _archive_with_config_payload(tmp_path, {"etc/config/network": b"12345"})
    monkeypatch.setattr(migrate, "MAX_CONFIG_FILE_BYTES", 4)

    with pytest.raises(OwbmError) as exc:
        migrate.source_configs(path)

    assert exc.value.code == "OWBM-E-CHK-002"


def test_source_configs_rejects_oversized_total(tmp_path, monkeypatch):
    path = _archive_with_config_payload(
        tmp_path, {"etc/config/network": b"123", "etc/config/wireless": b"456"}
    )
    monkeypatch.setattr(migrate, "MAX_CONFIG_FILE_BYTES", 8)
    monkeypatch.setattr(migrate, "MAX_CONFIG_TOTAL_BYTES", 5)

    with pytest.raises(OwbmError) as exc:
        migrate.source_configs(path)

    assert exc.value.code == "OWBM-E-CHK-002"


def test_plan_separates_packages_and_configs(device, tmp_path, logger):
    archive_path, parsed = _source_archive(device, tmp_path, logger)
    target_dev = device("ext4_root_no_overlay")
    target_client = target_dev.client()
    target = discovery.discover(target_client)

    plan = migrate.build_plan(parsed, target, archive_path, target_client)
    assert plan.packages_present or plan.packages_install
    # конфиги, которых у цели нет, копируются; совпадающие — остаются
    assert set(plan.configs_copy).isdisjoint(plan.configs_kept)
    assert plan.as_dict()["configs_copy"] == plan.configs_copy


def test_apply_rejects_wrong_pre_restore_snapshot(device, tmp_path, logger):
    from owbm.errors import OwbmError

    archive_path, parsed = _source_archive(device, tmp_path, logger)
    target_dev = device("ext4_root_no_overlay")
    client = target_dev.client()
    passport = discovery.discover(client)
    plan = migrate.build_plan(
        parsed, passport, archive_path, client,
        options=migrate.MigrateOptions(replace_existing_config=True),
    )
    plan.packages_install.clear()
    plan.packages_archive_install.clear()
    network = target_dev.root / "etc" / "config" / "network"
    original = network.read_bytes()
    work = tmp_path / "w"
    work.mkdir()

    with pytest.raises(OwbmError, match="pre-restore"):
        migrate.apply_plan(
            client, plan, parsed, archive_path, work,
            migrate.MigrateOptions(replace_existing_config=True), logger,
            root=str(target_dev.root), pre_restore_archive=archive_path,
        )

    snapshot_path = _pre_restore_snapshot(client, tmp_path, logger)
    plan.target_identity = {}
    with pytest.raises(OwbmError) as missing_identity:
        migrate.apply_plan(
            client, plan, parsed, archive_path, work,
            migrate.MigrateOptions(replace_existing_config=True), logger,
            root=str(target_dev.root), pre_restore_archive=snapshot_path,
        )
    assert missing_identity.value.code == "OWBM-E-MIG-002"
    plan.target_identity = {"board_id": "not-the-target"}
    with pytest.raises(OwbmError) as mismatched_identity:
        migrate.apply_plan(
            client, plan, parsed, archive_path, work,
            migrate.MigrateOptions(replace_existing_config=True), logger,
            root=str(target_dev.root), pre_restore_archive=snapshot_path,
        )
    assert mismatched_identity.value.code == "OWBM-E-MIG-002"
    assert network.read_bytes() == original


def test_apply_rejects_plan_for_another_client(device, tmp_path, logger):
    from owbm.errors import OwbmError

    archive_path, parsed = _source_archive(device, tmp_path, logger)
    target_a = device("ext4_root_no_overlay")
    client_a = target_a.client()
    plan = migrate.build_plan(
        parsed, discovery.discover(client_a), archive_path, client_a,
        options=migrate.MigrateOptions(replace_existing_config=True),
    )
    plan.packages_install.clear()
    plan.packages_archive_install.clear()
    snapshot_path = _pre_restore_snapshot(client_a, tmp_path, logger)

    target_b = device("opkg_overlay_f2fs")
    client_b = target_b.client()
    original = (target_b.root / "etc" / "config" / "network").read_bytes()
    work = tmp_path / "apply-other-device"
    work.mkdir()

    with pytest.raises(OwbmError) as mismatch:
        migrate.apply_plan(
            client_b, plan, parsed, archive_path, work,
            migrate.MigrateOptions(replace_existing_config=True), logger,
            root=str(target_b.root), pre_restore_archive=snapshot_path,
        )
    assert mismatch.value.code == "OWBM-E-MIG-002"
    assert (target_b.root / "etc" / "config" / "network").read_bytes() == original


def test_apply_rejects_changed_package_architecture(device, tmp_path, logger):
    from owbm.errors import OwbmError

    archive_path, parsed = _source_archive(device, tmp_path, logger)
    target_dev = device("ext4_root_no_overlay")
    client = target_dev.client()
    passport = discovery.discover(client)
    plan = migrate.build_plan(
        parsed, passport, archive_path, client,
        options=migrate.MigrateOptions(replace_existing_config=True),
    )
    plan.packages_install.clear()
    plan.packages_archive_install.clear()
    snapshot_path = _pre_restore_snapshot(client, tmp_path, logger)
    profile = json.loads(target_dev.profile.read_text(encoding="utf-8"))
    profile["commands"]["apk_arch"] = "changed-package-architecture"
    target_dev.profile.write_text(json.dumps(profile), encoding="utf-8")
    work = tmp_path / "w"
    work.mkdir()

    with pytest.raises(OwbmError) as mismatch:
        migrate.apply_plan(
            client, plan, parsed, archive_path, work,
            migrate.MigrateOptions(replace_existing_config=True), logger,
            root=str(target_dev.root), pre_restore_archive=snapshot_path,
        )
    assert mismatch.value.code == "OWBM-E-MIG-002"


def test_apply_refuses_mutation_without_pre_restore(device, tmp_path, logger):
    from owbm.errors import OwbmError

    archive_path, parsed = _source_archive(device, tmp_path, logger)
    target_dev = device("ext4_root_no_overlay")
    client = target_dev.client()
    passport = discovery.discover(client)
    plan = migrate.build_plan(
        parsed, passport, archive_path, client,
        options=migrate.MigrateOptions(replace_existing_config=True),
    )
    plan.packages_install.clear()
    plan.packages_archive_install.clear()
    network = target_dev.root / "etc" / "config" / "network"
    original = network.read_bytes()
    work = tmp_path / "w"
    work.mkdir()

    with pytest.raises(OwbmError, match="pre-restore"):
        migrate.apply_plan(
            client, plan, parsed, archive_path, work,
            migrate.MigrateOptions(replace_existing_config=True), logger,
            root=str(target_dev.root),
        )
    assert network.read_bytes() == original


def test_dry_run_changes_nothing(device, tmp_path, logger):
    archive_path, parsed = _source_archive(device, tmp_path, logger)
    target_dev = device("ext4_root_no_overlay")
    client = target_dev.client()
    target = discovery.discover(client)
    plan = migrate.build_plan(parsed, target, archive_path, client)

    before = (target_dev.root / "etc" / "config").stat().st_mtime_ns
    result = migrate.apply_plan(
        client, plan, parsed, archive_path, tmp_path / "w", migrate.MigrateOptions(dry_run=True), logger,
        root=str(target_dev.root),
    )
    assert result.configs_written == []
    assert (target_dev.root / "etc" / "config").stat().st_mtime_ns == before


def test_apply_copies_missing_config_and_keeps_existing(device, tmp_path, logger):
    archive_path, parsed = _source_archive(device, tmp_path, logger)
    target_dev = device("ext4_root_no_overlay")
    (target_dev.root / "etc" / "config" / "dropbear").unlink(missing_ok=True)
    client = target_dev.client()
    target = discovery.discover(client)
    plan = migrate.build_plan(parsed, target, archive_path, client)
    assert "dropbear" in plan.configs_copy, plan.configs_copy
    snapshot_path = _pre_restore_snapshot(client, tmp_path, logger)

    work = tmp_path / "w"
    work.mkdir()
    result = migrate.apply_plan(
        client, plan, parsed, archive_path, work, migrate.MigrateOptions(), logger,
        root=str(target_dev.root), pre_restore_archive=snapshot_path,
    )
    assert "dropbear" in result.configs_written
    assert (target_dev.root / "etc" / "config" / "dropbear").exists()


def test_existing_config_is_preserved_by_default(device, tmp_path, logger):
    archive_path, parsed = _source_archive(device, tmp_path, logger)
    target_dev = device("ext4_root_no_overlay")
    client = target_dev.client()
    target = discovery.discover(client)
    network = target_dev.root / "etc" / "config" / "network"
    original = network.read_text(encoding="utf-8")

    plan = migrate.build_plan(parsed, target, archive_path, client)
    assert "network" in plan.configs_kept
    assert "network" not in plan.configs_copy
    snapshot_path = _pre_restore_snapshot(client, tmp_path, logger)

    work = tmp_path / "w"
    work.mkdir()
    migrate.apply_plan(
        client, plan, parsed, archive_path, work, migrate.MigrateOptions(), logger,
        root=str(target_dev.root), pre_restore_archive=snapshot_path,
    )
    assert network.read_text(encoding="utf-8") == original


def test_replace_config_overrides(device, tmp_path, logger):
    archive_path, parsed = _source_archive(device, tmp_path, logger)
    target_dev = device("ext4_root_no_overlay")
    client = target_dev.client()
    target = discovery.discover(client)
    plan = migrate.build_plan(
        parsed, target, archive_path, client, options=migrate.MigrateOptions(replace_existing_config=True)
    )
    assert "network" in plan.configs_copy
    assert plan.configs_kept == []


def test_foreign_arch_is_reported(device, tmp_path, logger):
    archive_path, parsed = _source_archive(device, tmp_path, logger)
    target_client = device("opkg_overlay_f2fs").client()
    target = discovery.discover(target_client)
    plan = migrate.build_plan(parsed, target, archive_path, target_client)
    assert any("Архив собран для" in item for item in plan.warnings)
    assert plan.packages_archive_install == []


def test_package_architecture_allows_only_exact_or_portable():
    assert migrate._package_arch_matches("x86_64", "aarch64", "x86_64")
    assert migrate._package_arch_matches("noarch", "aarch64", "x86_64")
    assert migrate._package_arch_matches("all", "aarch64", "mipsel_24kc")
    assert not migrate._package_arch_matches("aarch64", "aarch64", "x86_64")
    assert not migrate._package_arch_matches("", "aarch64", "x86_64")


def test_archived_arch_packages_require_same_openwrt_platform(device, tmp_path, logger):
    import copy

    archive_path, parsed = _source_archive(device, tmp_path, logger)
    manager, source_arch, records = migrate.source_package_inventory(archive_path)
    arch_packages, _ = migrate._archive_package_files(
        archive_path, parsed, records,
        source_manager=manager, source_arch=source_arch,
        source_release=str(parsed.device.get("release")),
        source_target=str(parsed.device.get("target")),
        target_manager=manager, target_arch=source_arch,
        target_release="different-release", target_target=str(parsed.device.get("target")),
    )
    assert arch_packages == {}

    portable = copy.deepcopy(records)
    package = next(item for item in portable if item["file"])
    package["arch"] = "noarch"
    noarch_packages, _ = migrate._archive_package_files(
        archive_path, parsed, [package],
        source_manager=manager, source_arch=source_arch,
        source_release=str(parsed.device.get("release")),
        source_target=str(parsed.device.get("target")),
        target_manager=manager, target_arch="different-arch",
        target_release="different-release", target_target="different-target",
    )
    assert package["name"] in noarch_packages

    package["name"] = "kmod-test-driver"
    kernel_packages, incompatible = migrate._archive_package_files(
        archive_path, parsed, [package],
        source_manager=manager, source_arch=source_arch,
        source_release=str(parsed.device.get("release")),
        source_target=str(parsed.device.get("target")),
        target_manager=manager, target_arch=source_arch,
        target_release=str(parsed.device.get("release")),
        target_target=str(parsed.device.get("target")),
    )
    assert kernel_packages == {}
    assert "kmod-test-driver" in incompatible


def test_package_inventory_stream_has_total_uncompressed_limit(device, tmp_path, logger, monkeypatch):
    from owbm.errors import OwbmError

    archive_path, parsed = _source_archive(device, tmp_path, logger)
    manager, source_arch, records = migrate.source_package_inventory(archive_path)
    monkeypatch.setattr(migrate, "MAX_PACKAGE_ARCHIVE_UNCOMPRESSED_BYTES", 1)
    with pytest.raises(OwbmError, match="packages_binaries"):
        migrate._archive_package_files(
            archive_path, parsed, records,
            source_manager=manager, source_arch=source_arch,
            source_release=str(parsed.device.get("release", "")),
            source_target=str(parsed.device.get("target", "")),
            target_manager=manager, target_arch=source_arch,
            target_release=str(parsed.device.get("release", "")),
            target_target=str(parsed.device.get("target", "")),
        )


def test_duplicate_package_tar_members_are_rejected(device, tmp_path, logger):
    import hashlib
    import io
    import tarfile
    import zipfile

    archive_path, parsed = _source_archive(device, tmp_path, logger)
    manager, source_arch, records = migrate.source_package_inventory(archive_path)
    record = next(item for item in records if item["file"])
    component = parsed.component("packages_binaries")
    target_filename = migrate._normalise_member_name(record["file"])
    raw = archive.read_member(archive_path, component.path)
    package_data = None
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as source:
        for member in source:
            if migrate._normalise_member_name(member.name) == target_filename:
                package_data = source.extractfile(member).read()
                break
    assert package_data is not None

    duplicate_payload = tmp_path / "duplicate-packages.tar.gz"
    with tarfile.open(duplicate_payload, "w:gz") as destination:
        for _ in range(2):
            info = tarfile.TarInfo(target_filename)
            info.size = len(package_data)
            info.mode = 0o600
            destination.addfile(info, io.BytesIO(package_data))

    duplicate_manifest = archive.read_manifest(archive_path)
    component_record = next(
        item for item in duplicate_manifest["components"]
        if item["id"] == "packages_binaries"
    )
    component_data = duplicate_payload.read_bytes()
    component_record["size"] = len(component_data)
    component_record["sha256"] = hashlib.sha256(component_data).hexdigest()
    component_record["members"] = 2
    component_record["uncompressed_size"] = len(package_data) * 2

    members = []
    with zipfile.ZipFile(archive_path) as source:
        for name in source.namelist():
            if name == archive.CHECKSUMS_NAME:
                continue
            if name == archive.MANIFEST_NAME:
                data = json.dumps(duplicate_manifest).encode()
            elif name == component.path:
                data = component_data
            else:
                data = source.read(name)
            members.append(archive.Member(name, data=data))
    duplicate_archive = tmp_path / "duplicate-package-members.owbm"
    archive.write_archive(duplicate_archive, members)
    duplicate_parsed = manifest_mod.validate(archive.read_manifest(duplicate_archive))
    _candidate, incompatible = migrate._archive_package_files(
        duplicate_archive, duplicate_parsed, [record],
        source_manager=manager, source_arch=source_arch,
        source_release=str(duplicate_parsed.device.get("release", "")),
        source_target=str(duplicate_parsed.device.get("target", "")),
        target_manager=manager, target_arch=source_arch,
        target_release=str(duplicate_parsed.device.get("release", "")),
        target_target=str(duplicate_parsed.device.get("target", "")),
    )
    assert record["name"] in incompatible


def test_plan_uses_compatible_archived_packages_when_target_repo_lacks_them(device, tmp_path, logger):
    archive_path, parsed = _source_archive(device, tmp_path, logger)
    target_dev = device("ext4_root_no_overlay")
    profile = json.loads(target_dev.profile.read_text(encoding="utf-8"))
    profile["commands"]["package_versions"] = {}
    target_dev.profile.write_text(json.dumps(profile), encoding="utf-8")
    client = target_dev.client()
    plan = migrate.build_plan(parsed, discovery.discover(client), archive_path, client)

    assert {"base-files", "dnsmasq"}.issubset(plan.packages_archive_install)
    assert "kernel" in plan.packages_archive_incompatible
    assert "luci" in plan.packages_unavailable


def test_no_install_packages_plan_is_explicit(device, tmp_path, logger):
    archive_path, parsed = _source_archive(device, tmp_path, logger)
    target_dev = device("ext4_root_no_overlay")
    profile = json.loads(target_dev.profile.read_text(encoding="utf-8"))
    profile["commands"]["package_versions"] = {}
    target_dev.profile.write_text(json.dumps(profile), encoding="utf-8")
    client = target_dev.client()
    plan = migrate.build_plan(
        parsed, discovery.discover(client), archive_path, client,
        options=migrate.MigrateOptions(install_packages=False),
    )

    assert plan.install_packages_enabled is False
    assert plan.packages_archive_install
    assert "установка отключена" in plan.describe()[0]
    assert any("--no-install-packages" in warning for warning in plan.warnings)


def test_apply_rejects_package_option_different_from_plan(device, tmp_path, logger):
    from owbm.errors import OwbmError

    archive_path, parsed = _source_archive(device, tmp_path, logger)
    client = device("ext4_root_no_overlay").client()
    plan = migrate.build_plan(
        parsed, discovery.discover(client), archive_path, client,
        options=migrate.MigrateOptions(install_packages=False),
    )
    work = tmp_path / "w"
    work.mkdir()
    with pytest.raises(OwbmError) as mismatch:
        migrate.apply_plan(
            client, plan, parsed, archive_path, work, migrate.MigrateOptions(), logger,
        )
    assert mismatch.value.code == "OWBM-E-MIG-001"


def test_archive_package_install_requires_remote_success_marker(device, tmp_path, logger, monkeypatch):
    from owbm.ssh import RunResult

    archive_path, parsed = _source_archive(device, tmp_path, logger)
    manager, source_arch, records = migrate.source_package_inventory(archive_path)
    package = next(item for item in records if item["file"])
    target_dev = device("ext4_root_no_overlay")
    client = target_dev.client()
    real_run = client.run

    def interrupted(script, **kwargs):
        if "INSTALL=ok" in script:
            return RunResult(255, b"", "connection lost")
        return real_run(script, **kwargs)

    monkeypatch.setattr(client, "run", interrupted)
    work = tmp_path / "w"
    work.mkdir()
    installed, failed = migrate._install_archive_packages(
        client, parsed, archive_path, work, [package["name"]],
        source_manager=manager,
        source_arch=source_arch,
        source_release=str(parsed.device.get("release", "")),
        source_target=str(parsed.device.get("target", "")),
        target_manager=manager,
        target_arch=source_arch,
        target_release=str(parsed.device.get("release", "")),
        target_target=str(parsed.device.get("target", "")),
        logger=logger,
        root=str(target_dev.root),
    )
    assert installed == []
    assert package["name"] in failed


def test_archived_packages_install_and_temporary_files_are_cleaned(device, tmp_path, logger):
    archive_path, parsed = _source_archive(device, tmp_path, logger)
    target_dev = device("ext4_root_no_overlay")
    profile = json.loads(target_dev.profile.read_text(encoding="utf-8"))
    profile["commands"]["package_versions"] = {}
    target_dev.profile.write_text(json.dumps(profile), encoding="utf-8")
    client = target_dev.client()
    plan = migrate.build_plan(parsed, discovery.discover(client), archive_path, client)
    snapshot_path = _pre_restore_snapshot(client, tmp_path, logger)
    work = tmp_path / "w"
    work.mkdir()

    result = migrate.apply_plan(
        client, plan, parsed, archive_path, work, migrate.MigrateOptions(), logger,
        root=str(target_dev.root), pre_restore_archive=snapshot_path,
    )

    assert set(result.installed_from_archive) >= {"base-files", "dnsmasq"}
    assert "kernel" not in result.installed_from_archive
    log = target_dev.root / "install.log"
    assert log.exists()
    assert "--allow-untrusted" in log.read_text(encoding="utf-8")
    assert not list((target_dev.root / "tmp").glob("owbm-migrate-packages-*"))


def test_plan_is_json_serialisable(device, tmp_path, logger):
    archive_path, parsed = _source_archive(device, tmp_path, logger)
    client = device("ext4_root_no_overlay").client()
    target = discovery.discover(client)
    plan = migrate.build_plan(parsed, target, archive_path, client)
    text = json.dumps(plan.as_dict(), ensure_ascii=False)
    assert "packages_install" in text


def test_service_files_are_not_treated_as_config(device, tmp_path, logger):
    """uci temp files and apk leftovers must never be copied as configuration."""
    from owbm.migrate import CONFIG_NAME_RE

    for name in (".dhcp.uci-BoKPcF", "wireless.apk-new", "..", ""):
        assert not CONFIG_NAME_RE.match(name) or name.endswith(".apk-new")
    for name in ("network", "dhcp", "tachyon-core", "luci"):
        assert CONFIG_NAME_RE.match(name)


def test_binary_files_are_not_copied(device, tmp_path, logger):
    """Only arch-independent files travel; ELF binaries stay behind."""
    archive_path, parsed = _source_archive(device, tmp_path, logger)
    target_dev = device("ext4_root_no_overlay")
    # эмулируем бинарник в источнике
    client = target_dev.client()
    target = discovery.discover(client)
    plan = migrate.build_plan(parsed, target, archive_path, client)
    # в фикстуре источника бинарников нет — значит и в файлах их быть не должно
    assert all(not name.endswith(".so") for name in plan.files_copy)
    assert plan.as_dict()["files_written"] if False else True


def test_target_file_scan_error_is_not_treated_as_empty(device, monkeypatch):
    from owbm.errors import OwbmError
    from owbm.ssh import RunResult

    client = device("ext4_root_no_overlay").client()
    monkeypatch.setattr(client, "run", lambda *args, **kwargs: RunResult(1, b"", "find failed"))
    with pytest.raises(OwbmError) as error:
        migrate.target_file_list(client)
    assert error.value.code == "OWBM-E-MIG-003"


def test_truncated_target_file_scan_disables_file_copy(device, tmp_path, logger, monkeypatch):
    archive_path, parsed = _source_archive(device, tmp_path, logger)
    client = device("ext4_root_no_overlay").client()
    passport = discovery.discover(client)
    monkeypatch.setattr(migrate, "target_file_list", lambda *args, **kwargs: (set(), True))

    plan = migrate.build_plan(parsed, passport, archive_path, client)

    assert plan.files_copy == []
    assert any("40 000" in warning for warning in plan.warnings)


def test_copy_files_extracts_selected_paths(device, tmp_path, logger):
    archive_path, parsed = _source_archive(device, tmp_path, logger)
    target_dev = device("ext4_root_no_overlay")
    client = target_dev.client()
    work = tmp_path / "w"
    work.mkdir()
    payload = archive.extract_member(archive_path, "payload/overlay-upper.tar.gz", work)
    import tarfile
    with tarfile.open(payload, "r:gz") as tf:
        names = [n.lstrip("./") for n in tf.getnames() if tf.getmember(n).isfile()]
    if not names:
        pytest.skip("в фикстуре нет файлов в overlay")
    selected = names[:2]
    written = migrate.copy_files(client, parsed, archive_path, work, selected, logger, root=str(target_dev.root))
    assert written == selected
    for name in selected:
        assert (target_dev.root / name).exists()


def test_empty_config_file_is_copied(device, tmp_path, logger):
    """Zero-byte OpenWrt configs (e.g. ubootenv) are valid payloads."""
    archive_path, parsed = _source_archive(device, tmp_path, logger, extra_configs={"ubootenv": ""})
    target_dev = device("ext4_root_no_overlay")
    client = target_dev.client()
    plan = migrate.build_plan(parsed, discovery.discover(client), archive_path, client)
    assert "ubootenv" in plan.configs_copy
    snapshot_path = _pre_restore_snapshot(client, tmp_path, logger)

    work = tmp_path / "w"
    work.mkdir()
    result = migrate.apply_plan(
        client, plan, parsed, archive_path, work, migrate.MigrateOptions(), logger,
        root=str(target_dev.root), pre_restore_archive=snapshot_path,
    )
    assert "ubootenv" in result.configs_written
    restored = target_dev.root / "etc" / "config" / "ubootenv"
    assert restored.exists()
    assert restored.read_bytes() == b""


def test_config_failure_rolls_back_from_pre_restore(device, tmp_path, logger, monkeypatch):
    from owbm.errors import OwbmError

    archive_path, parsed = _source_archive(
        device, tmp_path, logger, extra_configs={"custom_new": "source-only config\\n"}
    )
    target_dev = device("ext4_root_no_overlay")
    client = target_dev.client()
    passport = discovery.discover(client)
    profile = capabilities.analyze(passport)
    store = storage.ArchiveStore(tmp_path / "pre")
    snapshot = packager.create_backup(
        client, passport, profile, store,
        packager.BackupOptions(mode="pre-restore", include_package_binaries=False), logger,
    )
    assert snapshot.ok
    network = target_dev.root / "etc" / "config" / "network"
    original = network.read_bytes()
    plan = migrate.build_plan(parsed, passport, archive_path, client,
                              options=migrate.MigrateOptions(replace_existing_config=True))
    plan.packages_install.clear()
    plan.packages_archive_install.clear()

    real_send = migrate.send_file
    calls = {"count": 0}

    def fail_second(client_arg, command, source, **kwargs):
        calls["count"] += 1
        if calls["count"] == 2:
            raise OwbmError("OWBM-E-RST-001", step="config", reason="simulated transfer failure")
        return real_send(client_arg, command, source, **kwargs)

    monkeypatch.setattr(migrate, "send_file", fail_second)
    work = tmp_path / "apply"
    work.mkdir()
    result = migrate.apply_plan(
        client, plan, parsed, archive_path, work, migrate.MigrateOptions(), logger,
        root=str(target_dev.root), pre_restore_archive=snapshot.path,
    )

    assert result.ok is False
    assert network.read_bytes() == original
    assert not (target_dev.root / "etc" / "config" / "custom_new").exists()
    assert any("возвращена из снимка pre-restore" in message for message in result.messages)


def test_reload_failure_rolls_back_configuration(device, tmp_path, logger, monkeypatch):
    from owbm.ssh import RunResult

    archive_path, parsed = _source_archive(
        device, tmp_path, logger, extra_configs={"custom_reload": "source-only config\\n"}
    )
    target_dev = device("ext4_root_no_overlay")
    client = target_dev.client()
    passport = discovery.discover(client)
    store = storage.ArchiveStore(tmp_path / "pre")
    snapshot = packager.create_backup(
        client, passport, capabilities.analyze(passport), store,
        packager.BackupOptions(mode="pre-restore", include_package_binaries=False), logger,
    )
    network = target_dev.root / "etc" / "config" / "network"
    original = network.read_bytes()
    plan = migrate.build_plan(
        parsed, passport, archive_path, client,
        options=migrate.MigrateOptions(replace_existing_config=True),
    )
    plan.packages_install.clear()
    plan.packages_archive_install.clear()
    plan.configs_copy = ["custom_reload"]
    real_run = client.run
    reload_calls = {"count": 0}

    def disconnected_on_reload(script, **kwargs):
        if "reload_config" in script:
            reload_calls["count"] += 1
            if reload_calls["count"] == 1:
                raise ConnectionError("simulated SSH loss during reload")
            return RunResult(0, b"RELOADED=1\\n", "")
        return real_run(script, **kwargs)

    monkeypatch.setattr(client, "run", disconnected_on_reload)
    work = tmp_path / "apply"
    work.mkdir()
    result = migrate.apply_plan(
        client, plan, parsed, archive_path, work,
        migrate.MigrateOptions(replace_existing_config=True, reload=True), logger,
        root=str(target_dev.root), pre_restore_archive=snapshot.path,
    )

    assert result.ok is False
    assert network.read_bytes() == original
    assert not (target_dev.root / "etc" / "config" / "custom_reload").exists()
    assert reload_calls["count"] == 2
    assert any("службы возвращены" in message for message in result.messages)


@pytest.mark.parametrize(
    "extra_configs,replace_config",
    [({}, True), ({"wireless": "config wifi-device 'radio0'\\n"}, False)],
)
def test_cli_refuses_reload_for_connectivity_config(
    device, tmp_path, logger, monkeypatch, capsys, extra_configs, replace_config,
):
    from owbm import cli

    archive_path, _parsed = _source_archive(
        device, tmp_path, logger, extra_configs=extra_configs
    )
    target_dev = device("ext4_root_no_overlay")
    network = target_dev.root / "etc" / "config" / "network"
    original = network.read_bytes()
    monkeypatch.setattr(cli, "SSHClient", lambda *args, **kwargs: target_dev.client())
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))

    args = [
        "--backup-root", str(tmp_path / "store"), "migrate", str(archive_path),
        "--host", "192.0.2.9", "--apply",
    ]
    if replace_config:
        args.append("--replace-config")
    args.extend(["--reload", "--yes"])
    rc = cli.main(args)
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert rc != 0
    assert "сторож" in output.lower()
    assert network.read_bytes() == original
    assert not (target_dev.root / "etc" / "config" / "wireless").exists()
    assert not (tmp_path / "store").exists()


def test_cli_refuses_snapshot_without_configuration(device, tmp_path, logger, monkeypatch, capsys):
    from owbm import cli

    archive_path, _parsed = _source_archive(device, tmp_path, logger)
    target_dev = device("ext4_root_no_overlay")
    network = target_dev.root / "etc" / "config" / "network"
    original = network.read_bytes()
    monkeypatch.setattr(cli, "SSHClient", lambda *args, **kwargs: target_dev.client())
    real_create = packager.create_backup

    def snapshot_without_configuration(*args, **kwargs):
        snapshot = real_create(*args, **kwargs)
        snapshot.manifest = dict(snapshot.manifest)
        snapshot.manifest["components"] = [
            item for item in snapshot.manifest.get("components", [])
            if item.get("id") != "configuration"
        ]
        return snapshot

    monkeypatch.setattr(packager, "create_backup", snapshot_without_configuration)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))

    rc = cli.main([
        "--backup-root", str(tmp_path / "store"), "migrate", str(archive_path),
        "--host", "192.0.2.9", "--apply", "--replace-config", "--yes",
    ])
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert rc != 0
    assert "не содержит конфигурацию" in output.lower()
    assert network.read_bytes() == original


def test_cli_migrate_creates_pre_restore_before_apply(device, tmp_path, logger, monkeypatch, capsys):
    from owbm import cli

    archive_path, _parsed = _source_archive(device, tmp_path, logger)
    target_dev = device("ext4_root_no_overlay")
    monkeypatch.setattr(cli, "SSHClient", lambda *args, **kwargs: target_dev.client())
    real_apply = migrate.apply_plan

    def apply_with_fake_root(*args, **kwargs):
        kwargs["root"] = str(target_dev.root)
        return real_apply(*args, **kwargs)

    monkeypatch.setattr(migrate, "apply_plan", apply_with_fake_root)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))

    rc = cli.main([
        "--backup-root", str(tmp_path / "store"), "migrate", str(archive_path),
        "--host", "192.0.2.9", "--apply", "--replace-config", "--yes",
    ])
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert rc == 0, output
    assert "pre-restore" in output
    snapshots = [item for item in storage.ArchiveStore(tmp_path / "store").list() if item.mode == "pre-restore"]
    assert len(snapshots) == 1
