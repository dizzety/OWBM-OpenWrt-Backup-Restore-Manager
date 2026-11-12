import pytest

from owbm import capabilities, discovery
from owbm.errors import OwbmError
from tests.fakedevice import names
from tests.fixtures.devices import DEVICES


@pytest.mark.parametrize("name", names())
def test_discovery_matches_fixture(name, device):
    dev = device(name)
    expect = DEVICES[name]["expect"]
    if expect.get("not_openwrt"):
        with pytest.raises(OwbmError) as exc:
            discovery.discover(dev.client())
        assert exc.value.code == "OWBM-E-DSC-001"
        return

    passport = discovery.discover(dev.client())
    ident = passport.identity

    assert ident.system_type == "openwrt"
    assert passport.tools  # tools were detected at all
    if "release" in expect:
        assert ident.release == expect["release"]
    if "arch" in expect:
        assert ident.arch == expect["arch"]
    if "target" in expect:
        assert ident.target == expect["target"]
    if "manager" in expect:
        assert passport.packages.manager == expect["manager"]
    if "packages" in expect:
        assert passport.packages.count == expect["packages"]
    if "kernel_package" in expect:
        assert ident.kernel_package == expect["kernel_package"]
    if "extroot" in expect:
        assert passport.storage.extroot is expect["extroot"]
    if "overlay_persistent" in expect:
        overlay = passport.storage.overlay
        if expect["overlay_persistent"]:
            assert overlay is not None and overlay.persistent
        else:
            assert overlay is None or not overlay.persistent


def test_passport_has_no_host_paths(device):
    passport = discovery.discover(device("apk_overlay_x86").client())
    dumped = repr(passport.as_dict())
    assert device("apk_overlay_x86").root.as_posix() not in dumped
    assert "/tmp/pytest" not in dumped


def test_overlay_upper_detected_from_mount_options(device):
    passport = discovery.discover(device("apk_overlay_x86").client())
    overlay = passport.storage.overlay
    assert overlay.upperdir == "/overlay/upper"
    assert overlay.workdir == "/overlay/work"
    assert overlay.upper_fstype == "ext4"
    assert overlay.persistent is True


def test_no_overlay_is_not_an_error(device):
    passport = discovery.discover(device("opkg_no_overlay").client())
    assert passport.storage.overlay is None
    assert passport.packages.manager == "opkg"
    assert passport.packages.count >= 1


def test_extroot_detected(device):
    passport = discovery.discover(device("opkg_extroot").client())
    assert passport.storage.extroot is True
    assert passport.storage.writable_persistent is True


def test_tmpfs_upper_produces_warning(device):
    passport = discovery.discover(device("apk_tmpfs_upper").client())
    assert passport.storage.overlay is not None
    assert passport.storage.overlay.persistent is False
    assert any("оперативной памяти" in item for item in passport.warnings)


def test_macs_are_collected_without_hardcoded_interface_names(device):
    passport = discovery.discover(device("apk_overlay_x86").client())
    assert "52:54:00:12:34:56" in passport.identity.macs


def test_capabilities_levels(device):
    for name in names():
        expect = DEVICES[name]["expect"]
        if expect.get("not_openwrt"):
            continue
        passport = discovery.discover(device(name).client())
        profile = capabilities.analyze(passport)
        if "overlay_upper" in expect:
            assert profile.overlay_upper.level == expect["overlay_upper"], name
        if "configuration" in expect:
            assert profile.configuration.level == expect["configuration"], name
        if "packages_inventory" in expect:
            assert profile.packages_inventory.level == expect["packages_inventory"], name
        if "packages_binaries" in expect:
            assert profile.packages_binaries.level == expect["packages_binaries"], name
        if "exact_restore" in expect:
            assert profile.exact_restore is expect["exact_restore"], name
        if "narrative_contains" in expect:
            assert expect["narrative_contains"] in capabilities.narrative(passport, profile)


def test_no_overlay_keeps_configuration_available(device):
    passport = discovery.discover(device("opkg_no_overlay").client())
    profile = capabilities.analyze(passport)
    assert profile.configuration.usable
    assert profile.packages_inventory.usable
    assert not profile.overlay_upper.usable
    assert not profile.exact_restore


def test_capability_dict_is_json_safe(device):
    import json

    passport = discovery.discover(device("apk_overlay_x86").client())
    profile = capabilities.analyze(passport)
    text = json.dumps({"p": passport.as_dict(), "c": profile.as_dict()}, ensure_ascii=False)
    assert "board_name" in text


def test_discovery_writes_nothing_to_the_device(device):
    """The probe must be read-only: no file in the fake device may change."""
    import os

    dev = device("apk_overlay_x86")
    before = {}
    for dirpath, _dirnames, filenames in os.walk(dev.root):
        for name in filenames:
            path = os.path.join(dirpath, name)
            stat = os.stat(path)
            before[path] = (stat.st_size, stat.st_mtime_ns)

    discovery.discover(dev.client())

    after = {}
    for dirpath, _dirnames, filenames in os.walk(dev.root):
        for name in filenames:
            path = os.path.join(dirpath, name)
            stat = os.stat(path)
            after[path] = (stat.st_size, stat.st_mtime_ns)

    assert before == after, "discovery must not modify the device"


def test_device_time_and_resources(device):
    passport = discovery.discover(device("apk_overlay_x86").client())
    assert passport.time.utc == "2026-11-09T09:15:00Z"
    assert passport.resources.uptime_s == 1234
    assert passport.resources.mem_total_kb == 512000
    assert passport.storage.writable_persistent is True
