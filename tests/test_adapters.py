from owbm.adapters import apk, filesystem, mountinfo, opkg, overlayfs, sysupgrade


def test_unescape_octal():
    assert mountinfo.unescape(r"/media/USB\040Drive") == "/media/USB Drive"
    assert mountinfo.unescape(r"a\134b") == "a\\b"


def test_parse_mountinfo_line():
    line = (
        "24 1 0:26 / / rw,noatime - overlay overlay "
        "rw,lowerdir=/rom,upperdir=/overlay/upper,workdir=/overlay/work"
    )
    entry = mountinfo.parse_line(line)
    assert entry.mountpoint == "/"
    assert entry.fstype == "overlay"
    assert entry.writable is True
    dirs = mountinfo.overlay_dirs(entry)
    assert dirs["upperdir"] == "/overlay/upper"
    assert dirs["workdir"] == "/overlay/work"
    assert dirs["lowerdirs"] == ["/rom"]


def test_parse_mountinfo_rejects_garbage():
    assert mountinfo.parse_line("not a mount line") is None
    assert mountinfo.parse_line("1 2 3:4 / / rw") is None


def test_mount_for_path_uses_deepest_mount():
    lines = [
        "1 0 8:1 / / rw - ext4 /dev/sda1 rw",
        "2 1 8:2 / /overlay rw - ext4 /dev/sda2 rw",
    ]
    mounts = mountinfo.parse(lines)
    assert mountinfo.mount_for_path(mounts, "/overlay/upper").mountpoint == "/overlay"
    assert mountinfo.mount_for_path(mounts, "/etc/config").mountpoint == "/"


def test_filesystem_classification():
    assert filesystem.is_persistent("ext4")
    assert not filesystem.is_persistent("tmpfs")
    assert filesystem.classify("squashfs") == "readonly"
    assert filesystem.classify("tmpfs") == "ram"
    assert filesystem.classify("overlay") == "overlay"
    assert filesystem.classify("proc") == "pseudo"
    assert filesystem.classify("something-new") == "unknown"
    assert "ext4" in filesystem.describe("ext4")


def test_whiteout_path_validation():
    assert overlayfs.validate_whiteout_paths(["etc/config/network", "usr/lib/foo"]) == []
    assert overlayfs.validate_whiteout_paths(["/etc/passwd"])
    assert overlayfs.validate_whiteout_paths(["../etc/passwd"])
    assert overlayfs.validate_whiteout_paths(["etc/../../passwd"])
    assert overlayfs.validate_whiteout_paths(["", "a", "a"])
    assert overlayfs.validate_whiteout_paths(["bad\x00name"])
    assert overlayfs.validate_whiteout_paths(["./etc/config"]) == []


def test_whiteout_device_check():
    assert overlayfs.is_whiteout("c", 0, 0)
    assert not overlayfs.is_whiteout("c", 1, 2)
    assert not overlayfs.is_whiteout("f", 0, 0)


def test_apk_parse_installed():
    lines = """C:Q1
P:base-files
V:1605~r24010
A:x86_64
T:OpenWrt base files

C:Q2
P:kernel
V:6.6.73~1
A:x86_64
""".splitlines()
    entries = apk.parse_installed(lines)
    assert [e.name for e in entries] == ["base-files", "kernel"]
    assert entries[1].version == "6.6.73~1"
    assert entries[0].description == "OpenWrt base files"


def test_apk_parse_world_and_repositories():
    assert apk.parse_world(["base-files", "", "# comment"]) == ["base-files"]
    repos = apk.parse_repositories(
        ["# comment", "https://example.invalid/base", "https://example.invalid/luci", ""]
    )
    assert repos == ["https://example.invalid/base", "https://example.invalid/luci"]


def test_opkg_parse_filters_not_installed():
    lines = """Package: base-files
Version: 1555
Status: install user installed
Architecture: mipsel_24kc

Package: luci
Version: 1
Status: deinstall user not-installed
Architecture: mipsel_24kc

Package: dropbear
Version: 2022.82-3
Status: install user installed
Architecture: mipsel_24kc
Description: SSH server
 long description line
""".splitlines()
    entries = opkg.parse_status(lines)
    assert [e.name for e in entries] == ["base-files", "dropbear"]
    assert entries[1].version == "2022.82-3"


def test_opkg_repository_lines():
    assert opkg.parse_conf_files(
        ["src/gz base https://example.invalid/base", "# comment"]
    ) == ["src/gz base https://example.invalid/base"]


def test_sysupgrade_analysis():
    info = sysupgrade.analyze("/sbin/sysupgrade", ["-b backup", "-r restore"])
    assert info.available and info.supports_backup and info.supports_restore
    missing = sysupgrade.analyze("", [])
    assert not missing.available
    assert missing.notes
    unknown_help = sysupgrade.analyze("/sbin/sysupgrade", [])
    assert unknown_help.supports_backup and unknown_help.notes
