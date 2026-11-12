"""Declarative fixture devices.

Each entry describes a filesystem tree, the output of a few read-only commands
and what OWBM must conclude from it. No real hardware, no real network, no
paths or addresses from any developer machine.
"""

from __future__ import annotations

from typing import Any, Dict

_MOUNTINFO_OVERLAY_EXT4 = "\n".join(
    [
        "22 1 8:2 / /rom rw,noatime - ext4 /dev/sda2 rw,relatime",
        "23 1 8:3 / /overlay rw,noatime - ext4 /dev/sda3 rw,relatime",
        "24 1 0:26 / / rw,noatime - overlay overlay rw,lowerdir=/rom,upperdir=/overlay/upper,workdir=/overlay/work",
        "25 1 0:5 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw",
        "26 1 0:4 / /dev rw,nosuid - devtmpfs devtmpfs rw",
        "27 1 0:7 / /proc rw,nosuid,nodev,noexec - proc proc rw",
        "28 1 0:9 / /sys rw,nosuid,nodev,noexec - sysfs sysfs rw",
    ]
)

_MOUNTINFO_OVERLAY_F2FS = "\n".join(
    [
        "14 1 31:0 / /rom ro,relatime - squashfs /dev/mtdblock6 ro",
        "15 1 179:1 / /overlay rw,noatime - f2fs /dev/mmcblk0p1 rw",
        "16 1 0:24 / / rw,noatime - overlay overlay rw,lowerdir=/rom,upperdir=/overlay/upper,workdir=/overlay/work",
        "17 1 0:5 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw",
        "18 1 0:7 / /proc rw,nosuid,nodev,noexec - proc proc rw",
        "19 1 0:9 / /sys rw,nosuid,nodev,noexec - sysfs sysfs rw",
    ]
)

_MOUNTINFO_EXTROOT = "\n".join(
    [
        "10 1 31:0 / /rom ro,relatime - squashfs /dev/mtdblock6 ro",
        "11 1 8:1 / /overlay rw,noatime - ext4 /dev/sda1 rw,relatime",
        "12 1 0:22 / / rw,noatime - overlay overlay rw,lowerdir=/rom,upperdir=/overlay/upper,workdir=/overlay/work",
        "13 1 0:5 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw",
        "14 1 0:7 / /proc rw,nosuid,nodev,noexec - proc proc rw",
    ]
)

_MOUNTINFO_NO_OVERLAY = "\n".join(
    [
        "9 1 31:0 / / ro,relatime - squashfs /dev/mtdblock6 ro",
        "10 1 0:5 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw",
        "11 1 0:7 / /proc rw,nosuid,nodev,noexec - proc proc rw",
        "12 1 0:9 / /sys rw,nosuid,nodev,noexec - sysfs sysfs rw",
    ]
)

_MOUNTINFO_EXT4_ROOT = "\n".join(
    [
        "1 1 8:1 / / rw,noatime - ext4 /dev/sda1 rw,relatime",
        "2 1 0:5 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw",
        "3 1 0:4 / /dev rw,nosuid - devtmpfs devtmpfs rw",
        "4 1 0:7 / /proc rw,nosuid,nodev,noexec - proc proc rw",
        "5 1 0:9 / /sys rw,nosuid,nodev,noexec - sysfs sysfs rw",
        "6 1 8:2 / /boot rw,noatime - ext4 /dev/sda2 rw,relatime",
    ]
)

_MOUNTINFO_TMPFS_UPPER = "\n".join(
    [
        "5 1 0:21 / /rom ro,relatime - squashfs /dev/vda1 ro",
        "6 1 0:22 / /overlay rw,noatime - tmpfs tmpfs rw",
        "7 1 0:23 / / rw,noatime - overlay overlay rw,lowerdir=/rom,upperdir=/overlay/upper,workdir=/overlay/work",
        "8 1 0:5 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw",
    ]
)

_APK_DB = """C:Q1abcd
P:base-files
V:1605~r24010
A:x86_64
T:OpenWrt base files
o:base-files

C:Q1abce
P:kernel
V:6.6.73~1-3a7d0c1a4b5e
A:x86_64
T:Linux kernel
o:kernel

C:Q1abcf
P:dnsmasq
V:2.90-1
A:x86_64
T:DNS and DHCP server
o:dnsmasq

C:Q1abd0
P:luci
V:git-25.100
A:x86_64
T:LuCI interface
o:luci
"""

_OPKG_STATUS = """Package: base-files
Version: 1555~r24010
Depends: libc, netifd
Status: install user installed
Architecture: mipsel_24kc
Installed-Time: 1700000000

Package: kernel
Version: 5.15.167~1-2f9a
Status: install user installed
Architecture: mipsel_24kc

Package: dropbear
Version: 2022.82-3
Status: install user installed
Architecture: mipsel_24kc

Package: luci
Version: git-24.100
Status: deinstall user not-installed
Architecture: mipsel_24kc
"""

_RELEASE_X86 = """DISTRIB_ID='OpenWrt'
DISTRIB_RELEASE='24.10.0'
DISTRIB_REVISION='r28123-0e6e2d5'
DISTRIB_TARGET='x86/64'
DISTRIB_ARCH='x86_64'
DISTRIB_DESCRIPTION='OpenWrt 24.10.0 r28123-0e6e2d5'
DISTRIB_TAINTS=''
"""

_RELEASE_RAMIPS = """DISTRIB_ID='OpenWrt'
DISTRIB_RELEASE='23.05.5'
DISTRIB_REVISION='r24106-10cc5fcd00'
DISTRIB_TARGET='ramips/mt7621'
DISTRIB_ARCH='mipsel_24kc'
DISTRIB_DESCRIPTION='OpenWrt 23.05.5 r24106-10cc5fcd00'
DISTRIB_TAINTS=''
"""

_UBUS_X86 = (
    '{\n\t"kernel": "6.6.73",\n\t"hostname": "OpenWrt",\n\t"system": "OpenWrt",\n'
    '\t"model": {\n\t\t"id": "generic",\n\t\t"name": "Generic x86/64"\n\t},\n'
    '\t"board_name": "generic",\n\t"rootfs_partition": false,\n'
    '\t"release": {\n\t\t"distribution": "OpenWrt",\n\t\t"version": "24.10.0",\n'
    '\t\t"revision": "r28123-0e6e2d5",\n\t\t"target": "x86/64",\n'
    '\t\t"description": "OpenWrt 24.10.0 r28123-0e6e2d5"\n\t}\n}'
)

_UBUS_RAMIPS = (
    '{\n\t"kernel": "5.15.167",\n\t"hostname": "OpenWrt",\n\t"system": "MediaTek MT7621 ver:1 eco:3",\n'
    '\t"model": {\n\t\t"id": "xiaomi,redmi-router-ax6s",\n\t\t"name": "Xiaomi Redmi Router AX6S"\n\t},\n'
    '\t"board_name": "xiaomi,redmi-router-ax6s",\n'
    '\t"release": {\n\t\t"distribution": "OpenWrt",\n\t\t"version": "23.05.5",\n'
    '\t\t"revision": "r24106-10cc5fcd00",\n\t\t"target": "ramips/mt7621"\n\t}\n}'
)

_SYSUPGRADE_HELP = """Usage: sysupgrade [<upgrade-option>...] <image file or URL>
       sysupgrade [-q] [-i] <backup-command> <file>

upgrade-option:
        -f <config> restore configuration from ./sysupgrade.conf
        -c              obsolete (ignored)
backup-command:
        -b | --create-backup <file>  create backup archive
        -r | --restore-backup <file> restore backup archive
"""

_COMMON_TOOLS = ["tar", "gzip", "sha256sum", "find", "awk", "sed", "sort", "xargs", "df", "mktemp", "uci", "ubus", "jsonfilter", "sync"]

DEVICES: Dict[str, Dict[str, Any]] = {
    "apk_overlay_x86": {
        "description": "OpenWrt 24.10 x86_64, APK, OverlayFS with upper on ext4",
        "files": {
            "/etc/openwrt_release": _RELEASE_X86,
            "/etc/apk/arch": "x86_64\n",
            "/etc/apk/repositories": (
                "https://downloads.openwrt.org/releases/24.10.0/packages/x86_64/base\n"
                "https://downloads.openwrt.org/releases/24.10.0/packages/x86_64/luci\n"
            ),
            "/etc/apk/world": "base-files\nluci\n",
            "/lib/apk/db/installed": _APK_DB,
            "/tmp/sysinfo/board_name": "generic\n",
            "/proc/self/mountinfo": _MOUNTINFO_OVERLAY_EXT4 + "\n",
            "/proc/meminfo": "MemTotal:         512000 kB\nMemFree:          256000 kB\n",
            "/proc/uptime": "1234.56 4000.00\n",
            "/proc/sys/kernel/hostname": "OpenWrt\n",
            "/etc/config/network": "config interface 'loopback'\n",
            "/etc/config/dropbear": "config dropbear\n\toption PasswordAuth 'on'\n",
            "/etc/config/fstab": "config swap\n\toption device '/dev/sda1'\n\toption enabled '0'\n",
        },
        "dirs": ["/lib/upgrade/keep.d", "/etc/config", "/overlay/upper/etc"],
        "net": {"eth0": "52:54:00:12:34:56", "br-lan": "52:54:00:12:34:57"},
        "tools": ["apk", "sysupgrade"] + _COMMON_TOOLS,
        "commands": {
            "uname_r": "6.6.73",
            "uname_m": "x86_64",
            "apk_arch": "x86_64",
            "package_versions": {
                "base-files": "1605~r24010",
                "kernel": "6.6.73~1-3a7d0c1a4b5e",
                "dnsmasq": "2.90-1",
            },
            "date_utc": "2026-11-09T09:15:00Z",
            "ubus_board": _UBUS_X86,
            "sysupgrade_help": _SYSUPGRADE_HELP,
            "df": [
                "Filesystem           1024-blocks      Used Available Capacity Mounted on",
                "/dev/sda3                5000000   1000000   4000000      20% /overlay",
                "tmpfs                     256000      1000    255000       1% /tmp",
            ],
        },
        "expect": {
            "release": "24.10.0",
            "target": "x86/64",
            "arch": "x86_64",
            "manager": "apk",
            "packages": 4,
            "kernel_package": "6.6.73~1-3a7d0c1a4b5e",
            "overlay_persistent": True,
            "extroot": False,
            "exact_restore": True,
            "overlay_upper": "exact",
            "packages_binaries": "exact",
        },
    },
    "opkg_overlay_f2fs": {
        "description": "OpenWrt 23.05 ramips, OPKG, OverlayFS on f2fs (eMMC)",
        "files": {
            "/etc/openwrt_release": _RELEASE_RAMIPS,
            "/usr/lib/opkg/status": _OPKG_STATUS,
            "/etc/opkg/distfeeds.conf": (
                "src/gz openwrt_base https://downloads.openwrt.org/releases/23.05.5/packages/mipsel_24kc/base\n"
                "src/gz openwrt_luci https://downloads.openwrt.org/releases/23.05.5/packages/mipsel_24kc/luci\n"
            ),
            "/etc/opkg/user-installed": "base-files\n",
            "/tmp/sysinfo/board_name": "xiaomi,redmi-router-ax6s\n",
            "/proc/self/mountinfo": _MOUNTINFO_OVERLAY_F2FS + "\n",
            "/proc/meminfo": "MemTotal:         262144 kB\n",
            "/proc/uptime": "86400.00 100000.00\n",
            "/proc/sys/kernel/hostname": "OpenWrt\n",
            "/etc/config/network": "config interface 'lan'\n",
        },
        "dirs": ["/etc/config", "/overlay/upper", "/overlay/upper/etc/config"],
        "net": {"br-lan": "aa:bb:cc:dd:ee:01"},
        "tools": ["opkg", "sysupgrade"] + _COMMON_TOOLS,
        "commands": {
            "uname_r": "5.15.167",
            "uname_m": "mips",
            "opkg_arch": "mipsel_24kc 1",
            "package_versions": {
                "base-files": "1555~r24010",
                "kernel": "5.15.167~1-2f9a",
            },
            "date_utc": "2026-11-09T09:20:00Z",
            "ubus_board": _UBUS_RAMIPS,
            "sysupgrade_help": _SYSUPGRADE_HELP,
            "df": [
                "Filesystem           1024-blocks      Used Available Capacity Mounted on",
                "/dev/root                  40960     40960         0     100% /rom",
                "/dev/mmcblk0p1           1048576    200000    848576      19% /overlay",
                "tmpfs                     131072      1200    129872       1% /tmp",
            ],
        },
        "expect": {
            "release": "23.05.5",
            "arch": "mipsel_24kc",
            "manager": "opkg",
            "packages": 3,
            "overlay_persistent": True,
            "extroot": False,
            "exact_restore": True,
            "overlay_upper": "exact",
            "packages_binaries": "exact",
        },
    },
    "opkg_extroot": {
        "description": "OpenWrt on squashfs with extroot on a USB ext4 drive",
        "files": {
            "/etc/openwrt_release": _RELEASE_RAMIPS,
            "/usr/lib/opkg/status": _OPKG_STATUS,
            "/etc/opkg/distfeeds.conf": "src/gz openwrt_base https://example.invalid/base\n",
            "/tmp/sysinfo/board_name": "xiaomi,redmi-router-ax6s\n",
            "/proc/self/mountinfo": _MOUNTINFO_EXTROOT + "\n",
            "/etc/config/fstab": (
                "config mount\n"
                "\toption target '/overlay'\n"
                "\toption uuid '1234abcd-0000-0000-0000-000000000000'\n"
                "\toption enabled '1'\n"
            ),
            "/proc/meminfo": "MemTotal:         262144 kB\n",
            "/proc/uptime": "7200.00 10000.00\n",
            "/proc/sys/kernel/hostname": "OpenWrt\n",
            "/etc/config/network": "config interface 'lan'\n",
        },
        "dirs": ["/etc/config", "/overlay/upper", "/overlay/upper/etc/config"],
        "net": {"br-lan": "aa:bb:cc:dd:ee:02"},
        "tools": ["opkg", "sysupgrade"] + _COMMON_TOOLS,
        "commands": {
            "uname_r": "5.15.167",
            "uname_m": "mips",
            "opkg_arch": "mipsel_24kc 1",
            "date_utc": "2026-11-09T09:25:00Z",
            "ubus_board": _UBUS_RAMIPS,
            "sysupgrade_help": _SYSUPGRADE_HELP,
            "df": [
                "Filesystem           1024-blocks      Used Available Capacity Mounted on",
                "/dev/sda1                7823300   2000000   5823300      26% /overlay",
                "tmpfs                     131072      1200    129872       1% /tmp",
            ],
        },
        "expect": {
            "manager": "opkg",
            "overlay_persistent": True,
            "extroot": True,
            "overlay_upper": "exact",
        },
    },
    "opkg_no_overlay": {
        "description": "squashfs root, no OverlayFS, OPKG",
        "files": {
            "/etc/openwrt_release": _RELEASE_RAMIPS,
            "/usr/lib/opkg/status": _OPKG_STATUS,
            "/tmp/sysinfo/board_name": "xiaomi,redmi-router-ax6s\n",
            "/proc/self/mountinfo": _MOUNTINFO_NO_OVERLAY + "\n",
            "/proc/meminfo": "MemTotal:         131072 kB\n",
            "/proc/uptime": "600.00 1000.00\n",
            "/proc/sys/kernel/hostname": "OpenWrt\n",
            "/etc/config/network": "config interface 'lan'\n",
        },
        "dirs": ["/etc/config"],
        "net": {"eth0": "aa:bb:cc:dd:ee:03"},
        "tools": ["opkg", "sysupgrade"] + _COMMON_TOOLS,
        "commands": {
            "uname_r": "5.15.167",
            "uname_m": "mips",
            "opkg_arch": "mipsel_24kc 1",
            "date_utc": "2026-11-09T09:30:00Z",
            "ubus_board": _UBUS_RAMIPS,
            "sysupgrade_help": _SYSUPGRADE_HELP,
            "df": [
                "Filesystem           1024-blocks      Used Available Capacity Mounted on",
                "/dev/root                  40960     40960         0     100% /",
                "tmpfs                      65536      1000     64536       2% /tmp",
            ],
        },
        "expect": {
            "manager": "opkg",
            "overlay_persistent": False,
            "extroot": False,
            "exact_restore": False,
            "overlay_upper": "unsupported",
            "configuration": "exact",
            "packages_inventory": "exact",
            "narrative_contains": "OverlayFS не обнаружен",
        },
    },
    "apk_tmpfs_upper": {
        "description": "VM-like device whose OverlayFS upper layer lives in tmpfs",
        "files": {
            "/etc/openwrt_release": _RELEASE_X86,
            "/etc/apk/arch": "x86_64\n",
            "/etc/apk/repositories": "https://downloads.openwrt.org/snapshots/packages/x86_64/base\n",
            "/lib/apk/db/installed": _APK_DB,
            "/tmp/sysinfo/board_name": "generic\n",
            "/proc/self/mountinfo": _MOUNTINFO_TMPFS_UPPER + "\n",
            "/proc/meminfo": "MemTotal:         256000 kB\n",
            "/proc/uptime": "300.00 400.00\n",
            "/proc/sys/kernel/hostname": "OpenWrt\n",
        },
        "dirs": ["/etc/config", "/overlay/upper", "/overlay/upper/etc/config"],
        "net": {"eth0": "52:54:00:aa:bb:cc"},
        "tools": ["apk", "sysupgrade"] + _COMMON_TOOLS,
        "commands": {
            "uname_r": "6.6.73",
            "uname_m": "x86_64",
            "apk_arch": "x86_64",
            "date_utc": "2026-11-09T09:35:00Z",
            "ubus_board": _UBUS_X86,
            "sysupgrade_help": _SYSUPGRADE_HELP,
            "df": [
                "Filesystem           1024-blocks      Used Available Capacity Mounted on",
                "tmpfs                     256000      5000    251000       2% /overlay",
                "tmpfs                     256000      1000    255000       1% /tmp",
            ],
        },
        "expect": {
            "manager": "apk",
            "overlay_persistent": False,
            "overlay_upper": "config",
            "exact_restore": False,
            "narrative_contains": "записываемый слой в памяти",
        },
    },
    "ext4_root_no_overlay": {
        "description": "x86 VM on a writable ext4 root without OverlayFS",
        "files": {
            "/etc/openwrt_release": _RELEASE_X86,
            "/etc/apk/arch": "x86_64\n",
            "/etc/apk/repositories": "https://downloads.openwrt.org/releases/24.10.0/packages/x86_64/base\n",
            "/etc/apk/world": "base-files\n",
            "/lib/apk/db/installed": _APK_DB,
            "/tmp/sysinfo/board_name": "generic\n",
            "/proc/self/mountinfo": _MOUNTINFO_EXT4_ROOT + "\n",
            "/proc/meminfo": "MemTotal:         512000 kB\n",
            "/proc/uptime": "900.00 1200.00\n",
            "/proc/sys/kernel/hostname": "OpenWrt\n",
            "/etc/config/network": "config interface 'lan'\n\toption proto 'static'\n",
            "/etc/config/firewall": "config defaults\n",
            "/etc/banner": "OpenWrt banner\n",
            "/usr/share/owbm-test/marker.txt": "user state\n",
        },
        "dirs": ["/etc/config", "/usr/share/owbm-test", "/srv/data"],
        "net": {"eth0": "52:54:00:de:ad:01"},
        "tools": ["apk", "sysupgrade"] + _COMMON_TOOLS,
        "commands": {
            "uname_r": "6.12.112",
            "uname_m": "x86_64",
            "apk_arch": "x86_64",
            "package_versions": {"base-files": "1605~r24010", "kernel": "6.6.73~1-3a7d0c1a4b5e"},
            "date_utc": "2026-11-09T09:50:00Z",
            "ubus_board": _UBUS_X86,
            "sysupgrade_help": _SYSUPGRADE_HELP,
            "df": [
                "Filesystem           1024-blocks      Used Available Capacity Mounted on",
                "/dev/sda1                1048576    700000    348576      67% /",
                "tmpfs                     256000      1000    255000       1% /tmp",
            ],
        },
        "expect": {
            "release": "24.10.0",
            "manager": "apk",
            "packages": 4,
            "overlay_persistent": False,
            "extroot": False,
            "exact_restore": True,
            "overlay_upper": "config",
            "narrative_contains": "корневая ФС копируется целиком",
        },
    },
    "not_openwrt": {
        "description": "Some generic Linux box that is not OpenWrt",
        "files": {
            "/etc/os-release": "NAME=Other\nID=other\n",
            "/proc/self/mountinfo": _MOUNTINFO_NO_OVERLAY + "\n",
            "/proc/meminfo": "MemTotal:         100000 kB\n",
            "/proc/uptime": "10.00 20.00\n",
        },
        "dirs": [],
        "net": {"eth0": "aa:bb:cc:00:11:22"},
        "tools": _COMMON_TOOLS,
        "commands": {
            "uname_r": "6.1.0",
            "uname_m": "x86_64",
            "date_utc": "2026-11-09T09:40:00Z",
            "df": [
                "Filesystem           1024-blocks      Used Available Capacity Mounted on",
                "/dev/sda1                 500000    100000    400000      20% /",
            ],
        },
        "expect": {"not_openwrt": True},
    },
}
