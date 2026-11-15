# Important limitations

OWBM helps preserve and migrate user settings on OpenWrt. It is not a full-device image and does not guarantee that different models will behave identically. Review the plan before applying it.

## What is backed up and restored

- OWBM saves available settings, the installed-package list, and selected files. The contents depend on the capabilities of each device.
- The backup is file-based, not a bit-for-bit memory image. It does not preserve firmware, the bootloader, factory areas, flash partitions, or the system image from which OpenWrt runs.
- Wi-Fi and network settings may depend on the device model. When migrating, check network interface names, Wi-Fi, and access rules.
- OWBM does not rewrite network settings to make them fit a different model. By default, existing settings on the target device are kept. Replacing them requires an explicit choice.

## Software and different devices

- Software is normally installed from the target device's own repositories. OWBM limits temporary extraction of local package files to 2 GiB; some or all such files may be omitted if that limit is reached.
- A package file from the archive is used only when OWBM verifies that it is suitable for the target. Files for another architecture or system version are skipped, and unavailable packages are reported.
- If a required package is not in the target's repositories and the archive has no compatible package file, OWBM cannot install it automatically. You will need to find a suitable package or build one for the device.
- Copying files does not guarantee that an application will start immediately. You may need to review its settings and restart its service manually.
- Changing the device address during restore may interrupt the connection. OWBM may not be able to find the device at its new address, so arrange an alternate access method in advance.
- Not every OpenWrt model or external device has been tested. Pay particular attention to Wi-Fi, external disks, and non-standard flash layouts.

## Requirements and data protection

- OWBM requires an OpenWrt device accessible over SSH. The management computer must have Linux, Python 3.9+, and OpenSSH.
- Archives may contain passwords, Wi-Fi keys, and other secrets from device settings. By default, archives are not encrypted; file permissions are restricted where the filesystem supports it. To encrypt during creation, use `--encrypt age` or `--encrypt gpg`. The selected encryption tool must be installed, and the command must run in an interactive terminal.
- Backups are not automatically deleted. Store them securely and remove old copies yourself after checking them.

Even if OWBM reports success, manually verify device access, networking, and required applications. See the [safe restore guide](RESTORE-SAFETY.md).
