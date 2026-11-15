# Safely restoring OpenWrt

A restore can replace settings and temporarily interrupt the connection to a device. Before applying a plan, verify that you selected the right archive and have a way to reach the device if its network does not come back.

Examples below use `owbm` for an installed program. For a downloaded file, run `python3 owbm.pyz`; from the source directory, run `./openwrt-brm`.

## Before you start

1. Create a fresh backup of the current device, if possible.
2. Verify the archive with `owbm check`.
3. Keep the computer connected to the network and leave the terminal open while the operation runs.
4. If you have no second way to access the device (such as a local cable or console), avoid replacing its network settings unless absolutely necessary.

## Review the plan first

Run restore without `--apply`:

```bash
owbm restore --host <device-address>
```

This command checks the archive and displays the planned actions. Device settings are not changed until you explicitly run the operation with `--apply`.

To migrate to another device, use `owbm migrate`. Review the plan first without `--apply`, and apply it only when you understand the list of files and software. Existing network settings on the target are kept by default. The `--replace-config` option replaces them with settings from the archive and may interrupt connectivity.

## Safety measures

- Before making changes, OWBM saves a separate copy of the device's current settings, shown as `pre-restore`. Keep it until you have confirmed that the device works as expected.
- When restoring network settings, OWBM starts an automatic rollback watchdog on the device. If connectivity is not confirmed in time, the device restores its previous network settings and reboots.
- After some failures, OWBM attempts to restore settings from the saved copy and reports what it could recover.

These safeguards help regain access, but they may not undo software already installed or every file copied. To restore the previous state fully, use the saved copy and review the operation report.

## If connectivity is lost

1. Do not immediately run the restore again.
2. Wait at least three minutes to let the device reboot. If you specified a longer timeout, wait longer.
3. Try connecting to the previous address.
4. If connectivity does not return, use a local console or another physical access method. Do not continue changing settings blindly.
5. Save the OWBM message and operation log; they help identify where the problem occurred.

If network settings were replaced during migration, the device may have a different address. OWBM cannot always determine the new address automatically.

## After completion

Check that:

- SSH and the web interface are reachable;
- the computer receives an address from the device and has internet access if needed;
- Wi-Fi, the local network, and required applications work;
- the report has no relevant items marked unavailable, skipped, or not installed.

A success message confirms that the requested steps completed; it does not verify every setting or application. If verification fails, keep the `pre-restore` archive and operation log until the problem is resolved.
