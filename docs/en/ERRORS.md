# Troubleshooting errors

Find the same code in the program output. This reference explains the cause, possible fixes, and whether it is safe to continue. Values in braces are replaced with details from your message. A `pre-restore` archive is a snapshot of the target device's settings made before restore. In examples, `owbm` is the installed command; for a downloaded `owbm.pyz`, use `python3 owbm.pyz`, or run `./openwrt-brm` from the source directory.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success |
| 2 | command or configuration error |
| 3 | preflight requirements were not met |
| 4 | archive is incompatible with the device |
| 5 | network or SSH problem |
| 6 | device error |
| 7 | archive problem |
| 8 | storage space or permissions problem |
| 9 | operation was only partially completed; read the message |
| 10 | operation was interrupted |

## Error messages

### OWBM-E-ARC-001

- What happened: File was not found or is not an OWBM archive: {path}
- Why: The path may be wrong, the file may be damaged, or it may not be an OWBM archive.
- How to fix: Check the path (`owbm list` shows available archives). A damaged archive cannot be restored.
- Is it safe to continue: The device and archives were not modified.

### OWBM-E-CFG-001

- What happened: Configuration file {path} cannot be read: {reason}
- Why: The file is damaged, unavailable, or has incorrect permissions.
- How to fix: Fix or remove the file; without it, OWBM uses its default settings.
- Is it safe to continue: This was a read-only operation.

### OWBM-E-CFG-002

- What happened: Invalid value for setting {key}: {reason}
- Why: The value does not match the expected format.
- How to fix: Fix the value in the configuration file or set it with a command-line option.
- Is it safe to continue: This was a read-only operation.

### OWBM-E-CFG-003

- What happened: Connection profile {name!r} was not found.
- Why: The saved settings do not contain a profile with that name.
- How to fix: Specify the device address directly with --host or create a connection profile.
- Is it safe to continue: This was a read-only operation.

### OWBM-E-CFG-004

- What happened: Required program {tool} was not found.
- Why: It is required for: {purpose}.
- How to fix: Install it using your distribution's package manager or disable this feature.
- Is it safe to continue: This was a read-only operation.

### OWBM-E-CHK-001

- What happened: Integrity check failed for archive member {member!r}.
- Why: The archive is damaged or was modified after it was created.
- How to fix: Do not restore this archive. Use another copy.
- Is it safe to continue: The device and archives were not modified.

### OWBM-E-CHK-002

- What happened: Archive is damaged or incomplete: {reason}
- Why: Required files are missing or empty.
- How to fix: Use another backup.
- Is it safe to continue: The device and archives were not modified.

### OWBM-E-CHK-003

- What happened: Archive contains an unsafe path: {path}
- Why: A path in the archive would write a file outside the restore directory.
- How to fix: Do not use this archive. Obtain another copy and report the suspicious file.
- Is it safe to continue: The device and archives were not modified.

### OWBM-E-CHK-004

- What happened: Archive contains an unsupported object: {path} ({kind}).
- Why: This object cannot be restored safely from the archive.
- How to fix: Do not use this copy; choose another valid archive.
- Is it safe to continue: The device and archives were not modified.

### OWBM-E-CMP-001

- What happened: The archive was created on a device with different characteristics: {reason}
- Why: Settings or software from the archive may not work on this device.
- How to fix: To move to another device, use `migrate`, review its plan, and do not apply unsuitable settings.
- Is it safe to continue: The device and archives were not modified.

### OWBM-E-CMP-002

- What happened: Not enough space on the target device: {need} required, {free} available.
- Why: The device does not have enough space for the saved files.
- How to fix: Free up space or select less data in the restore plan.
- Is it safe to continue: The device and archives were not modified.

### OWBM-E-CMP-003

- What happened: Could not prepare a safe rollback for network settings: {reason}
- Why: If SSH disconnects, the device will not be able to restore the previous connection automatically.
- How to fix: Do not change network settings remotely without another way to access the device. Exclude them from the plan or connect locally.
- Is it safe to continue: The device and archives were not modified.

### OWBM-E-DSC-001

- What happened: Device {host} does not appear to be running OpenWrt.
- Why: The device did not provide the expected OpenWrt information.
- How to fix: Check the address and make sure SSH reaches an OpenWrt device.
- Is it safe to continue: This was a read-only operation.

### OWBM-E-DSC-002

- What happened: Could not retrieve device information.
- Why: {reason}
- How to fix: Check SSH access and free space on the device, then try again.
- Is it safe to continue: This was a read-only operation.

### OWBM-E-DSC-003

- What happened: Could not parse the device response: {reason}
- Why: The device returned data in an unexpected format.
- How to fix: Try again. If the problem persists, save a verbose log for support.
- Is it safe to continue: This was a read-only operation.

### OWBM-E-FMT-001

- What happened: This archive was created by a newer version of OWBM.
- Why: The installed version cannot read this archive format.
- How to fix: Update OWBM and check the archive again.
- Is it safe to continue: The device and archives were not modified.

### OWBM-E-INT-001

- What happened: Operation stopped by the user.
- Why: You pressed Ctrl+C or stopped input.
- How to fix: If you interrupted a restore or migration, check the device and save a pre-restore archive if one was created.
- Is it safe to continue: Completed archives were preserved. Device changes depend on which operation was interrupted; check the device state.

### OWBM-E-MIG-001

- What happened: The selected migration settings changed after the plan was prepared.
- Why: The plan was prepared with different options.
- How to fix: Prepare the plan again and apply it without changing the selected options.
- Is it safe to continue: The device and archives were not modified.

### OWBM-E-MIG-002

- What happened: Device information changed after the migration plan was prepared.
- Why: The plan may have been prepared for another device or before its settings changed.
- How to fix: Check the address, prepare a new plan, and compare it carefully with the target device.
- Is it safe to continue: The target device and source archive were not modified. A pre-restore snapshot may have been created.

### OWBM-E-MIG-003

- What happened: Could not safely read device information.
- Why: {reason}
- How to fix: Check the SSH connection and prepare the plan again.
- Is it safe to continue: This was a read-only operation.

### OWBM-E-RST-001

- What happened: Restore stopped at step {step}: {reason}
- Why: The operation did not finish; some changes may have been applied.
- How to fix: Do not blindly run restore again. Check the device and save the `pre-restore` archive.
- Is it safe to continue: Check the device state before continuing.

### OWBM-E-RST-002

- What happened: After step {step} failed, OWBM restored the previous network settings.
- Why: {reason}
- How to fix: Check the connection and device. This does not necessarily undo package installation or file copying.
- Is it safe to continue: Network settings were restored; check the rest of the device state.

### OWBM-E-SSH-001

- What happened: The ssh program was not found.
- Why: The OpenSSH client is not installed or could not be located.
- How to fix: Install the OpenSSH client using your distribution's package manager.
- Is it safe to continue: This was a read-only operation.

### OWBM-E-SSH-002

- What happened: Could not connect to {host}:{port}.
- Why: {reason}
- How to fix: Check the address, device availability, and SSH settings.
- Is it safe to continue: If this happened during restore or migration, check the device and any saved pre-restore archive before trying again.

### OWBM-E-SSH-003

- What happened: The SSH host key for {host} does not match the saved key.
- Why: The device may have been reinstalled or replaced, or its key may have been regenerated.
- How to fix: Verify the fingerprint against the device. If you intentionally reinstalled or replaced it, run `owbm trust --host {host} --accept-host-key` after checking it again.
- Is it safe to continue: If this happened during restore or migration, check the device and any saved pre-restore archive before trying again.

### OWBM-E-SSH-004

- What happened: SSH authentication failed for {user}@{host}.
- Why: The password may be wrong, the device may have rejected the key, or the required key may not be loaded.
- How to fix: Check the username and password or SSH key. If you use an SSH agent, make sure the required key is loaded.
- Is it safe to continue: This was a read-only operation.

### OWBM-E-SSH-005

- What happened: The SSH operation timed out after {timeout} seconds.
- Why: The device is not responding, or the transfer took longer than expected.
- How to fix: Check the connection and device state. Before retrying a modifying operation, determine whether it already ran.
- Is it safe to continue: It is unknown whether the operation changed the device. Check its state and any saved pre-restore archive before trying again.

### OWBM-E-SSH-006

- What happened: The SSH host key was not confirmed by the user.
- Why: On the first connection, verify that the SSH key belongs to your device.
- How to fix: Compare the displayed fingerprint with a trusted source, then confirm it.
- Is it safe to continue: The device and archives were not modified.

### OWBM-E-SSH-007

- What happened: Required program {tool} was not found.
- Why: It is needed to check or retrieve the SSH host key.
- How to fix: Install the openssh-client package, which provides {tool}.
- Is it safe to continue: This was a read-only operation.

### OWBM-E-SSH-008

- What happened: Could not retrieve the SSH host key for {host}:{port}.
- Why: {reason}
- How to fix: Make sure the device is reachable over SSH, then try again.
- Is it safe to continue: The device and archives were not modified.

### OWBM-E-STO-001

- What happened: Not enough free space in {path}: {free} available, {need} required.
- Why: The backup storage directory is almost full.
- How to fix: Free up space or choose another directory with --backup-root. OWBM does not delete old archives.
- Is it safe to continue: The device and archives were not modified.

### OWBM-E-STO-002

- What happened: File {path} already exists.
- Why: Archive names are unique and overwriting is disabled.
- How to fix: This prevents data loss. Try again to create a new archive with a unique name.
- Is it safe to continue: The device and archives were not modified.

### OWBM-E-STO-003

- What happened: No permission to write to {path}.
- Why: The directory belongs to another user or is mounted read-only.
- How to fix: Choose another directory or fix its permissions.
- Is it safe to continue: The device and archives were not modified.

### OWBM-E-STO-004

- What happened: Backup directory {path} is already in use by another operation.
- Why: Running multiple operations on the same directory at once is unsafe.
- How to fix: Wait for the other operation to finish, then try again.
- Is it safe to continue: The device and archives were not modified.
