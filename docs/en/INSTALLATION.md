# Installation

## One-command installation

Install OWBM with one command:

```bash
wget -qO- https://raw.githubusercontent.com/dizzety/OWBM-OpenWrt-Backup-Restore-Manager/main/install.sh | sh
```

Then open the menu:

```bash
owbm menu
```

`wget` must already be installed to download the installer. The installer checks for Python 3.9 or later and an SSH client. If either is missing, it offers to install the dependencies using the system package manager. You must confirm before installation; installing system packages may require a `sudo` or `doas` password. On NixOS, dependencies are installed in the user's Nix profile without changing the system configuration.

Automatic dependency installation is supported on NixOS, Debian 11+, Ubuntu 22.04+, Fedora 34+, current Arch Linux, and Alpine 3.15+. The distribution repository must provide Python 3.9 or later. On other systems, the installer proceeds if Python and OpenSSH are already installed; otherwise, it stops without changing the system. OWBM itself is installed to `~/.local/bin`; if that directory is not in `PATH`, run `~/.local/bin/owbm menu`.

The installer verifies the SHA-256 checksum and tests the downloaded program before replacing an installed version. It changes only management-computer packages and the OWBM file in your home directory; it does not connect to the router or change its settings.

To encrypt backups, you may separately install `age` or `gpg`. These tools are optional and are not installed by the OWBM installer.

## Manual installation

If Python 3.9+ and OpenSSH are already installed, download the program files directly:

```bash
wget -O owbm.pyz https://github.com/dizzety/OWBM-OpenWrt-Backup-Restore-Manager/releases/latest/download/owbm.pyz
wget -O owbm.pyz.sha256 https://github.com/dizzety/OWBM-OpenWrt-Backup-Restore-Manager/releases/latest/download/owbm.pyz.sha256
sha256sum -c owbm.pyz.sha256
python3 owbm.pyz menu
```
