# OWBM — OpenWrt Backup and Restore Manager

OWBM backs up OpenWrt settings, verifies archives, and helps restore data or migrate it to another device over SSH. It shows the planned actions before making changes and never applies a restore without explicit confirmation.

## Installation

One-command installation requires Linux and `wget`. The installer checks for Python 3.9+ and an SSH client and can offer to install missing dependencies on supported distributions. See the [installation guide](docs/en/INSTALLATION.md) for details and supported systems.

```bash
wget -qO- https://raw.githubusercontent.com/dizzety/OWBM-OpenWrt-Backup-Restore-Manager/main/install.sh | sh
```

If `~/.local/bin` is not in `PATH`, the installer prints the full command to run. The management computer's model and processor do not matter. The user supplies the device address and connection method; OWBM does not scan the network or select a device automatically.

## Quick start

The easiest way to get started is the interactive menu:

```bash
owbm menu
```

In the menu, enter the OpenWrt device address, user name, and login method. On first connection, OWBM displays the device's SSH host-key fingerprint; continue only if it matches your device.

## Language

The interface is Russian by default. Use `--lang en` for English during one command, for example `owbm --lang en info --host <device-address>`. This override is not saved. To keep a language choice, change it in the interactive menu; the installer uses English on an English-language system and otherwise falls back to Russian.

Common commands:

```bash
# Check connectivity and inspect the device
owbm info --host <device-address>

# Create a backup
owbm backup --host <device-address>

# List and verify saved backups
owbm list
owbm check

# Preview the restore plan; without --apply no files are changed
owbm restore --host <device-address>

# Apply the restore after reviewing the plan
owbm restore --host <device-address> --apply

# Migrate to another OpenWrt device: preview, then apply
owbm migrate --host <new-device-address>
owbm migrate --host <new-device-address> --apply
```

During migration, OWBM keeps the target device's existing settings by default, including settings important for network access. `--replace-config` replaces them with settings from the archive and may disconnect the device. Use it only if you understand the consequences and have an alternate way to access the device.

## Before restoring

- Read the plan carefully and verify that you selected the intended device.
- Before making changes, OWBM saves a separate backup of the target's current settings.
- A successful command does not replace checks of Wi-Fi, the local network, DHCP, SSH access, and required applications.
- If connectivity is lost, do not immediately retry the restore. Wait for the automatic network rollback; see the [safe restore guide](docs/en/RESTORE-SAFETY.md).

Archives may contain passwords and keys from OpenWrt settings. Store them securely. If needed, encrypt an archive at creation with an installed `age` or `gpg`: `--encrypt age` or `--encrypt gpg`.

## Limitations

OWBM saves user files and settings, but not firmware, the bootloader, or a full memory image. Migrating between different models may require manual network configuration and installing applications unavailable in the target's repositories. OWBM skips incompatible software and files.

More details: [known limitations](docs/en/LIMITS.md), [safe restore](docs/en/RESTORE-SAFETY.md), and [error reference](docs/en/ERRORS.md).

---

# OWBM — резервное копирование OpenWrt

OWBM сохраняет настройки OpenWrt, проверяет архивы и помогает восстановить данные
или перенести их на другое устройство через SSH. Программа сначала показывает,
что будет сделано, и не начинает восстановление без явного подтверждения.

## Установка

Для установки одной командой нужны Linux и уже установленный `wget`. Установщик
проверит Python 3.9+ и SSH-клиент и предложит автоматически установить недостающие
зависимости на поддерживаемых дистрибутивах. Подробности и список систем — в
[инструкции по установке](docs/INSTALLATION.md).

Установите OWBM одной командой:

```bash
wget -qO- https://raw.githubusercontent.com/dizzety/OWBM-OpenWrt-Backup-Restore-Manager/main/install.sh | sh
```

Если `~/.local/bin` не входит в `PATH`, установщик покажет полный путь запуска.
Модель и процессор компьютера не важны. Адрес устройства и способ подключения
задаются пользователем; программа не сканирует сеть и не выбирает устройство самостоятельно.

## Быстрый старт

Самый простой способ — открыть меню:

```bash
owbm menu
```

В меню укажите адрес OpenWrt-устройства, имя пользователя и способ входа. При
первом подключении программа покажет отпечаток SSH-ключа устройства; продолжайте,
только если он соответствует вашему устройству.

## Язык интерфейса

По умолчанию интерфейс русский. Для английского на один запуск добавьте `--lang en`,
например `owbm --lang en info --host <адрес-устройства>`. Этот параметр не
сохраняется. Чтобы закрепить выбор, смените язык в интерактивном меню; установщик
использует английский при английской системной локали, иначе — русский.

Основные команды:

```bash
# Проверить связь и получить сведения об устройстве
owbm info --host <адрес-устройства>

# Создать резервную копию
owbm backup --host <адрес-устройства>

# Посмотреть и проверить сохранённые копии
owbm list
owbm check

# Сначала показать план восстановления; без --apply файлы не меняются
owbm restore --host <адрес-устройства>

# Выполнить восстановление после проверки плана
owbm restore --host <адрес-устройства> --apply

# Перенос на другое OpenWrt-устройство: сначала план, затем применение
owbm migrate --host <адрес-нового-устройства>
owbm migrate --host <адрес-нового-устройства> --apply
```

При переносе OWBM по умолчанию сохраняет уже существующие настройки нового
устройства, в том числе важные для подключения к сети. Флаг `--replace-config`
заменяет их настройками из архива и может лишить устройство связи. Используйте
его только если понимаете последствия и имеете запасной способ доступа.

## Важно перед восстановлением

- Внимательно прочитайте показанный план и убедитесь, что выбрали нужное устройство.
- Перед изменениями OWBM сохраняет отдельную копию текущих настроек цели.
- Успешное завершение команды не заменяет проверку Wi-Fi, локальной сети, DHCP,
  доступа по SSH и нужных приложений.
- Если связь пропала, не запускайте восстановление повторно сразу. Сначала
  дождитесь автоматического возврата сетевых настроек; подробные действия описаны
  в [`docs/RESTORE-SAFETY.md`](docs/RESTORE-SAFETY.md).

Архивы могут содержать пароли и ключи из настроек OpenWrt. Храните их в безопасном
месте. При необходимости зашифруйте архив при создании с помощью установленного
`age` или `gpg`: `--encrypt age` либо `--encrypt gpg`.

## Ограничения

OWBM сохраняет пользовательские файлы и настройки, но не прошивку, загрузчик или
образ всей памяти устройства. Перенос между разными моделями может потребовать
ручной настройки сети и установки приложений, которых нет в репозиториях целевого
устройства. Несовместимые программы и файлы OWBM не переносит.

Подробнее: [известные ограничения](docs/LIMITS.md),
[безопасное восстановление](docs/RESTORE-SAFETY.md) и
[справка по сообщениям об ошибках](docs/ERRORS.md).
