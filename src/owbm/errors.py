"""Error catalog: one stable code per failure mode.

Every error carries four user-facing answers: what happened, why, how to fix it,
and whether it is safe to continue. Codes are stable API: never reuse them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from . import i18n

# --- exit codes (documented in docs/ERRORS.md) -------------------------------
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_PREFLIGHT = 3
EXIT_INCOMPATIBLE = 4
EXIT_NETWORK = 5
EXIT_DEVICE = 6
EXIT_ARCHIVE = 7
EXIT_STORAGE = 8
EXIT_PARTIAL = 9
EXIT_INTERRUPTED = 10


@dataclass(frozen=True)
class Spec:
    exit_code: int
    what: str
    why: str
    fix: str
    safe: str


_UNKNOWN = Spec(
    exit_code=EXIT_DEVICE,
    what="Непредвиденная ошибка.",
    why="Причину ошибки не удалось определить.",
    fix="Запустите программу с --verbose и сохраните журнал.",
    safe="Состояние устройства неизвестно: проверьте его вручную.",
)

SAFE_UNTOUCHED = "Устройство и архивы не изменялись."
SAFE_READONLY = "Операция была только для чтения."

CATALOG: Dict[str, Spec] = {
    # --- configuration -------------------------------------------------------
    "OWBM-E-CFG-001": Spec(
        EXIT_USAGE,
        "Файл конфигурации {path} не читается: {reason}",
        "Файл повреждён, недоступен или имеет неверные права доступа.",
        "Исправьте файл или удалите его: без файла программа работает с настройками по умолчанию.",
        SAFE_READONLY,
    ),
    "OWBM-E-CFG-002": Spec(
        EXIT_USAGE,
        "Неверное значение настройки {key}: {reason}",
        "Значение не соответствует ожидаемому формату.",
        "Исправьте значение в файле конфигурации или задайте его параметром командной строки.",
        SAFE_READONLY,
    ),
    "OWBM-E-CFG-003": Spec(
        EXIT_USAGE,
        "Настройка подключения «{name}» не найдена.",
        "Сохранённые настройки не содержат записи с таким именем.",
        "Укажите адрес устройства напрямую (--host) или создайте запись подключения.",
        SAFE_READONLY,
    ),
    "OWBM-E-CFG-004": Spec(
        EXIT_PREFLIGHT,
        "Не найдена программа {tool}.",
        "Она нужна для: {purpose}.",
        "Установите её средствами дистрибутива или откажитесь от этой возможности.",
        SAFE_READONLY,
    ),
    # --- ssh -----------------------------------------------------------------
    "OWBM-E-SSH-001": Spec(
        EXIT_PREFLIGHT,
        "Не найдена программа ssh.",
        "Клиент OpenSSH не установлен или не найден.",
        "Установите клиент OpenSSH средствами вашего дистрибутива.",
        SAFE_READONLY,
    ),
    "OWBM-E-SSH-002": Spec(
        EXIT_NETWORK,
        "Не удалось подключиться к {host}:{port}.",
        "{reason}",
        "Проверьте адрес, доступность устройства и настройки SSH.",
        "Если ошибка возникла во время восстановления или переноса, проверьте состояние устройства и сохранённую копию перед восстановлением, если она создана.",
    ),
    "OWBM-E-SSH-003": Spec(
        EXIT_NETWORK,
        "Ключ SSH-хоста {host} не совпадает с сохранённым.",
        "Устройство переустановлено, подменено или ключ был перегенерирован.",
        "Сверьте отпечаток с устройством. Если вы намеренно переустановили или заменили его, "
        "запустите `owbm trust --host {host} --accept-host-key` после повторной проверки.",
        "Если ошибка возникла во время восстановления или переноса, проверьте состояние устройства и сохранённую копию перед восстановлением, если она создана.",
    ),
    "OWBM-E-SSH-004": Spec(
        EXIT_NETWORK,
        "SSH отказал в аутентификации для {user}@{host}.",
        "Неверный пароль, устройство не приняло ключ или нужный ключ не подключён.",
        "Проверьте имя пользователя и пароль или ключ SSH. Если используете SSH agent, "
        "убедитесь, что в него добавлен нужный ключ.",
        SAFE_READONLY,
    ),
    "OWBM-E-SSH-005": Spec(
        EXIT_NETWORK,
        "SSH-операция превысила таймаут {timeout} с.",
        "Устройство не отвечает или передача данных заняла больше времени, чем ожидалось.",
        "Проверьте подключение и состояние устройства. Не повторяйте изменяющую операцию, пока не выясните, успела ли она выполниться.",
        "Неизвестно, успела ли операция изменить устройство; проверьте его состояние и сохранённую копию перед восстановлением, если она создана.",
    ),
    "OWBM-E-SSH-006": Spec(
        EXIT_PREFLIGHT,
        "Ключ SSH-хоста не подтверждён пользователем.",
        "При первом подключении нужно проверить, что SSH-ключ принадлежит вашему устройству.",
        "Сверьте показанный отпечаток с доверенным источником и только затем подтвердите его.",
        SAFE_UNTOUCHED,
    ),
    "OWBM-E-SSH-007": Spec(
        EXIT_PREFLIGHT,
        "Не найдена программа {tool}.",
        "Она нужна для проверки или получения ключа SSH-хоста.",
        "Установите пакет openssh-client (в нём есть {tool}).",
        SAFE_READONLY,
    ),
    "OWBM-E-SSH-008": Spec(
        EXIT_PREFLIGHT,
        "Не удалось получить ключ SSH-хоста {host}:{port}.",
        "{reason}",
        "Убедитесь, что устройство доступно по SSH, и повторите попытку.",
        SAFE_UNTOUCHED,
    ),
    # --- discovery -----------------------------------------------------------
    "OWBM-E-DSC-001": Spec(
        EXIT_DEVICE,
        "Устройство {host} не похоже на OpenWrt.",
        "Устройство не предоставило ожидаемые сведения об OpenWrt.",
        "Проверьте адрес и убедитесь, что SSH ведёт к устройству с OpenWrt.",
        SAFE_READONLY,
    ),
    "OWBM-E-DSC-002": Spec(
        EXIT_DEVICE,
        "Не удалось получить сведения об устройстве.",
        "{reason}",
        "Проверьте доступ по SSH и свободное место на устройстве, затем повторите.",
        SAFE_READONLY,
    ),
    "OWBM-E-DSC-003": Spec(
        EXIT_DEVICE,
        "Не удалось прочитать ответ устройства: {reason}",
        "Устройство ответило в неожиданном формате.",
        "Повторите операцию. Если ошибка повторяется, сохраните подробный журнал для поддержки.",
        SAFE_READONLY,
    ),
    # --- storage -------------------------------------------------------------
    "OWBM-E-STO-001": Spec(
        EXIT_STORAGE,
        "Недостаточно свободного места в {path}: доступно {free}, требуется {need}.",
        "Каталог хранения резервных копий почти заполнен.",
        "Освободите место или укажите другой каталог (--backup-root) — старые архивы программа не удаляет.",
        SAFE_UNTOUCHED,
    ),
    "OWBM-E-STO-002": Spec(
        EXIT_STORAGE,
        "Файл {path} уже существует.",
        "Имена архивов уникальны, и перезапись запрещена.",
        "Это защита от потери данных. Повторите операцию — будет создано новое уникальное имя.",
        SAFE_UNTOUCHED,
    ),
    "OWBM-E-STO-003": Spec(
        EXIT_STORAGE,
        "Нет прав на запись в {path}.",
        "Каталог принадлежит другому пользователю или смонтирован только для чтения.",
        "Выберите другой каталог или исправьте права доступа.",
        SAFE_UNTOUCHED,
    ),
    "OWBM-E-STO-004": Spec(
        EXIT_STORAGE,
        "Папка для резервных копий {path} уже используется другой операцией.",
        "Одновременно выполнять несколько операций с одной папкой небезопасно.",
        "Дождитесь завершения другой операции и повторите попытку.",
        SAFE_UNTOUCHED,
    ),
    # --- archive -------------------------------------------------------------
    "OWBM-E-ARC-001": Spec(
        EXIT_ARCHIVE,
        "Файл не найден или не является архивом OWBM: {path}",
        "Путь указан неверно, файл повреждён или это не архив OWBM.",
        "Проверьте путь (owbm list покажет все архивы). Повреждённый архив восстановлению не подлежит.",
        SAFE_UNTOUCHED,
    ),
    "OWBM-E-FMT-001": Spec(
        EXIT_ARCHIVE,
        "Этот архив создан более новой версией OWBM.",
        "Установленная версия программы не умеет читать такой архив.",
        "Обновите OWBM и проверьте архив снова.",
        SAFE_UNTOUCHED,
    ),
    "OWBM-E-CHK-001": Spec(
        EXIT_ARCHIVE,
        "Файл «{member}» не прошёл проверку целостности.",
        "Архив повреждён или изменён после создания.",
        "Не восстанавливайте этот архив. Используйте другую копию.",
        SAFE_UNTOUCHED,
    ),
    "OWBM-E-CHK-002": Spec(
        EXIT_ARCHIVE,
        "Архив повреждён или неполон: {reason}",
        "В нём отсутствуют необходимые файлы или они пусты.",
        "Используйте другую резервную копию.",
        SAFE_UNTOUCHED,
    ),
    "OWBM-E-CHK-003": Spec(
        EXIT_ARCHIVE,
        "Архив содержит небезопасный путь: {path}",
        "Путь в архиве пытается записать файл за пределами папки восстановления.",
        "Не используйте этот архив. Получите другую копию и сообщите об этом файле как о подозрительном.",
        SAFE_UNTOUCHED,
    ),
    "OWBM-E-CHK-004": Spec(
        EXIT_ARCHIVE,
        "Архив содержит недопустимый объект: {path} ({kind}).",
        "Такой объект нельзя безопасно восстановить из архива.",
        "Не используйте эту копию; выберите другой исправный архив.",
        SAFE_UNTOUCHED,
    ),
    # --- compatibility -------------------------------------------------------
    "OWBM-E-CMP-001": Spec(
        EXIT_INCOMPATIBLE,
        "Архив создан на устройстве с другими характеристиками: {reason}",
        "Настройки или программы из архива могут не подойти этому устройству.",
        "Для переноса на другое устройство используйте `migrate`, проверьте его план и не применяйте неподходящие настройки.",
        SAFE_UNTOUCHED,
    ),
    "OWBM-E-CMP-002": Spec(
        EXIT_INCOMPATIBLE,
        "На целевом устройстве недостаточно места: нужно {need}, доступно {free}.",
        "На устройстве недостаточно места для сохранённых файлов.",
        "Освободите место или выберите в плане восстановления меньше данных.",
        SAFE_UNTOUCHED,
    ),
    "OWBM-E-CMP-003": Spec(
        EXIT_INCOMPATIBLE,
        "Не удалось подготовить безопасный возврат сетевых настроек: {reason}",
        "При обрыве SSH устройство не сможет автоматически вернуть прежнее подключение.",
        "Не меняйте сетевые настройки удалённо без запасного доступа. Исключите их из плана или подключитесь к устройству локально.",
        SAFE_UNTOUCHED,
    ),
    # --- restore -------------------------------------------------------------
    "OWBM-E-RST-001": Spec(
        EXIT_PARTIAL,
        "Восстановление остановилось на шаге {step}: {reason}",
        "Операция не завершена; часть изменений могла примениться.",
        "Не запускайте восстановление повторно вслепую. Проверьте устройство и сохраните копию `pre-restore`.",
        "Перед продолжением проверьте состояние устройства.",
    ),
    "OWBM-E-RST-002": Spec(
        EXIT_PARTIAL,
        "После сбоя на шаге {step} программа вернула прежние сетевые настройки.",
        "{reason}",
        "Проверьте подключение и устройство. Это не обязательно отменяет установку программ и копирование файлов.",
        "Сетевые настройки возвращены; проверьте остальное состояние устройства.",
    ),
    "OWBM-E-INT-001": Spec(
        EXIT_INTERRUPTED,
        "Операция остановлена пользователем.",
        "Вы нажали Ctrl+C или остановили ввод.",
        "Если вы прервали восстановление или перенос, проверьте устройство и сохраните копию перед восстановлением (`pre-restore`), если она создана.",
        "Готовые архивы сохранены. Изменения устройства зависят от прерванной операции; проверьте его состояние.",
    ),
    "OWBM-E-MIG-001": Spec(
        EXIT_USAGE,
        "Выбранные настройки переноса изменились после подготовки плана.",
        "План был подготовлен для других параметров.",
        "Подготовьте план заново и примените его, не меняя выбранные настройки.",
        SAFE_UNTOUCHED,
    ),
    "OWBM-E-MIG-002": Spec(
        EXIT_INCOMPATIBLE,
        "Сведения об устройстве изменились после подготовки переноса.",
        "План мог быть подготовлен для другого устройства или до изменения его настроек.",
        "Проверьте адрес, подготовьте новый план и внимательно сравните его с текущим устройством.",
        "Целевое устройство не изменено; исходный архив не изменён. Снимок pre-restore мог быть создан.",
    ),
    "OWBM-E-MIG-003": Spec(
        EXIT_DEVICE,
        "Не удалось безопасно прочитать сведения об устройстве.",
        "{reason}",
        "Проверьте SSH-подключение и повторите подготовку плана.",
        SAFE_READONLY,
    ),
}

_SAFE_UNTOUCHED_EN = "The device and archives were not modified."
_SAFE_READONLY_EN = "This was a read-only operation."

ENGLISH_CATALOG: Dict[str, Spec] = {
    "OWBM-E-CFG-001": Spec(EXIT_USAGE, "Configuration file {path} cannot be read: {reason}", "The file is damaged, unavailable, or has incorrect permissions.", "Fix or remove the file; without it, OWBM uses its default settings.", _SAFE_READONLY_EN),
    "OWBM-E-CFG-002": Spec(EXIT_USAGE, "Invalid value for setting {key}: {reason}", "The value does not match the expected format.", "Fix the value in the configuration file or set it with a command-line option.", _SAFE_READONLY_EN),
    "OWBM-E-CFG-003": Spec(EXIT_USAGE, "Connection profile {name!r} was not found.", "The saved settings do not contain a profile with that name.", "Specify the device address directly with --host or create a connection profile.", _SAFE_READONLY_EN),
    "OWBM-E-CFG-004": Spec(EXIT_PREFLIGHT, "Required program {tool} was not found.", "It is required for: {purpose}.", "Install it using your distribution's package manager or disable this feature.", _SAFE_READONLY_EN),
    "OWBM-E-SSH-001": Spec(EXIT_PREFLIGHT, "The ssh program was not found.", "The OpenSSH client is not installed or could not be located.", "Install the OpenSSH client using your distribution's package manager.", _SAFE_READONLY_EN),
    "OWBM-E-SSH-002": Spec(EXIT_NETWORK, "Could not connect to {host}:{port}.", "{reason}", "Check the address, device availability, and SSH settings.", "If this happened during restore or migration, check the device and any saved pre-restore archive before trying again."),
    "OWBM-E-SSH-003": Spec(EXIT_NETWORK, "The SSH host key for {host} does not match the saved key.", "The device may have been reinstalled or replaced, or its key may have been regenerated.", "Verify the fingerprint against the device. If you intentionally reinstalled or replaced it, run `owbm trust --host {host} --accept-host-key` after checking it again.", "If this happened during restore or migration, check the device and any saved pre-restore archive before trying again."),
    "OWBM-E-SSH-004": Spec(EXIT_NETWORK, "SSH authentication failed for {user}@{host}.", "The password may be wrong, the device may have rejected the key, or the required key may not be loaded.", "Check the username and password or SSH key. If you use an SSH agent, make sure the required key is loaded.", _SAFE_READONLY_EN),
    "OWBM-E-SSH-005": Spec(EXIT_NETWORK, "The SSH operation timed out after {timeout} seconds.", "The device is not responding, or the transfer took longer than expected.", "Check the connection and device state. Before retrying a modifying operation, determine whether it already ran.", "It is unknown whether the operation changed the device. Check its state and any saved pre-restore archive before trying again."),
    "OWBM-E-SSH-006": Spec(EXIT_PREFLIGHT, "The SSH host key was not confirmed by the user.", "On the first connection, verify that the SSH key belongs to your device.", "Compare the displayed fingerprint with a trusted source, then confirm it.", _SAFE_UNTOUCHED_EN),
    "OWBM-E-SSH-007": Spec(EXIT_PREFLIGHT, "Required program {tool} was not found.", "It is needed to check or retrieve the SSH host key.", "Install the openssh-client package, which provides {tool}.", _SAFE_READONLY_EN),
    "OWBM-E-SSH-008": Spec(EXIT_PREFLIGHT, "Could not retrieve the SSH host key for {host}:{port}.", "{reason}", "Make sure the device is reachable over SSH, then try again.", _SAFE_UNTOUCHED_EN),
    "OWBM-E-DSC-001": Spec(EXIT_DEVICE, "Device {host} does not appear to be running OpenWrt.", "The device did not provide the expected OpenWrt information.", "Check the address and make sure SSH reaches an OpenWrt device.", _SAFE_READONLY_EN),
    "OWBM-E-DSC-002": Spec(EXIT_DEVICE, "Could not retrieve device information.", "{reason}", "Check SSH access and free space on the device, then try again.", _SAFE_READONLY_EN),
    "OWBM-E-DSC-003": Spec(EXIT_DEVICE, "Could not parse the device response: {reason}", "The device returned data in an unexpected format.", "Try again. If the problem persists, save a verbose log for support.", _SAFE_READONLY_EN),
    "OWBM-E-STO-001": Spec(EXIT_STORAGE, "Not enough free space in {path}: {free} available, {need} required.", "The backup storage directory is almost full.", "Free up space or choose another directory with --backup-root. OWBM does not delete old archives.", _SAFE_UNTOUCHED_EN),
    "OWBM-E-STO-002": Spec(EXIT_STORAGE, "File {path} already exists.", "Archive names are unique and overwriting is disabled.", "This prevents data loss. Try again to create a new archive with a unique name.", _SAFE_UNTOUCHED_EN),
    "OWBM-E-STO-003": Spec(EXIT_STORAGE, "No permission to write to {path}.", "The directory belongs to another user or is mounted read-only.", "Choose another directory or fix its permissions.", _SAFE_UNTOUCHED_EN),
    "OWBM-E-STO-004": Spec(EXIT_STORAGE, "Backup directory {path} is already in use by another operation.", "Running multiple operations on the same directory at once is unsafe.", "Wait for the other operation to finish, then try again.", _SAFE_UNTOUCHED_EN),
    "OWBM-E-ARC-001": Spec(EXIT_ARCHIVE, "File was not found or is not an OWBM archive: {path}", "The path may be wrong, the file may be damaged, or it may not be an OWBM archive.", "Check the path (`owbm list` shows available archives). A damaged archive cannot be restored.", _SAFE_UNTOUCHED_EN),
    "OWBM-E-FMT-001": Spec(EXIT_ARCHIVE, "This archive was created by a newer version of OWBM.", "The installed version cannot read this archive format.", "Update OWBM and check the archive again.", _SAFE_UNTOUCHED_EN),
    "OWBM-E-CHK-001": Spec(EXIT_ARCHIVE, "Integrity check failed for archive member {member!r}.", "The archive is damaged or was modified after it was created.", "Do not restore this archive. Use another copy.", _SAFE_UNTOUCHED_EN),
    "OWBM-E-CHK-002": Spec(EXIT_ARCHIVE, "Archive is damaged or incomplete: {reason}", "Required files are missing or empty.", "Use another backup.", _SAFE_UNTOUCHED_EN),
    "OWBM-E-CHK-003": Spec(EXIT_ARCHIVE, "Archive contains an unsafe path: {path}", "A path in the archive would write a file outside the restore directory.", "Do not use this archive. Obtain another copy and report the suspicious file.", _SAFE_UNTOUCHED_EN),
    "OWBM-E-CHK-004": Spec(EXIT_ARCHIVE, "Archive contains an unsupported object: {path} ({kind}).", "This object cannot be restored safely from the archive.", "Do not use this copy; choose another valid archive.", _SAFE_UNTOUCHED_EN),
    "OWBM-E-CMP-001": Spec(EXIT_INCOMPATIBLE, "The archive was created on a device with different characteristics: {reason}", "Settings or software from the archive may not work on this device.", "To move to another device, use `migrate`, review its plan, and do not apply unsuitable settings.", _SAFE_UNTOUCHED_EN),
    "OWBM-E-CMP-002": Spec(EXIT_INCOMPATIBLE, "Not enough space on the target device: {need} required, {free} available.", "The device does not have enough space for the saved files.", "Free up space or select less data in the restore plan.", _SAFE_UNTOUCHED_EN),
    "OWBM-E-CMP-003": Spec(EXIT_INCOMPATIBLE, "Could not prepare a safe rollback for network settings: {reason}", "If SSH disconnects, the device will not be able to restore the previous connection automatically.", "Do not change network settings remotely without another way to access the device. Exclude them from the plan or connect locally.", _SAFE_UNTOUCHED_EN),
    "OWBM-E-RST-001": Spec(EXIT_PARTIAL, "Restore stopped at step {step}: {reason}", "The operation did not finish; some changes may have been applied.", "Do not blindly run restore again. Check the device and save the `pre-restore` archive.", "Check the device state before continuing."),
    "OWBM-E-RST-002": Spec(EXIT_PARTIAL, "After step {step} failed, OWBM restored the previous network settings.", "{reason}", "Check the connection and device. This does not necessarily undo package installation or file copying.", "Network settings were restored; check the rest of the device state."),
    "OWBM-E-INT-001": Spec(EXIT_INTERRUPTED, "Operation stopped by the user.", "You pressed Ctrl+C or stopped input.", "If you interrupted a restore or migration, check the device and save a pre-restore archive if one was created.", "Completed archives were preserved. Device changes depend on which operation was interrupted; check the device state."),
    "OWBM-E-MIG-001": Spec(EXIT_USAGE, "The selected migration settings changed after the plan was prepared.", "The plan was prepared with different options.", "Prepare the plan again and apply it without changing the selected options.", _SAFE_UNTOUCHED_EN),
    "OWBM-E-MIG-002": Spec(EXIT_INCOMPATIBLE, "Device information changed after the migration plan was prepared.", "The plan may have been prepared for another device or before its settings changed.", "Check the address, prepare a new plan, and compare it carefully with the target device.", "The target device and source archive were not modified. A pre-restore snapshot may have been created."),
    "OWBM-E-MIG-003": Spec(EXIT_DEVICE, "Could not safely read device information.", "{reason}", "Check the SSH connection and prepare the plan again.", _SAFE_READONLY_EN),
}

_ENGLISH_UNKNOWN = Spec(
    EXIT_DEVICE,
    "Unexpected error.",
    "The cause of the error could not be determined.",
    "Run the program with --verbose and save the log.",
    "The device state is unknown; check it manually.",
)


class OwbmError(Exception):
    """Typed error with stable code and user-facing explanation."""

    def __init__(self, code: str, **context: Any) -> None:
        self.code = code
        self.context: Dict[str, Any] = context
        self._ru_spec = CATALOG.get(code, _UNKNOWN)
        self.exit_code = self._ru_spec.exit_code
        self.missing_context = self._missing()
        super().__init__(self.message)

    @property
    def spec(self) -> Spec:
        if i18n.get_language() == "en":
            return ENGLISH_CATALOG.get(self.code, _ENGLISH_UNKNOWN)
        return self._ru_spec

    def _fmt(self, template: str) -> str:
        values = dict(self.context)
        for field in ("reason", "step", "kind"):
            value = values.get(field)
            if isinstance(value, str):
                values[field] = i18n.localize_text(value)
        try:
            return template.format(**values)
        except (KeyError, IndexError):
            return template

    def _missing(self) -> list[str]:
        import string

        out = []
        try:
            fields = [
                f for _, f, _, _ in string.Formatter().parse(self._ru_spec.what) if f
            ]
        except ValueError:
            return out
        for name in fields:
            if name not in self.context:
                out.append(name)
        return out

    @property
    def what(self) -> str:
        return self._fmt(self.spec.what)

    @property
    def why(self) -> str:
        return self._fmt(self.spec.why)

    @property
    def fix(self) -> str:
        return self._fmt(self.spec.fix)

    @property
    def safe(self) -> str:
        return self._fmt(self.spec.safe)

    @property
    def message(self) -> str:
        return f"[{self.code}] {self.what}"

    def render(self) -> str:
        lines = [
            i18n.tr("common.error.title", code=self.code),
            f"  {i18n.tr('common.error.what_happened')}: {self.what}",
        ]
        if self.why:
            lines.append(f"  {i18n.tr('common.error.why')}: {self.why}")
        if self.fix:
            lines.append(f"  {i18n.tr('common.error.how_to_fix')}: {self.fix}")
        if self.safe:
            lines.append(f"  {i18n.tr('common.error.safe_to_continue')}: {self.safe}")
        return "\n".join(lines)

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "code": self.code,
            "what": self.what,
            "why": self.why,
            "fix": self.fix,
            "safe": self.safe,
            "exit_code": self.exit_code,
        }


def fail(code: str, **context: Any) -> "OwbmError":
    return OwbmError(code, **context)


EXIT_NAME_KEYS = {
    EXIT_OK: "common.error.exit_ok",
    EXIT_USAGE: "common.error.exit_usage",
    EXIT_PREFLIGHT: "common.error.exit_preflight",
    EXIT_INCOMPATIBLE: "common.error.exit_incompatible",
    EXIT_NETWORK: "common.error.exit_network",
    EXIT_DEVICE: "common.error.exit_device",
    EXIT_ARCHIVE: "common.error.exit_archive",
    EXIT_STORAGE: "common.error.exit_storage",
    EXIT_PARTIAL: "common.error.exit_partial",
    EXIT_INTERRUPTED: "common.error.exit_interrupted",
}
EXIT_NAMES = {code: i18n.tr(key, language="ru") for code, key in EXIT_NAME_KEYS.items()}


def exit_name(code: int, language: Optional[str] = None) -> str:
    key = EXIT_NAME_KEYS.get(code)
    return i18n.tr(key, language=language) if key else "unknown exit code"


def catalog_markdown(language: str = "ru") -> str:
    """Render the error catalog in one locale for the generated documentation."""
    locale = i18n.normalize_language(language)
    if locale == "en":
        title = "# Troubleshooting errors"
        intro = (
            "Find the same code in the program output. This reference explains the cause, "
            "possible fixes, and whether it is safe to continue. Values in braces are "
            "replaced with details from your message. A `pre-restore` archive is a snapshot "
            "of the target device's settings made before restore. In examples, `owbm` is "
            "the installed command; for a downloaded `owbm.pyz`, use `python3 owbm.pyz`, "
            "or run `./openwrt-brm` from the source directory."
        )
        code_heading, value_heading = "Code", "Meaning"
        errors_heading = "Error messages"
    else:
        title = "# Если появилась ошибка"
        intro = (
            "Найдите такой же код в сообщении программы. Ниже объяснены причина ошибки, "
            "что можно сделать и безопасно ли продолжать. Значения в фигурных скобках "
            "заменяются конкретными данными из вашего сообщения. Копия перед "
            "восстановлением (`pre-restore`) — это сохранённые настройки целевого "
            "устройства. В примерах `owbm` — установленная команда; для скачанного "
            "`owbm.pyz` используйте `python3 owbm.pyz`, а из исходного каталога — "
            "`./openwrt-brm`."
        )
        code_heading, value_heading = "Код", "Значение"
        errors_heading = "Сообщения об ошибках"
    lines = [
        title,
        "",
        intro,
        "",
        "## Exit codes" if locale == "en" else "## Коды завершения",
        "",
        f"| {code_heading} | {value_heading} |",
        "| --- | --- |",
    ]
    for code in sorted(EXIT_NAME_KEYS):
        lines.append(f"| {code} | {exit_name(code, locale)} |")
    lines += ["", f"## {errors_heading}", ""]
    for code in sorted(CATALOG):
        spec = ENGLISH_CATALOG.get(code, _ENGLISH_UNKNOWN) if locale == "en" else CATALOG[code]
        if locale == "en":
            labels = ("What happened", "Why", "How to fix", "Is it safe to continue")
        else:
            labels = ("Что произошло", "Почему", "Как исправить", "Можно ли продолжать")
        lines += [
            f"### {code}",
            "",
            f"- {labels[0]}: {spec.what}",
            f"- {labels[1]}: {spec.why}",
            f"- {labels[2]}: {spec.fix}",
            f"- {labels[3]}: {spec.safe}",
            "",
        ]
    return "\n".join(lines)
