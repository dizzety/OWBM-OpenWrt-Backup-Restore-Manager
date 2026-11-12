"""Error catalog: one stable code per failure mode.

Every error carries four user-facing answers: what happened, why, how to fix it,
and whether it is safe to continue. Codes are stable API: never reuse them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping

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


class OwbmError(Exception):
    """Typed error with stable code and user-facing explanation."""

    def __init__(self, code: str, **context: Any) -> None:
        self.code = code
        self.context: Dict[str, Any] = context
        spec = CATALOG.get(code)
        self.spec = spec or Spec(
            _UNKNOWN.exit_code,
            _UNKNOWN.what,
            _UNKNOWN.why,
            _UNKNOWN.fix,
            _UNKNOWN.safe,
        )
        self.exit_code = self.spec.exit_code
        self.missing_context = self._missing()
        super().__init__(self.message)

    def _fmt(self, template: str) -> str:
        try:
            return template.format(**self.context)
        except (KeyError, IndexError):
            return template

    def _missing(self) -> list[str]:
        import string

        out = []
        try:
            fields = [
                f for _, f, _, _ in string.Formatter().parse(self.spec.what) if f
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
        lines = [f"Ошибка {self.code}", f"  Что произошло: {self.what}"]
        if self.why:
            lines.append(f"  Почему: {self.why}")
        if self.fix:
            lines.append(f"  Как исправить: {self.fix}")
        if self.safe:
            lines.append(f"  Можно ли продолжать: {self.safe}")
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


EXIT_NAMES = {
    EXIT_OK: "успех",
    EXIT_USAGE: "ошибка команды или настройки",
    EXIT_PREFLIGHT: "не выполнены условия для запуска",
    EXIT_INCOMPATIBLE: "архив не подходит устройству",
    EXIT_NETWORK: "проблема с сетью или SSH",
    EXIT_DEVICE: "ошибка устройства",
    EXIT_ARCHIVE: "проблема с архивом",
    EXIT_STORAGE: "проблема с местом или правами доступа",
    EXIT_PARTIAL: "операция выполнена не полностью; прочитайте сообщение",
    EXIT_INTERRUPTED: "операция остановлена",
}


def catalog_markdown() -> str:
    """Render this catalog as documentation. docs/ERRORS.md is generated from here."""
    lines = [
        "# Если появилась ошибка",
        "",
        "Найдите такой же код в сообщении программы. Ниже объяснены причина ошибки, "
        "что можно сделать и безопасно ли продолжать. Значения в фигурных скобках "
        "заменяются конкретными данными из вашего сообщения. Копия перед "
        "восстановлением (`pre-restore`) — это сохранённые настройки целевого "
        "устройства. В примерах `owbm` — установленная команда; для скачанного "
        "`owbm.pyz` используйте `python3 owbm.pyz`, а из исходного каталога — "
        "`./openwrt-brm`.",
        "",
        "## Коды завершения",
        "",
        "| Код | Значение |",
        "| --- | --- |",
    ]
    for code in sorted(EXIT_NAMES):
        lines.append(f"| {code} | {EXIT_NAMES[code]} |")
    lines += ["", "## Сообщения об ошибках", ""]
    for code in sorted(CATALOG):
        spec = CATALOG[code]
        lines += [
            f"### {code}",
            "",
            f"- Что произошло: {spec.what}",
            f"- Почему: {spec.why}",
            f"- Как исправить: {spec.fix}",
            f"- Можно ли продолжать: {spec.safe}",
            "",
        ]
    return "\n".join(lines)
