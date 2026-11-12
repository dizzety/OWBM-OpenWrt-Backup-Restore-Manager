"""Compatibility model: every check has a verdict, a severity and a mitigation.

The same comparison serves two strategies. For Exact Restore a mismatch is
blocking; for Migration Restore the same mismatch becomes a planned adaptation.
Only facts that make data loss certain stay blocking in both.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from ..discovery import DevicePassport
from ..manifest import STATUS_COMPLETE, Manifest

VERDICT_MATCH = "match"
VERDICT_ACCEPTABLE = "acceptable"
VERDICT_MISMATCH = "mismatch"
VERDICT_UNKNOWN = "unknown"

SEVERITY_BLOCKING = "blocking"
SEVERITY_WARNING = "warning"
SEVERITY_INFO = "info"

STRATEGY_EXACT = "exact"
STRATEGY_MIGRATION = "migration"
STRATEGY_SELECTIVE = "selective"

LEVEL_EXACT = "exact"
LEVEL_MIGRATION = "migration"
LEVEL_INCOMPATIBLE = "incompatible"

_VERDICT_MARK = {
    VERDICT_MATCH: "✓",
    VERDICT_ACCEPTABLE: "~",
    VERDICT_MISMATCH: "✗",
    VERDICT_UNKNOWN: "?",
}


@dataclass(frozen=True)
class Check:
    name: str
    title: str
    source: str
    target: str
    verdict: str
    severity: str
    explanation: str
    mitigation: str = ""

    @property
    def blocking(self) -> bool:
        return self.verdict == VERDICT_MISMATCH and self.severity == SEVERITY_BLOCKING

    @property
    def mark(self) -> str:
        return _VERDICT_MARK.get(self.verdict, "?")

    def as_dict(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "title": self.title,
            "source": self.source,
            "target": self.target,
            "verdict": self.verdict,
            "severity": self.severity,
            "explanation": self.explanation,
            "mitigation": self.mitigation,
        }


@dataclass
class CompatibilityReport:
    strategy: str
    level: str = LEVEL_INCOMPATIBLE
    checks: List[Check] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def blocking(self) -> List[Check]:
        return [item for item in self.checks if item.blocking]

    @property
    def mismatches(self) -> List[Check]:
        return [item for item in self.checks if item.verdict == VERDICT_MISMATCH]

    @property
    def ok(self) -> bool:
        return not self.blocking

    def as_dict(self) -> Dict[str, object]:
        return {
            "strategy": self.strategy,
            "level": self.level,
            "ok": self.ok,
            "checks": [item.as_dict() for item in self.checks],
            "notes": list(self.notes),
        }

    def describe(self) -> List[str]:
        lines = []
        for item in self.checks:
            line = f"  {item.mark} {item.title:<32} {item.source or '—':<28} → {item.target or '—'}"
            if item.explanation:
                line += f"   {item.explanation}"
            lines.append(line)
            if item.mitigation:
                lines.append(f"      → {item.mitigation}")
        return lines


def _major_minor(version: str) -> str:
    parts = version.split("-")[0].split(".")[:2]
    return ".".join(parts)


def _writable_layer(passport: DevicePassport) -> str:
    storage = passport.storage
    if storage.overlay and storage.overlay.upperdir:
        return "overlayfs"
    if storage.extroot:
        return "extroot"
    return "filesystem"


def compare(
    parsed: Manifest,
    passport: DevicePassport,
    *,
    strategy: str = STRATEGY_EXACT,
    selected: Optional[Sequence[str]] = None,
) -> CompatibilityReport:
    key = parsed.compatibility_key
    identity = passport.identity
    report = CompatibilityReport(strategy=strategy)

    exact = strategy in (STRATEGY_EXACT,)

    def add(
        name: str,
        title: str,
        source: str,
        target: str,
        *,
        base_severity: str = SEVERITY_BLOCKING,
        explanation: str = "",
        mitigation: str = "",
        severity: Optional[str] = None,
    ) -> None:
        if not source or not target or source.lower() in ("unknown", "none") or target.lower() in ("unknown", "none"):
            verdict = VERDICT_UNKNOWN
        elif source == target:
            verdict = VERDICT_MATCH
        else:
            verdict = VERDICT_MISMATCH
        if severity is not None:
            sev = severity
        elif verdict == VERDICT_UNKNOWN:
            sev = SEVERITY_WARNING
        elif verdict == VERDICT_MATCH:
            sev = SEVERITY_INFO
        else:
            sev = base_severity if exact else SEVERITY_WARNING
        report.checks.append(
            Check(
                name=name,
                title=title,
                source=source or "—",
                target=target or "—",
                verdict=verdict,
                severity=sev,
                explanation=explanation,
                mitigation=mitigation if verdict == VERDICT_MISMATCH else "",
            )
        )

    add(
        "board_id",
        "Плата устройства",
        key.get("board_id", ""),
        identity.board_id,
        explanation="основа совместимости драйверов и конфигурации оборудования",
        mitigation="потребуется адаптация: сетевые интерфейсы, Wi-Fi и параметры оборудования",
    )
    add(
        "target",
        "Цель сборки (target)",
        key.get("target", ""),
        identity.target,
        explanation="разные target — разные наборы драйверов и ядер",
        mitigation="ядерные модули и системные пакеты не переносятся",
    )
    add(
        "arch",
        "Архитектура",
        key.get("arch", ""),
        identity.arch,
        explanation="бинарные пакеты другой архитектуры неприменимы",
        mitigation="бинарные пакеты будут исключены, потребуется переустановка из репозиториев",
    )
    add(
        "package_manager",
        "Пакетный менеджер",
        key.get("package_manager", ""),
        passport.packages.manager,
        explanation="APK и OPKG несовместимы по формату и базе",
        mitigation="список пакетов будет пересобран под доступный менеджер",
    )
    add(
        "kernel_package",
        "Версия пакета ядра",
        key.get("kernel_package", ""),
        identity.kernel_package,
        explanation="модули ядра привязаны к точной версии пакета",
        mitigation="модули ядра не переносятся; потребуется установка пакетов ядра целевой системы",
    )
    add(
        "kernel_release",
        "Версия ядра",
        key.get("kernel_release", ""),
        identity.kernel_release,
        explanation="разные ядра несовместимы по модулям и символам",
        mitigation="перезагрузка и проверка модулей обязательны",
    )
    add(
        "writable_layer",
        "Схема хранения",
        key.get("writable_layer", ""),
        _writable_layer(passport),
        base_severity=SEVERITY_WARNING,
        explanation="набор файлов зависит от того, где хранится записываемый слой",
        mitigation="файлы будут разложены по объединённой файловой системе цели",
    )

    # free space ------------------------------------------------------------
    components = _selected_components(parsed, selected)
    need = sum(int(item.uncompressed_size or 0) for item in components)
    free = passport.storage.free_bytes_writable
    if need <= 0:
        verdict, sev, explanation = VERDICT_UNKNOWN, SEVERITY_WARNING, "объём распаковки неизвестен"
    elif free is None:
        verdict, sev, explanation = VERDICT_UNKNOWN, SEVERITY_WARNING, "свободное место на цели не определено"
    elif free >= int(need * 1.2):
        verdict, sev, explanation = VERDICT_MATCH, SEVERITY_INFO, ""
    elif free >= need:
        verdict, sev, explanation = VERDICT_ACCEPTABLE, SEVERITY_WARNING, "места впритык"
    else:
        verdict, sev, explanation = VERDICT_MISMATCH, SEVERITY_BLOCKING, "данные не поместятся в записываемый слой"
    from ..util import human_size

    report.checks.append(
        Check(
            name="free_space",
            title="Свободное место на цели",
            source=human_size(need) if need else "—",
            target=human_size(free) if free is not None else "неизвестно",
            verdict=verdict,
            severity=sev,
            explanation=explanation,
            mitigation="освободите место или выберите меньше категорий (Selective Restore)"
            if verdict == VERDICT_MISMATCH
            else "",
        )
    )

    # sysupgrade availability ----------------------------------------------
    if any(item.id == "configuration" for item in components):
        available = passport.tools.sysupgrade.supports_restore
        report.checks.append(
            Check(
                name="sysupgrade_restore",
                title="sysupgrade -r на цели",
                source="требуется",
                target="доступен" if available else "недоступен",
                verdict=VERDICT_MATCH if available else VERDICT_ACCEPTABLE,
                severity=SEVERITY_INFO if available else SEVERITY_WARNING,
                explanation="" if available else "конфигурация будет распакована пофайлово",
                mitigation="" if available else "файлы /etc/config восстанавливаются напрямую",
            )
        )

    # archive completeness -------------------------------------------------
    if parsed.status != STATUS_COMPLETE:
        report.notes.append(
            f"Архив неполный (статус {parsed.status}): восстановление затронет только сохранённые категории."
        )
    if parsed.clock_warning:
        report.notes.append(f"Время создания архива вызывало вопросы: {parsed.clock_warning}")

    # level ----------------------------------------------------------------
    if report.blocking:
        report.level = LEVEL_INCOMPATIBLE
    elif strategy == STRATEGY_EXACT and not report.mismatches:
        report.level = LEVEL_EXACT
    else:
        report.level = LEVEL_MIGRATION
    return report


def _selected_components(parsed: Manifest, selected: Optional[Sequence[str]]):
    if not selected:
        return list(parsed.components)
    wanted = set(selected)
    return [item for item in parsed.components if item.id in wanted]


def raise_if_blocked(report: CompatibilityReport) -> None:
    from ..errors import fail

    blocking = report.blocking
    if not blocking:
        return
    first = blocking[0]
    reason = f"{first.title}: в архиве «{first.source}», на устройстве «{first.target}»"
    if first.name == "free_space":
        raise fail(
            "OWBM-E-CMP-002",
            need=first.source,
            free=first.target,
        )
    raise fail("OWBM-E-CMP-001", reason=reason)
