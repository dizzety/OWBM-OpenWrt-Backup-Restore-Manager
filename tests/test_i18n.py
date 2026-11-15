import ast
import string
from pathlib import Path

from owbm import i18n


def test_every_message_has_both_locales():
    assert i18n.MESSAGES
    for key, translations in i18n.MESSAGES.items():
        assert translations.get("ru"), key
        assert translations.get("en"), key


def test_language_context_restores_previous_value():
    token = i18n.set_language("en")
    try:
        assert i18n.get_language() == "en"
        with i18n.language_context("ru"):
            assert i18n.get_language() == "ru"
        assert i18n.get_language() == "en"
    finally:
        i18n.reset_language(token)
    assert i18n.get_language() == "ru"


def test_translate_formats_values_and_uses_requested_language():
    assert i18n.tr("menu.storage", language="en", path="/tmp/backups") == "Storage: /tmp/backups"
    assert i18n.tr("menu.storage", language="ru", path="/tmp/backups") == "Хранилище: /tmp/backups"
    assert i18n.tr("menu.io.yes_default", language="ru") == "[Д/н]"
    assert i18n.tr("menu.io.no_default", language="ru") == "[д/Н]"


def test_unknown_language_falls_back_to_russian():
    assert i18n.normalize_language("fr") == "ru"
    assert i18n.tr("menu.goodbye", language="fr") == "До свидания."


def test_missing_format_value_does_not_crash():
    assert i18n.tr("menu.storage", language="en") == "Storage: {path}"


def test_unknown_message_key_is_visible_for_diagnosis():
    assert i18n.tr("missing.message.key") == "missing.message.key"


def test_localize_text_translates_known_dynamic_messages_only():
    assert i18n.localize_text("элемент payload/config.json превышает предел 4096 байт", language="en") == (
        "member payload/config.json exceeds the 4096-byte limit"
    )
    assert i18n.localize_text("custom device label", language="en") == "custom device label"
    assert i18n.localize_text("custom: device label", language="en") == "custom: device label"
    assert i18n.localize_text("manifest.json: отсутствует поле archive_id", language="en") == (
        "manifest.json: missing field archive_id"
    )
    assert i18n.localize_text(
        "пользовательские каталоги: /srv/my-router/config", language="en"
    ) == "user directories: /srv/my-router/config"
    assert i18n.localize_text("custom device: /srv/my-router", language="en") == (
        "custom device: /srv/my-router"
    )
    assert i18n.localize_text("apk: 12 пакетов", language="en") == "apk: 12 packages"
    assert i18n.localize_text("user directories: /srv/router", language="ru") == (
        "пользовательские каталоги: /srv/router"
    )
    assert i18n.localize_text("apk: 12 packages", language="ru") == "apk: 12 пакетов"
    english_capability = (
        "Root filesystem compressed read-only image (squashfs) will be copied except for "
        "/proc, /sys, /dev, /tmp, /boot, and other mount points."
    )
    assert i18n.localize_text(english_capability, language="ru") == (
        "Корневая ФС — сжатый образ только для чтения (squashfs): копируется целиком, "
        "кроме /proc, /sys, /dev, /tmp, /boot и других точек монтирования."
    )
    assert i18n.localize_text(i18n.tr("util.clock.past", language="ru"), language="en") == (
        i18n.tr("util.clock.past", language="en")
    )


def test_static_translation_calls_resolve_to_catalog_entries():
    source_root = Path(__file__).resolve().parents[1] / "src" / "owbm"
    missing = []
    for path in source_root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr != "tr" or not node.args or not isinstance(node.args[0], ast.Constant):
                continue
            key = node.args[0].value
            if isinstance(key, str) and key not in i18n.MESSAGES:
                missing.append(f"{path}:{node.lineno}: {key}")
    assert not missing, "Missing translations:\n" + "\n".join(missing)


def test_translations_use_the_same_format_fields():
    for key, translations in i18n.MESSAGES.items():
        fields = {
            field
            for _, field, _, _ in string.Formatter().parse(translations["ru"])
            if field
        }
        translated_fields = {
            field
            for _, field, _, _ in string.Formatter().parse(translations["en"])
            if field
        }
        assert translated_fields == fields, key
