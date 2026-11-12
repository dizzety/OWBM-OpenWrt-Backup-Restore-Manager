import re
from pathlib import Path

import pytest

from owbm import errors


def test_every_code_is_well_formed():
    pattern = re.compile(r"OWBM-E-[A-Z]{3}-\d{3}$")
    for code in errors.CATALOG:
        assert pattern.match(code), code


def test_every_message_has_four_answers():
    for code, spec in errors.CATALOG.items():
        assert spec.what, code
        assert spec.why, code
        assert spec.fix, code
        assert spec.safe, code
        assert spec.exit_code in errors.EXIT_NAMES, code


def test_render_contains_all_sections():
    error = errors.OwbmError("OWBM-E-STO-002", path="/tmp/a.owbm")
    text = error.render()
    assert "OWBM-E-STO-002" in text
    assert "Что произошло:" in text
    assert "Почему:" in text
    assert "Как исправить:" in text
    assert "Можно ли продолжать:" in text
    assert "/tmp/a.owbm" in text


def test_missing_context_does_not_crash():
    error = errors.OwbmError("OWBM-E-CMP-001")
    assert error.code == "OWBM-E-CMP-001"
    assert error.exit_code == errors.EXIT_INCOMPATIBLE
    assert isinstance(error.render(), str)


def test_docs_match_catalog():
    doc = Path(__file__).resolve().parents[1] / "docs" / "ERRORS.md"
    assert doc.exists(), "docs/ERRORS.md must be generated from the catalog"
    assert doc.read_text(encoding="utf-8") == errors.catalog_markdown(), (
        "docs/ERRORS.md устарел: перегенерируйте из errors.catalog_markdown()"
    )


def test_partial_success_has_own_exit_code():
    assert errors.EXIT_PARTIAL != errors.EXIT_OK
    assert errors.OwbmError("OWBM-E-RST-001").exit_code == errors.EXIT_PARTIAL


@pytest.mark.parametrize("code", sorted(errors.CATALOG))
def test_as_dict_is_json_shaped(code):
    payload = errors.OwbmError(code).as_dict()
    assert set(payload) == {"code", "what", "why", "fix", "safe", "exit_code"}
