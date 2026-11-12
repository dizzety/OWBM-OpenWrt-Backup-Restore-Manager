import json

import pytest

from owbm import archive, manifest
from owbm.errors import OwbmError


def _component(**kwargs):
    base = dict(
        id="configuration",
        path="payload/configuration.tar.gz",
        support_level="exact",
        portability="portable",
        critical=True,
        sha256="c" * 64,
        size=100,
        restore_order=10,
    )
    base.update(kwargs)
    return manifest.Component(**base)


def _build(**kwargs):
    base = dict(
        archive_id="11111111-2222-3333-4444-555555555555",
        created_utc="2026-11-09T09:15:00Z",
        mode="backup",
        device={"board_id": "generic", "arch": "x86_64", "target": "x86/64"},
        capabilities_snapshot={"storage": {"overlay": {"upperdir": "/overlay/upper"}}},
        components=[_component()],
        inventory={},
        status=manifest.STATUS_COMPLETE,
    )
    base.update(kwargs)
    return manifest.build(**base)


def test_build_and_validate_roundtrip():
    obj = _build()
    data = obj.as_dict()
    parsed = manifest.validate(data)
    assert parsed.archive_id == obj.archive_id
    assert parsed.status == manifest.STATUS_COMPLETE
    assert parsed.components[0].id == "configuration"
    assert parsed.compatibility_key["writable_layer"] == "overlayfs"
    assert parsed.compatibility_key["arch"] == "x86_64"


def test_components_are_ordered_by_restore_order():
    obj = _build(
        components=[
            _component(id="system_state", path="payload/system-state.tar.gz", restore_order=60, critical=False),
            _component(restore_order=10),
        ]
    )
    assert [item.id for item in obj.components] == ["configuration", "system_state"]


def test_manifest_has_no_machine_specific_fields():
    data = _build().as_dict()
    text = json.dumps(data)
    assert "/home/" not in text
    assert "/tmp/" not in text


@pytest.mark.parametrize(
    "mutate, code",
    [
        (lambda d: d.pop("archive_id"), "OWBM-E-CHK-002"),
        (lambda d: d.update(archive_id="not-a-uuid"), "OWBM-E-CHK-002"),
        (lambda d: d.update(format="other"), "OWBM-E-ARC-001"),
        (lambda d: d.update(format_version=99), "OWBM-E-FMT-001"),
        (lambda d: d.update(created_utc="вчера"), "OWBM-E-CHK-002"),
        (lambda d: d.update(components=[]), "OWBM-E-CHK-002"),
        (lambda d: d.update(mode="unknown"), "OWBM-E-CHK-002"),
        (lambda d: d.update(completeness={"status": "maybe"}), "OWBM-E-CHK-002"),
        (lambda d: d["components"][0].update(id="secrets"), "OWBM-E-CHK-002"),
        (lambda d: d["components"][0].update(path="/etc/passwd"), "OWBM-E-CHK-002"),
        (lambda d: d["components"][0].update(sha256="short"), "OWBM-E-CHK-002"),
        (lambda d: d["components"][0].update(size=0), "OWBM-E-CHK-002"),
        (lambda d: d["device"].pop("arch"), "OWBM-E-CHK-002"),
    ],
)
def test_validation_rejects(mutate, code):
    data = _build().as_dict()
    mutate(data)
    with pytest.raises(OwbmError) as exc:
        manifest.validate(data)
    assert exc.value.code == code


def test_partial_status_is_allowed_and_reported():
    obj = _build(status=manifest.STATUS_PARTIAL, warnings=["не сохранено: user_data"])
    parsed = manifest.validate(obj.as_dict())
    assert parsed.status == manifest.STATUS_PARTIAL
    assert parsed.completeness["warnings"]


def test_unknown_fields_are_ignored():
    data = _build().as_dict()
    data["future_field"] = {"anything": 1}
    assert manifest.validate(data).archive_id == data["archive_id"]


def test_compatibility_key_variants():
    extroot = manifest.compatibility_key(
        {"board_id": "b", "arch": "mips"},
        {"storage": {"overlay": None, "extroot": True}},
    )
    assert extroot["writable_layer"] == "extroot"
    plain = manifest.compatibility_key({"board_id": "b"}, {"storage": {}})
    assert plain["writable_layer"] == "filesystem"
