import hashlib
import json
import struct
import zipfile
from pathlib import Path

import pytest

from owbm import archive, manifest
from owbm.errors import OwbmError


def _component(**kwargs) -> manifest.Component:
    base = dict(
        id="configuration",
        path="payload/configuration.tar.gz",
        support_level="exact",
        portability="portable",
        critical=True,
        sha256="a" * 64,
        size=100,
        restore_order=10,
    )
    base.update(kwargs)
    return manifest.Component(**base)


def _manifest(**kwargs) -> dict:
    base = dict(
        archive_id="11111111-2222-3333-4444-555555555555",
        created_utc="2026-11-09T09:15:00Z",
        mode="backup",
        device={"board_id": "generic", "arch": "x86_64", "release": "24.10.0"},
        capabilities_snapshot={},
        components=[_component()],
        inventory={},
        status=manifest.STATUS_COMPLETE,
    )
    base.update(kwargs)
    return manifest.build(**base).as_dict()


def _write(tmp_path: Path, files: dict) -> Path:
    members = []
    for name, data in files.items():
        members.append(archive.Member(name, data=data, compress=True))
    path = tmp_path / "test.owbm"
    archive.write_archive(path, members)
    return path


def test_roundtrip_and_checksums(tmp_path):
    path = _write(tmp_path, {"manifest.json": json.dumps(_manifest()).encode(), "inventory/x.json": b"{}"})
    report = archive.verify_archive(path)
    assert report.ok, report.issues
    assert report.members == 3  # two members plus the checksum list
    assert report.checksums_verified == 2
    assert archive.read_manifest(path)["format"] == "owbm"


def test_payload_from_file(tmp_path):
    payload = tmp_path / "blob.bin"
    payload.write_bytes(b"x" * 5000)
    path = tmp_path / "file.owbm"
    archive.write_archive(
        path,
        [
            archive.Member("manifest.json", data=json.dumps(_manifest()).encode()),
            archive.Member("payload/configuration.tar.gz", source=payload),
        ],
    )
    report = archive.verify_archive(path)
    assert report.ok, report.issues
    assert report.payload_bytes == 5000


def test_tampering_is_detected(tmp_path):
    path = _write(tmp_path, {"manifest.json": json.dumps(_manifest()).encode(), "inventory/x.json": b"{}"})
    # rewrite the archive with different content but the old checksum file
    with zipfile.ZipFile(path, "a") as zf:
        zf.writestr("inventory/extra.json", b"violation")
    report = archive.verify_archive(path)
    assert not report.ok
    assert any("OWBM-E-CHK-002" == issue.code for issue in report.issues)


def test_checksum_mismatch(tmp_path):
    path = tmp_path / "x.owbm"
    body = b"{}"
    manifest_bytes = json.dumps(_manifest()).encode()
    sums = (
        f"{hashlib.sha256(manifest_bytes).hexdigest()}  manifest.json\n"
        f"{hashlib.sha256(b'nope').hexdigest()}  inventory/x.json\n"
    )
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("manifest.json", manifest_bytes)
        zf.writestr("inventory/x.json", body)
        zf.writestr(archive.CHECKSUMS_NAME, sums)
    report = archive.verify_archive(path)
    assert not report.ok
    assert any(issue.code == "OWBM-E-CHK-001" for issue in report.issues)
    with pytest.raises(OwbmError) as exc:
        report.raise_first()
    assert exc.value.code == "OWBM-E-CHK-001"


def test_missing_manifest(tmp_path):
    path = tmp_path / "x.owbm"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("inventory/x.json", b"{}")
    report = archive.verify_archive(path)
    assert not report.ok
    with pytest.raises(OwbmError) as exc:
        report.raise_first()
    assert exc.value.code in ("OWBM-E-ARC-001", "OWBM-E-CHK-002")


def test_not_a_zip(tmp_path):
    path = tmp_path / "broken.owbm"
    path.write_bytes(b"definitely not a zip")
    report = archive.verify_archive(path)
    assert not report.ok
    with pytest.raises(OwbmError) as exc:
        report.raise_first()
    assert exc.value.code == "OWBM-E-ARC-001"


def test_truncated_zip(tmp_path):
    path = _write(tmp_path, {"manifest.json": json.dumps(_manifest()).encode(), "inventory/x.json": b"{}" * 1000})
    data = path.read_bytes()
    path.write_bytes(data[: len(data) // 2])
    report = archive.verify_archive(path)
    assert not report.ok


def test_unsafe_names_rejected_on_write(tmp_path):
    for name in ("../evil", "/etc/passwd", "a/../../b", "bad\x00name"):
        with pytest.raises(OwbmError) as exc:
            archive.write_archive(tmp_path / "x.owbm", [archive.Member(name, data=b"x")])
        assert exc.value.code == "OWBM-E-CHK-003"


def test_unsafe_names_rejected_on_read(tmp_path):
    path = tmp_path / "x.owbm"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("manifest.json", json.dumps(_manifest()))
        zf.writestr("../escape.txt", b"x")
    report = archive.verify_archive(path)
    assert not report.ok
    assert any(issue.code == "OWBM-E-CHK-003" for issue in report.issues)


def test_symlink_member_rejected(tmp_path):
    path = tmp_path / "x.owbm"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("manifest.json", json.dumps(_manifest()))
        info = zipfile.ZipInfo("payload/link")
        info.external_attr = (0o120777) << 16  # symlink
        zf.writestr(info, "/etc/passwd")
    report = archive.verify_archive(path)
    assert not report.ok
    assert any(issue.code == "OWBM-E-CHK-004" for issue in report.issues)


def test_future_format_version(tmp_path):
    data = _manifest()
    data["format_version"] = 99
    path = _write(tmp_path, {"manifest.json": json.dumps(data).encode()})
    report = archive.verify_archive(path)
    assert not report.ok
    with pytest.raises(OwbmError) as exc:
        report.raise_first()
    assert exc.value.code == "OWBM-E-FMT-001"


def test_extract_member_is_sandboxed(tmp_path):
    payload = tmp_path / "p.bin"
    payload.write_bytes(b"data")
    path = tmp_path / "x.owbm"
    archive.write_archive(
        path,
        [archive.Member("manifest.json", data=b"{}"), archive.Member("payload/p.bin", source=payload)],
    )
    dest = tmp_path / "out"
    target = archive.extract_member(path, "payload/p.bin", dest)
    assert target.read_bytes() == b"data"
    assert target.parent == dest / "payload"


def test_open_zip_rejects_too_many_members_before_materializing_directory(tmp_path, monkeypatch):
    path = _write(
        tmp_path,
        {
            "manifest.json": json.dumps(_manifest()).encode(),
            "inventory/a.json": b"{}",
            "inventory/b.json": b"{}",
        },
    )
    monkeypatch.setattr(archive, "MAX_ARCHIVE_MEMBERS", 2)
    monkeypatch.setattr(
        archive.zipfile,
        "ZipFile",
        lambda *_args, **_kwargs: pytest.fail("ZipFile should not materialize the directory"),
    )

    with pytest.raises(OwbmError) as exc:
        archive.open_zip(path)

    assert exc.value.code == "OWBM-E-CHK-002"


def test_open_zip_accepts_valid_zip64_directory(tmp_path):
    path = _write(tmp_path, {"manifest.json": b"{}", "inventory/x.json": b"{}"})
    data = bytearray(path.read_bytes())
    eocd = data.rfind(b"PK\x05\x06")
    disk_entries, entries = struct.unpack_from("<HH", data, eocd + 8)
    central_size = int.from_bytes(data[eocd + 12:eocd + 16], "little")
    central_offset = int.from_bytes(data[eocd + 16:eocd + 20], "little")
    zip64_offset = eocd
    zip64_end = struct.pack(
        "<4sQ2H2I4Q",
        b"PK\x06\x06", 44, 45, 45, 0, 0, disk_entries, entries, central_size, central_offset,
    )
    locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, zip64_offset, 1)
    data[eocd:eocd] = zip64_end + locator
    path.write_bytes(data)

    with archive.open_zip(path) as zf:
        assert set(zf.namelist()) == {"manifest.json", "inventory/x.json", archive.CHECKSUMS_NAME}


def test_open_zip_counts_actual_records_not_untrusted_eocd_count(tmp_path, monkeypatch):
    path = _write(tmp_path, {"manifest.json": b"{}", "inventory/x.json": b"{}"})
    data = bytearray(path.read_bytes())
    eocd = data.rfind(b"PK\x05\x06")
    assert eocd >= 0
    # Lie that only one member exists while leaving two central-directory records.
    data[eocd + 8:eocd + 10] = (1).to_bytes(2, "little")
    data[eocd + 10:eocd + 12] = (1).to_bytes(2, "little")
    path.write_bytes(data)
    monkeypatch.setattr(archive, "MAX_ARCHIVE_MEMBERS", 1)

    with pytest.raises(OwbmError) as exc:
        archive.open_zip(path)

    assert exc.value.code == "OWBM-E-CHK-002"


def test_read_manifest_rejects_oversized_member(tmp_path, monkeypatch):
    path = _write(tmp_path, {"manifest.json": json.dumps(_manifest()).encode()})
    monkeypatch.setattr(archive, "MAX_MANIFEST_BYTES", 8)

    with pytest.raises(OwbmError) as exc:
        archive.read_manifest(path)

    assert exc.value.code == "OWBM-E-CHK-002"


def test_verify_archive_rejects_oversized_manifest(tmp_path, monkeypatch):
    path = _write(tmp_path, {"manifest.json": json.dumps(_manifest()).encode()})
    monkeypatch.setattr(archive, "MAX_MANIFEST_BYTES", 8)

    report = archive.verify_archive(path)

    assert not report.ok
    assert any(issue.code == "OWBM-E-CHK-002" for issue in report.issues)


def test_verify_archive_rejects_oversized_checksum_index(tmp_path, monkeypatch):
    path = _write(tmp_path, {"manifest.json": json.dumps(_manifest()).encode(), "inventory/x.json": b"{}"})
    monkeypatch.setattr(archive, "MAX_CHECKSUMS_BYTES", 1)

    report = archive.verify_archive(path)

    assert not report.ok
    assert any(issue.code == "OWBM-E-CHK-002" for issue in report.issues)


def test_read_member_rejects_oversized_metadata(tmp_path, monkeypatch):
    path = _write(tmp_path, {"manifest.json": json.dumps(_manifest()).encode(), "inventory/x.json": b"12345"})
    monkeypatch.setattr(archive, "MAX_METADATA_MEMBER_BYTES", 4)

    with pytest.raises(OwbmError) as exc:
        archive.read_member(path, "inventory/x.json")

    assert exc.value.code == "OWBM-E-CHK-002"


def test_member_name_rules():
    assert archive.check_member_name("manifest.json") is None
    assert archive.check_member_name("payload/configuration.tar.gz") is None
    assert archive.check_member_name("checksums/SHA256SUMS") is None
    assert archive.check_member_name("/abs") is not None
    assert archive.check_member_name("a//b") is not None
    assert archive.check_member_name("a/./b") is not None
    assert archive.check_member_name("a\\b") is not None
    assert archive.check_member_name("") is not None
