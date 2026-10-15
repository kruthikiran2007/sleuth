"""Tests for sleuth.apk: APK manifest + dex analysis.

Fixtures are hand-built with zipfile (plain-text manifests) or struct.pack
(binary AXML blobs), so no real APK or third-party tooling is needed.
"""

import struct
import zipfile

from sleuth import apk


MANIFEST_EVIL = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.evil.test"
    android:versionCode="7"
    android:versionName="1.2">
  <uses-permission android:name="android.permission.SEND_SMS"/>
  <uses-permission android:name="android.permission.RECEIVE_SMS"/>
  <uses-permission android:name="android.permission.INTERNET"/>
  <application android:debuggable="true">
    <activity android:name=".MainActivity" android:exported="true"/>
  </application>
</manifest>
"""

MANIFEST_CLEAN = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.clean.test"
    android:versionCode="1"
    android:versionName="1.0">
  <uses-permission android:name="android.permission.INTERNET"/>
  <application>
    <activity android:name=".MainActivity" android:exported="false"/>
  </application>
</manifest>
"""


def _write_apk(path, manifest_text, dex_entries=()):
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_text)
        for name, data in dex_entries:
            zf.writestr(name, data)


def test_evil_apk_plain_manifest(tmp_path):
    dex = b"\x00" * 64 + b"AKIAIOSFODNN7EXAMPLE" + b"\x00" * 64
    path = str(tmp_path / "evil.apk")
    _write_apk(path, MANIFEST_EVIL, [("classes.dex", dex)])

    result = apk.analyze_apk(path)
    assert result["available"] is True
    assert result["package"] == "com.evil.test"
    assert result["version_name"] == "1.2"
    assert result["version_code"] == "7"

    # Dangerous permissions flagged.
    assert "android.permission.SEND_SMS" in result["dangerous_permissions"]
    assert "android.permission.RECEIVE_SMS" in result["dangerous_permissions"]

    # Risky combo RECEIVE_SMS + SEND_SMS present.
    combos = result["risky_combos"]
    assert any(
        set(c["combo"])
        == {
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS",
        }
        and "premium-SMS" in c["label"]
        for c in combos
    )

    # Debuggable + exported component.
    assert result["debuggable"] is True
    assert ".MainActivity" in result["exported"]["activities"]

    # Signals carry points.
    assert result["signals"], "expected non-empty signals"
    assert all(s["points"] > 0 for s in result["signals"])


def test_true_negative(tmp_path):
    path = str(tmp_path / "clean.apk")
    _write_apk(path, MANIFEST_CLEAN)

    result = apk.analyze_apk(path)
    assert result["available"] is True
    assert result["package"] == "com.clean.test"
    assert result["dangerous_permissions"] == []
    assert result["risky_combos"] == []
    assert result["debuggable"] is False
    assert result["exported"]["activities"] == []
    assert result["signals"] == []


def test_corrupt_apk_never_raises(tmp_path):
    path = str(tmp_path / "corrupt.apk")
    with open(path, "wb") as f:
        f.write(b"not a zip")

    result = apk.analyze_apk(path)
    assert result["available"] is False
    assert result["reason"], "expected a reason string"
    # All other keys present but empty/False.
    assert result["package"] == ""
    assert result["permissions"] == []
    assert result["exported"] == {
        "activities": [],
        "services": [],
        "receivers": [],
    }
    assert result["debuggable"] is False
    assert result["dangerous_permissions"] == []
    assert result["risky_combos"] == []
    assert result["dex_strings"] == 0
    assert result["dex_secrets"] == []
    assert result["signals"] == []


def test_corrupt_apk_missing_manifest_never_raises(tmp_path):
    path = str(tmp_path / "nomanifest.apk")
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("classes.dex", b"\x00" * 16)

    result = apk.analyze_apk(path)
    assert result["available"] is False
    assert "AndroidManifest" in result["reason"]


# ---------------------------------------------------------------------------
# Binary AXML blob builder (UTF-16 string pool)
# ---------------------------------------------------------------------------


def _utf16_pool_blob(strings):
    """Build a type-0x0001 string pool chunk (UTF-16) via struct.pack."""
    offsets = []
    data = b""
    for s in strings:
        offsets.append(len(data))
        encoded = s.encode("utf-16-le")
        data += struct.pack("<H", len(s)) + encoded + struct.pack("<H", 0)
    header = struct.pack(
        "<HHI", 0x0001, 28, 28 + 4 * len(strings) + len(data)
    )
    body = struct.pack(
        "<IIIII",
        len(strings),  # stringCount
        0,  # styleCount
        0,  # flags: UTF-16 (0x100 bit clear)
        28 + 4 * len(strings),  # stringsStart
        0,  # stylesStart
    )
    offs = struct.pack("<%dI" % len(offsets), *offsets)
    return header + body + offs + data


def _start_element(name_idx, attrs, line=1):
    """Build a type-0x0102 START_ELEMENT chunk. attrs: [(name_idx, raw_idx)]."""
    node = struct.pack(
        "<HHIII", 0x0102, 16, 16 + 20 + 20 * len(attrs), line, 0xFFFFFFFF
    )
    body = struct.pack(
        "<IIHHHHHH",
        0xFFFFFFFF,  # nsIdx
        name_idx,
        20,  # attributeStart
        20,  # attributeSize
        len(attrs),  # attributeCount
        0xFFFF,  # idIndex
        0xFFFF,  # classIndex
        0xFFFF,  # styleIndex
    )
    blob = node + body
    for aname_idx, raw_idx in attrs:
        blob += struct.pack(
            "<IIIHBBI",
            0xFFFFFFFF,  # nsIdx
            aname_idx,
            raw_idx,
            8,  # size
            0,  # res0
            0x03,  # dataType = string
            raw_idx,  # data = pool index
        )
    return blob


def _end_element(name_idx, line=1):
    node = struct.pack("<HHIII", 0x0103, 16, 24, line, 0xFFFFFFFF)
    body = struct.pack("<II", 0xFFFFFFFF, name_idx)
    return node + body


def _build_axml():
    strings = [
        "manifest",  # 0
        "package",  # 1
        "com.axml.test",  # 2
        "uses-permission",  # 3
        "android:name",  # 4
        "android.permission.SEND_SMS",  # 5
    ]
    chunks = b""
    chunks += _utf16_pool_blob(strings)
    chunks += _start_element(0, [(1, 2)])  # <manifest package="com.axml.test">
    chunks += _start_element(3, [(4, 5)])  # <uses-permission android:name=...>
    chunks += _end_element(3)
    chunks += _end_element(0)
    header = struct.pack("<HHI", 0x0003, 8, 8 + len(chunks))
    return header + chunks, strings


def test_axml_parser_unit():
    blob, strings = _build_axml()
    elements = apk._parse_axml(blob)
    assert [name for name, _ in elements] == ["manifest", "uses-permission"]
    manifest_attrs = elements[0][1]
    perm_attrs = elements[1][1]
    assert manifest_attrs["package"] == "com.axml.test"
    # "android:name" -> local part "name".
    assert perm_attrs["name"] == "android.permission.SEND_SMS"


def test_axml_end_to_end(tmp_path):
    blob, _ = _build_axml()
    path = str(tmp_path / "axml.apk")
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", blob)

    result = apk.analyze_apk(path)
    assert result["available"] is True
    assert result["package"] == "com.axml.test"
    assert result["permissions"] == ["android.permission.SEND_SMS"]
    assert result["dangerous_permissions"] == ["android.permission.SEND_SMS"]
    assert result["risky_combos"] == []
    assert result["debuggable"] is False
    assert any(s["points"] == 5 for s in result["signals"])


def test_dex_secret_redacted(tmp_path):
    secret = b"AKIAIOSFODNN7EXAMPLE"
    dex = b"\x00" * 32 + secret + b"\x00" * 32
    path = str(tmp_path / "evil.apk")
    _write_apk(path, MANIFEST_EVIL, [("classes.dex", dex)])

    result = apk.analyze_apk(path)
    assert result["dex_strings"] > 0
    hits = result["dex_secrets"]
    assert hits, "expected dex secret hits"
    aws = [h for h in hits if h["type"] == "aws_access_key"]
    assert aws, "expected an aws_access_key hit"
    preview = aws[0]["preview"]
    # Redacted like secrets.redact: first 4 chars + "...".
    assert preview.endswith("..."), "preview must be redacted: %r" % preview
    assert secret.decode() not in preview, "full secret must never appear"
    # Dex-secret signals merge into the verdict format.
    dex_signals = [s for s in result["signals"] if s["points"] == 10]
    assert any("aws_access_key" in s["evidence"] for s in dex_signals)
