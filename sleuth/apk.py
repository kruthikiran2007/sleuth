"""Android APK manifest + dex analysis (static, never executes the target).

DESIGN DECISION: minimal built-in AXML (binary AndroidManifest.xml) parser,
NO androguard dependency. androguard is a heavy dependency that is painful
to install on Windows (native wheels, version pinning); a small
dependency-free parser keeps installs painless and matches Sleuth's
small-footprint philosophy. APKs whose manifest is stored as plain text
XML are also supported via an ElementTree fallback.

Everything here is read-only: the APK is opened as a ZIP and its entries
are read as bytes. Corrupt input never raises -- analyze_apk returns
{"available": False, "reason": ...} with all other keys present but
empty/False.
"""

import re
import struct
import zipfile
import xml.etree.ElementTree as ET

from . import secrets as secrets_mod
from . import strings as strings_mod

# Cap on total dex bytes read (memory safety).
_DEX_BUDGET = 50 * 1024 * 1024  # 50 MB

_DEX_NAME_RE = re.compile(r"^classes\d*\.dex$")

# Android "dangerous" protection-level permissions we flag (full names).
DANGEROUS_PERMISSIONS = frozenset(
    "android.permission." + name
    for name in (
        "SEND_SMS",
        "RECEIVE_SMS",
        "READ_SMS",
        "READ_CONTACTS",
        "WRITE_CONTACTS",
        "READ_CALL_LOG",
        "RECORD_AUDIO",
        "CAMERA",
        "ACCESS_FINE_LOCATION",
        "ACCESS_COARSE_LOCATION",
        "READ_PHONE_STATE",
        "CALL_PHONE",
        "READ_EXTERNAL_STORAGE",
    )
)

_INTERNET = "android.permission.INTERNET"

# (permission set, human label). All are much more suspicious together.
RISKY_COMBOS = [
    (
        frozenset(
            (
                "android.permission.RECEIVE_SMS",
                "android.permission.SEND_SMS",
            )
        ),
        "can read and send SMS -- premium-SMS fraud pattern",
    ),
    (
        frozenset(
            (
                "android.permission.RECORD_AUDIO",
                "android.permission.INTERNET",
            )
        ),
        "can record audio and exfiltrate",
    ),
    (
        frozenset(
            (
                "android.permission.READ_CONTACTS",
                "android.permission.INTERNET",
            )
        ),
        "can harvest contacts",
    ),
    (
        frozenset(
            (
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.INTERNET",
            )
        ),
        "can track location",
    ),
]

_NO_VALUE = 0xFFFFFFFF

# ---------------------------------------------------------------------------
# AXML (binary AndroidManifest.xml) parsing
# ---------------------------------------------------------------------------


def _read_uvarint(buf, pos):
    """Read the AXML 1-or-2-byte length encoding. Returns (value, new_pos)."""
    b0 = buf[pos]
    if b0 & 0x80:
        return ((b0 & 0x7F) << 8) | buf[pos + 1], pos + 2
    return b0, pos + 1


def _pool_get(strings, idx):
    """Safe string-pool lookup: out-of-range -> empty string."""
    if 0 <= idx < len(strings):
        return strings[idx]
    return ""


def _parse_string_pool(data, off):
    """Parse a type-0x0001 string pool chunk at *off*. Returns [str, ...]."""
    (string_count, style_count, flags, strings_start, _styles_start) = (
        struct.unpack_from("<IIIII", data, off + 8)
    )
    utf8 = bool(flags & 0x100)
    offsets = struct.unpack_from("<%dI" % string_count, data, off + 28)
    strings = []
    for rel in offsets:
        pos = off + strings_start + rel
        try:
            if utf8:
                _, pos = _read_uvarint(data, pos)  # char count (unused)
                nbytes, pos = _read_uvarint(data, pos)
                raw = data[pos : pos + nbytes]
                strings.append(raw.decode("utf-8", errors="replace"))
            else:
                (count,) = struct.unpack_from("<H", data, pos)
                pos += 2
                # ">32767 continuation encoding" deliberately not implemented:
                # real manifests never use it, and mis-decoding is safe here
                # (worst case a garbled string, never a crash).
                raw = data[pos : pos + count * 2]
                strings.append(raw.decode("utf-16-le", errors="replace"))
        except (struct.error, IndexError):
            strings.append("")
    return strings


def _local(name):
    """Attribute/element local name: the part after any namespace prefix."""
    return name.split(":")[-1]


def _resolve_attr(strings, raw_idx, data_type, data):
    """Resolve an attribute value: raw string pool ref wins, else typed value."""
    if raw_idx != _NO_VALUE:
        return _pool_get(strings, raw_idx)
    if data_type == 0x03:  # TYPE_STRING -> pool index
        return _pool_get(strings, data)
    if data_type == 0x12:  # TYPE_INT_BOOLEAN
        return data != 0
    if data_type == 0x10:  # TYPE_INT_DEC
        return str(data)
    return data


def _parse_start_element(data, off, strings):
    """Parse a type-0x0102 START_ELEMENT chunk. Returns (name, {attr: value})."""
    ns_idx, name_idx = struct.unpack_from("<II", data, off + 16)
    (
        attr_start,
        attr_size,
        attr_count,
        _id_index,
        _class_index,
        _style_index,
    ) = struct.unpack_from("<HHHHHH", data, off + 24)
    name = _local(_pool_get(strings, name_idx))
    attrs = {}
    for i in range(attr_count):
        # attributes sit after the 16-byte node header, at attr_start bytes
        # into the element body
        aoff = off + 16 + attr_start + i * attr_size
        _ans_idx, aname_idx, raw_idx = struct.unpack_from("<III", data, aoff)
        _size, _res0, data_type, tdata = struct.unpack_from(
            "<HBBI", data, aoff + 12
        )
        key = _local(_pool_get(strings, aname_idx))
        attrs[key] = _resolve_attr(strings, raw_idx, data_type, tdata)
    return name, attrs


def _parse_axml(data):
    """Parse binary Android XML. Returns [(element_name, {attr: value}), ...].

    Raises ValueError on anything that is not a well-formed AXML document;
    the caller converts that into available=False.
    """
    if len(data) < 8:
        raise ValueError("too short for AXML header")
    chunk_type, _header_size, _file_size = struct.unpack_from("<HHI", data, 0)
    if chunk_type != 0x0003:
        raise ValueError("not a binary XML file (type 0x%04x)" % chunk_type)

    strings = []
    elements = []
    off = 8
    while off + 8 <= len(data):
        ctype, _chsize, cchunk = struct.unpack_from("<HHI", data, off)
        if cchunk < 8 or off + cchunk > len(data):
            break  # truncated chunk: stop, keep what we parsed
        if ctype == 0x0001:  # string pool
            strings = _parse_string_pool(data, off)
        elif ctype == 0x0180:  # resource map: skip via chunkSize
            pass
        elif ctype == 0x0102:  # START_ELEMENT
            elements.append(_parse_start_element(data, off, strings))
        # 0x0100/0x0101 namespaces and 0x0103 end elements carry no new data
        off += cchunk
    if not elements:
        raise ValueError("no XML elements found")
    return elements


# ---------------------------------------------------------------------------
# Manifest extraction (shared by the AXML and plain-XML paths)
# ---------------------------------------------------------------------------


def _as_bool(value):
    """Interpret a manifest boolean-ish attribute value."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() == "true"


def _extract_manifest(elements):
    """Build the manifest summary from [(name, {attr: value}), ...]."""
    info = {
        "package": "",
        "version_name": "",
        "version_code": "",
        "permissions": [],
        "exported": {"activities": [], "services": [], "receivers": []},
        "debuggable": False,
    }
    for name, attrs in elements:
        if name == "manifest":
            info["package"] = str(attrs.get("package", ""))
            info["version_name"] = str(attrs.get("versionName", ""))
            info["version_code"] = str(attrs.get("versionCode", ""))
        elif name == "uses-permission":
            perm = attrs.get("name", "")
            if perm and perm not in info["permissions"]:
                info["permissions"].append(str(perm))
        elif name == "application":
            info["debuggable"] = _as_bool(attrs.get("debuggable", False))
        elif name in ("activity", "service", "receiver"):
            if _as_bool(attrs.get("exported", False)):
                comp = str(attrs.get("name", ""))
                if comp:
                    key = {"activity": "activities",
                           "service": "services",
                           "receiver": "receivers"}[name]
                    info["exported"][key].append(comp)
    return info


def _elements_from_plain_xml(data):
    """Parse a plain-text AndroidManifest.xml into [(name, {attr: value})]."""
    root = ET.fromstring(data.decode("utf-8", errors="replace"))

    def local(tag):
        return tag.rsplit("}", 1)[-1]

    elements = []
    for elem in root.iter():
        attrs = {local(k): v for k, v in elem.attrib.items()}
        elements.append((local(elem.tag), attrs))
    return elements


def _find_manifest_entry(zf):
    """Return the ZipInfo for AndroidManifest.xml, or None."""
    for info in zf.infolist():
        if info.filename == "AndroidManifest.xml" or info.filename.endswith(
            "/AndroidManifest.xml"
        ):
            return info
    return None


def _empty_result(reason):
    """available=False result: every key present, never raises."""
    return {
        "available": False,
        "reason": reason,
        "package": "",
        "version_name": "",
        "version_code": "",
        "permissions": [],
        "exported": {"activities": [], "services": [], "receivers": []},
        "debuggable": False,
        "dangerous_permissions": [],
        "risky_combos": [],
        "dex_strings": 0,
        "dex_secrets": [],
        "signals": [],
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_apk(path):
    """Statically analyze an APK. Returns a report dict; never raises.

    Reads AndroidManifest.xml (binary AXML via the built-in parser, or
    plain XML as a fallback), flags dangerous permissions and risky
    permission combos, and scans classes*.dex strings for leaked secrets.
    Corrupt input (not a ZIP, no manifest, bad XML) yields
    {"available": False, "reason": ...} with all other keys empty/False.
    """
    try:
        return _analyze_apk(path)
    except Exception as exc:  # corrupt input must never raise
        result = _empty_result("failed to analyze APK: %s" % exc)
        return result


def _analyze_apk(path):
    try:
        zf = zipfile.ZipFile(path)
    except Exception:
        return _empty_result("not a valid ZIP/APK archive")

    with zf:
        manifest_info = _find_manifest_entry(zf)
        if manifest_info is None:
            return _empty_result("no AndroidManifest.xml found in archive")

        raw = zf.read(manifest_info.filename)
        stripped = raw.lstrip()
        try:
            if stripped.startswith(b"<"):
                elements = _elements_from_plain_xml(raw)
            else:
                elements = _parse_axml(raw)
        except Exception as exc:
            return _empty_result("could not parse AndroidManifest.xml: %s" % exc)

        info = _extract_manifest(elements)

        # Dangerous permissions + risky combos.
        declared = set(info["permissions"])
        dangerous = sorted(p for p in info["permissions"] if p in DANGEROUS_PERMISSIONS)
        combos = []
        for combo_perms, label in RISKY_COMBOS:
            if combo_perms <= declared:
                combos.append(
                    {"combo": sorted(combo_perms), "label": label}
                )

        # Dex scan: strings -> secrets, capped at _DEX_BUDGET total bytes.
        dex_strings = 0
        dex_secrets = []
        remaining = _DEX_BUDGET
        for entry in zf.infolist():
            if not _DEX_NAME_RE.match(entry.filename.rsplit("/", 1)[-1]):
                continue
            if remaining <= 0:
                break
            with zf.open(entry) as f:
                dex_data = f.read(remaining)
            remaining -= len(dex_data)
            strings = strings_mod.extract_strings(dex_data)
            dex_strings += len(strings)
            dex_secrets.extend(secrets_mod.scan_secrets("\n".join(strings)))

    # Signals, ready to merge into the verdict engine's format.
    signals = []
    for perm in dangerous:
        signals.append(
            {
                "points": 5,
                "evidence": "dangerous permission '%s' declared" % perm,
                "detail": "Android dangerous-level permission requested "
                          "by the manifest",
            }
        )
    for combo in combos:
        signals.append(
            {
                "points": 12,
                "evidence": "risky permission combo: %s" % combo["label"],
                "detail": "combo: %s" % " + ".join(combo["combo"]),
            }
        )
    if info["debuggable"]:
        signals.append(
            {
                "points": 10,
                "evidence": "debuggable=true in manifest application",
                "detail": "debuggable builds leak logs and allow a debugger "
                          "to attach",
            }
        )
    for hit in dex_secrets:
        signals.append(
            {
                "points": 10,
                "evidence": "secret '%s' found in dex: %s"
                % (hit["type"], hit["preview"]),
                "detail": "line %d of extracted dex strings" % hit["line"],
            }
        )

    return {
        "available": True,
        "reason": "",
        "package": info["package"],
        "version_name": info["version_name"],
        "version_code": info["version_code"],
        "permissions": info["permissions"],
        "exported": info["exported"],
        "debuggable": info["debuggable"],
        "dangerous_permissions": dangerous,
        "risky_combos": combos,
        "dex_strings": dex_strings,
        "dex_secrets": dex_secrets,
        "signals": signals,
    }
