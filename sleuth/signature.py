"""Code-signature check for Windows PE files (Authenticode).

What this does: looks for the PE certificate table (the Authenticode
signature blob) and reports signed vs unsigned. It also applies one
focused heuristic: an *unsigned* binary that *claims* a trusted system
identity (a Windows system filename like svchost.exe, or version-info
CompanyName "Microsoft Corporation") is highly suspicious — real system
binaries are always signed.

What this does NOT do: it does not validate the certificate chain or
check revocation. "Signed" here means "a certificate table is present",
not "the signature is cryptographically valid". That is stated honestly
in every report.

For non-PE files (ELF, Mach-O, ...): signature check is N/A — we never
fake a result for a format we cannot parse.
"""

import os
import re

try:
    import pefile

    _HAVE_PEFILE = True
except ImportError:  # pragma: no cover - exercised via graceful path
    _HAVE_PEFILE = False

# Data-directory index of the certificate table (IMAGE_DIRECTORY_ENTRY_SECURITY).
_CERT_DIR_INDEX = 4

# Windows system binary names. An unsigned file wearing one of these names
# is pretending to be part of the OS.
_SYSTEM_NAMES = {
    "svchost.exe", "csrss.exe", "lsass.exe", "smss.exe", "winlogon.exe",
    "services.exe", "lsaiso.exe", "wininit.exe", "explorer.exe",
    "rundll32.exe", "taskhostw.exe", "dwm.exe", "conhost.exe",
    "spoolsv.exe", "msiexec.exe", "regsvr32.exe", "dllhost.exe",
}

# Version-info CompanyName values that imply a trusted vendor identity.
_TRUSTED_COMPANIES = (
    "microsoft corporation",
    "microsoft",
)

# Points for the impersonation heuristic (strong, evidence-cited).
_IMPERSONATION_POINTS = 20

# Look for "CN=..." / "O=..." inside the raw certificate blob. This is a
# heuristic extraction, not an ASN.1 parse — labeled as such.
_SUBJECT_RE = re.compile(rb"(?:CN|O)\s*=\s*([^,/\x00]{2,80})")


def check_signature(path):
    """Check the Authenticode certificate table of the PE file at *path*.

    Returns a dict::

        {
          "available": bool,      # False for non-PE files / parse failures
          "reason": str,          # set when available is False
          "signed": bool,         # a certificate table is present
          "cert_size": int,       # bytes in the certificate table
          "signer_hint": str|None,# best-effort CN=/O= from the cert blob
          "company_name": str|None,  # from version info, if present
          "product_name": str|None,
          "signals": [...],      # heuristic signals (Sleuth signal dicts)
        }

    Never raises. Never executes the target.
    """
    result = {
        "available": False,
        "reason": "not checked",
        "signed": False,
        "cert_size": 0,
        "signer_hint": None,
        "company_name": None,
        "product_name": None,
        "signals": [],
    }

    with open(path, "rb") as f:
        head = f.read(2)
    if head != b"MZ":
        result["reason"] = "signature check N/A (PE-only)"
        return result

    if not _HAVE_PEFILE:
        result["reason"] = "pefile is not installed (pip install pefile)"
        return result

    try:
        with open(path, "rb") as f:
            data = f.read()
        pe = pefile.PE(data=data)
    except Exception as exc:
        result["reason"] = "not a parseable PE: %s" % exc
        return result

    # The certificate table is data directory #4. Unlike other directories,
    # its VirtualAddress is a *file offset*, not an RVA.
    cert_size = 0
    cert_blob = b""
    try:
        cert_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[_CERT_DIR_INDEX]
        if cert_dir.Size > 0 and cert_dir.VirtualAddress > 0:
            cert_size = int(cert_dir.Size)
            start = int(cert_dir.VirtualAddress)
            cert_blob = data[start:start + cert_size]
    except Exception:
        cert_size = 0

    signed = cert_size > 0 and len(cert_blob) > 0
    result["available"] = True
    result["signed"] = signed
    result["cert_size"] = cert_size
    result["reason"] = "ok"

    if signed:
        result["signer_hint"] = _extract_signer_hint(cert_blob)

    version_info = _version_info(pe)
    result["company_name"] = version_info.get("CompanyName")
    result["product_name"] = version_info.get("ProductName")

    result["signals"] = impersonation_signals(
        filename=os.path.basename(path),
        company_name=result["company_name"],
        signed=signed,
    )
    return result


def _extract_signer_hint(cert_blob):
    """Best-effort signer name from the raw certificate blob.

    Searches for CN=/O= attribute strings inside the PKCS#7 data. This is
    NOT an ASN.1 parse — it can miss or misread names, so callers must
    treat the result as a hint, never as verified identity.
    """
    if not cert_blob:
        return None
    # Only look at printable runs to avoid garbage matches.
    text = cert_blob.decode("ascii", errors="ignore")
    for match in _SUBJECT_RE.finditer(cert_blob):
        raw = match.group(1)
        cleaned = re.sub(rb"[^\x20-\x7e]", b"", raw).decode(
            "ascii", errors="ignore").strip()
        if 2 <= len(cleaned) <= 80:
            return cleaned
    _ = text  # silence linters; text kept for future refinement
    return None


def _version_info(pe):
    """Extract a few StringFileInfo fields from the PE version resource.

    Returns {} when no version resource is present. Defensive: any parse
    problem yields {} rather than an exception.
    """
    info = {}
    try:
        file_info = getattr(pe, "FileInfo", None)
        if not file_info:
            return info
        for entry in file_info:
            for st in getattr(entry, "StringTable", []) or []:
                entries = getattr(st, "entries", {}) or {}
                for key in ("CompanyName", "ProductName", "FileDescription",
                            "OriginalFilename"):
                    value = entries.get(key)
                    if value and key not in info:
                        if isinstance(value, bytes):
                            value = value.decode("utf-8", errors="replace")
                        info[key] = str(value).strip()
    except Exception:
        pass
    return info


def impersonation_signals(filename, company_name, signed):
    """Heuristic: unsigned binary claiming a trusted system identity.

    *filename*: basename of the file (e.g. "svchost.exe").
    *company_name*: version-info CompanyName or None.
    *signed*: whether a certificate table is present.

    Returns a list of Sleuth signal dicts (possibly empty). A signed
    binary never triggers this — we only flag the *unsigned* case, because
    any signature at all means the author was not hiding behind a fake name.
    """
    signals = []
    if signed:
        return signals

    lowered = (filename or "").lower()
    if lowered in _SYSTEM_NAMES:
        signals.append({
            "points": _IMPERSONATION_POINTS,
            "evidence": "unsigned file named '%s'" % filename,
            "detail": "Claims a Windows system-binary identity but has no "
                      "Authenticode signature — real system binaries are "
                      "always signed",
        })
        return signals

    company = (company_name or "").strip().lower()
    if company in _TRUSTED_COMPANIES:
        signals.append({
            "points": _IMPERSONATION_POINTS,
            "evidence": "unsigned file claims CompanyName '%s'" % company_name,
            "detail": "Claims a trusted vendor identity in version info but "
                      "has no Authenticode signature",
        })
    return signals
