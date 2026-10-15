"""PE (Windows executable) anatomy using pefile (pure Python, no execution).

Extracts: section list with per-section entropy, imported DLLs + functions,
and hardening mitigations (DEP/NX, ASLR). If pefile is not installed,
returns a clear "unavailable" result instead of crashing.
"""

from .strings import shannon_entropy

try:
    import pefile

    _HAVE_PEFILE = True
except ImportError:  # pragma: no cover - exercised via graceful path
    _HAVE_PEFILE = False

# IMAGE_DLLCHARACTERISTICS flags (from the PE spec).
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040


def analyze_pe(data):
    """Analyze PE *data* (bytes). Returns a dict with sections, imports,
    mitigations, or {"available": False, "reason": ...} if pefile is missing
    or parsing fails."""
    if not _HAVE_PEFILE:
        return {
            "available": False,
            "reason": "pefile is not installed (pip install pefile)",
        }
    try:
        pe = pefile.PE(data=data)
    except Exception as exc:
        return {"available": False, "reason": "not a parseable PE: %s" % exc}

    sections = []
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        sdata = section.get_data()
        sections.append(
            {
                "name": name,
                "size": section.SizeOfRawData,
                "entropy": round(shannon_entropy(sdata), 2),
            }
        )

    imports = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("ascii", errors="replace")
            funcs = sorted(
                imp.name.decode("ascii", errors="replace")
                for imp in entry.imports
                if imp.name
            )
            imports[dll] = funcs

    dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
    mitigations = {
        # DEP/NX: binary opts into Data Execution Prevention.
        "dep": bool(dll_chars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT),
        # ASLR: binary can be relocated at load time.
        "aslr": bool(dll_chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE),
    }

    return {
        "available": True,
        "sections": sections,
        "imports": imports,
        "mitigations": mitigations,
    }
