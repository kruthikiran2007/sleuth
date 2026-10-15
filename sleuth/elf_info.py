"""ELF binary anatomy using pyelftools (pure Python, no execution).

Extracts: section list with per-section entropy, imported symbols, and
hardening mitigations (NX, PIE, stack canary, RELRO). If pyelftools is not
installed, returns a clear "unavailable" result instead of crashing.
"""

from io import BytesIO

from .strings import shannon_entropy

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    _HAVE_ELFTOOLS = True
except ImportError:  # pragma: no cover - exercised via graceful path
    _HAVE_ELFTOOLS = False


def analyze_elf(data):
    """Analyze ELF *data* (bytes). Returns a dict with sections, imports,
    mitigations, or {"available": False, "reason": ...} if pyelftools is
    missing or parsing fails."""
    if not _HAVE_ELFTOOLS:
        return {
            "available": False,
            "reason": "pyelftools is not installed (pip install pyelftools)",
        }
    try:
        elf = ELFFile(BytesIO(data))
    except Exception as exc:
        return {"available": False, "reason": "not a parseable ELF: %s" % exc}

    sections = []
    for section in elf.iter_sections():
        try:
            sdata = section.data()
        except Exception:
            sdata = b""
        sections.append(
            {
                "name": section.name,
                "size": section["sh_size"],
                "entropy": round(shannon_entropy(sdata), 2),
            }
        )

    imports = sorted(
        {
            sym.name
            for section in elf.iter_sections()
            if isinstance(section, SymbolTableSection)
            for sym in section.iter_symbols()
            if sym["st_info"]["type"] == "STT_FUNC"
            and sym["st_shndx"] == "SHN_UNDEF"
            and sym.name
        }
    )

    header = elf.header
    mitigations = {
        # NX: GNU_STACK segment without execute permission.
        "nx": _has_nx(elf),
        # PIE: executable built as position-independent (shared-object type).
        "pie": header["e_type"] == "ET_DYN",
        # Stack canary: __stack_chk_fail referenced => canary checks compiled in.
        "canary": "__stack_chk_fail" in imports,
        # RELRO: GNU_RELRO segment present (partial at least).
        "relro": any(
            seg["p_type"] == "PT_GNU_RELRO" for seg in elf.iter_segments()
        ),
    }

    return {
        "available": True,
        "sections": sections,
        "imports": imports,
        "mitigations": mitigations,
    }


def _has_nx(elf):
    """True if a GNU_STACK segment exists and is not executable."""
    for seg in elf.iter_segments():
        if seg["p_type"] == "PT_GNU_STACK":
            return not bool(seg["p_flags"] & 0x1)  # PF_X
    return False  # no GNU_STACK marker -> cannot confirm NX
