"""Entry-point disassembly view for Sleuth (capstone).

Disassembles the first ~200 instructions at the binary's entry point for
x86/x64 ELF and PE targets. This is a *view*, not a full disassembly:
an excerpt to eyeball, plus weak heuristic flags (raw syscalls, GetPC
tricks, heavy XOR) that are honestly labeled as weak indicators.

The target is only read from disk — never executed, loaded, or emulated.

Graceful degradation: if ``capstone`` is missing, the arch is unsupported,
or the entry point can't be resolved, returns
``{"available": False, "reason": ...}``. Never raises.
"""

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

    CAPSTONE_AVAILABLE = True
except Exception:
    CAPSTONE_AVAILABLE = False

# Machine types we can disassemble: (arch, mode).
_PE_MACHINES = {
    0x14C: ("x86", 32),    # i386
    0x8664: ("x86", 64),   # x86-64
}
_ELF_MACHINES = {
    3: ("x86", 32),        # EM_386
    62: ("x86", 64),       # EM_X86_64
}

_EXCERPT_BYTES = 4096  # bytes read from the entry point region
WEAK_POINTS = 3


def _entry_region_pe(data):
    """Return (arch_tuple, vaddr, code_bytes) for a PE, or None."""
    try:
        import pefile

        pe = pefile.PE(data=data)
        machine = pe.FILE_HEADER.Machine
        arch = _PE_MACHINES.get(machine)
        if arch is None:
            return None
        entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        offset = pe.get_offset_from_rva(entry_rva)
        vaddr = pe.OPTIONAL_HEADER.ImageBase + entry_rva
        return arch, vaddr, data[offset:offset + _EXCERPT_BYTES]
    except Exception:
        return None


def _entry_region_elf(data):
    """Return (arch_tuple, vaddr, code_bytes) for an ELF, or None."""
    try:
        from elftools.elf.elffile import ELFFile
        from io import BytesIO

        elf = ELFFile(BytesIO(data))
        arch = _ELF_MACHINES.get(elf.header.e_machine)
        if arch is None:
            return None
        entry = elf.header.e_entry
        for section in elf.iter_sections():
            start = section.header.sh_addr
            size = section.header.sh_size
            if size and start <= entry < start + size:
                off = section.header.sh_offset + (entry - start)
                return arch, entry, data[off:off + _EXCERPT_BYTES]
        return None
    except Exception:
        return None


def _weak_signals(instructions):
    """Flag suspicious instruction patterns as WEAK signals (3 pts each)."""
    signals = []
    mnems = [i["mnemonic"] for i in instructions]

    # Raw syscalls: classic evasion / direct kernel interaction.
    for i in instructions:
        if i["mnemonic"] in ("syscall", "sysenter"):
            signals.append({
                "points": WEAK_POINTS,
                "evidence": "raw '%s' instruction at %s" % (
                    i["mnemonic"], i["address"]),
                "detail": "Direct syscall (weak indicator — also used by "
                          "legitimate runtimes)",
            })
            break
        if i["mnemonic"] == "int" and i["op_str"].strip() in ("0x80", "0x2e"):
            signals.append({
                "points": WEAK_POINTS,
                "evidence": "raw 'int %s' at %s" % (i["op_str"], i["address"]),
                "detail": "Legacy syscall interrupt (weak indicator)",
            })
            break

    # GetPC tricks (call/pop, fnstenv): position-independent shellcode habit.
    for i in instructions:
        if i["mnemonic"] == "fnstenv":
            signals.append({
                "points": WEAK_POINTS,
                "evidence": "'fnstenv' at %s" % i["address"],
                "detail": "GetPC trick via fnstenv (weak anti-analysis indicator)",
            })
            break
        if i["mnemonic"] == "call" and "$+" in i["op_str"]:
            signals.append({
                "points": WEAK_POINTS,
                "evidence": "'call %s' at %s" % (i["op_str"], i["address"]),
                "detail": "GetPC trick via call/pop (weak anti-analysis indicator)",
            })
            break

    # Sandbox/VM fingerprinting instructions.
    for i in instructions:
        if i["mnemonic"] in ("cpuid", "rdtsc"):
            signals.append({
                "points": WEAK_POINTS,
                "evidence": "'%s' at %s" % (i["mnemonic"], i["address"]),
                "detail": "CPU/timing fingerprinting (weak indicator — "
                          "also used legitimately)",
            })
            break

    # Heavy XOR: possible decode/decrypt loop.
    xor_count = sum(1 for m in mnems if m == "xor")
    if instructions and xor_count >= max(5, len(instructions) // 10):
        signals.append({
            "points": WEAK_POINTS,
            "evidence": "%d XOR instructions in %d-instruction excerpt"
            % (xor_count, len(instructions)),
            "detail": "Heavy XOR usage suggests a decode loop (weak indicator)",
        })
    return signals


def disassemble_bytes(code, arch, mode, base_addr=0, count=200):
    """Disassemble raw *code* bytes. Returns a list of instruction dicts.

    Each dict: {"address": "0x...", "mnemonic": str, "op_str": str}.
    Raises RuntimeError if capstone is unavailable.
    """
    if not CAPSTONE_AVAILABLE:
        raise RuntimeError("capstone not installed — run: pip install capstone")
    md = Cs(CS_ARCH_X86, CS_MODE_64 if mode == 64 else CS_MODE_32)
    md.detail = False
    out = []
    for insn in md.disasm(code, base_addr):
        out.append(
            {
                "address": "0x%x" % insn.address,
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
            }
        )
        if len(out) >= count:
            break
    return out


def disassemble_file(path, file_type, count=200):
    """Disassemble the entry-point region of *path*.

    *file_type*: "pe" or "elf" (other types -> unavailable). Returns::

        {"available": bool, "reason": str (when unavailable),
         "arch": "x86-32"/"x86-64", "count": int,
         "instructions": [{"address","mnemonic","op_str"}],
         "weak_signals": [sleuth signal dicts]}

    Never raises.
    """
    if not CAPSTONE_AVAILABLE:
        return {
            "available": False,
            "reason": "capstone not installed — run: pip install capstone",
        }
    if file_type not in ("pe", "elf"):
        return {
            "available": False,
            "reason": "disassembly supports x86/x64 PE and ELF only",
        }
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as exc:
        return {"available": False, "reason": "cannot read file: %s" % exc}
    try:
        region = _entry_region_pe(data) if file_type == "pe" else _entry_region_elf(data)
        if region is None:
            return {
                "available": False,
                "reason": "unsupported architecture or entry point not found",
            }
        (arch_name, bits), vaddr, code = region
        if not code:
            return {"available": False, "reason": "no code bytes at entry point"}
        instructions = disassemble_bytes(
            code, arch_name, bits, base_addr=vaddr, count=count
        )
        return {
            "available": True,
            "arch": "%s-%d" % (arch_name, bits),
            "count": len(instructions),
            "instructions": instructions,
            "weak_signals": _weak_signals(instructions),
        }
    except Exception as exc:
        return {"available": False, "reason": "disassembly failed: %s" % exc}
