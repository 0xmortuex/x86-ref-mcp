"""x86-ref-mcp: x86 instruction, register and MSR reference for AI agents."""

from __future__ import annotations

import functools
import re
from collections.abc import Callable
from typing import Any, TypeVar

import capstone
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import arch
from . import exceptions as excmod
from . import insns

mcp = MCPServer(
    "x86-ref",
    instructions=(
        "x86 reference for questions models usually get wrong: which flags an instruction "
        "reads and writes, which CPUID feature it needs, whether it is privileged, which "
        "exceptions it can raise, what a CR0/CR4/EFER/RFLAGS value means, and MSR numbers. "
        "Instruction data comes from Intel XED's machine-readable ISA database "
        "(Apache-2.0); register and MSR tables are hand-written. Look facts up here instead "
        "of recalling them. x86_decode turns raw bytes into instructions with the same info."
    ),
)

F = TypeVar("F", bound=Callable[..., Any])

# Failures an agent can act on. MCPServer only forwards a ToolError's message
# to the client - anything else arrives as a bare "Error executing tool X" -
# so these are re-raised as ToolError with their text intact.
_EXPECTED = (KeyError, ValueError)


def tool(fn: F) -> F:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except _EXPECTED as e:
            # KeyError's str() wraps the message in quotes; use the raw text.
            msg = e.args[0] if isinstance(e, KeyError) and e.args else str(e)
            raise ToolError(str(msg)) from e

    mcp.tool()(wrapper)
    return fn


def _uniq(values: list[str]) -> list[str]:
    return list(dict.fromkeys(v for v in values if v))


def _cpuid_lines(forms: list[insns.Form]) -> list[str]:
    groups: list[str] = []
    for f in forms:
        for group in f["cpuid"]:
            groups.append(" AND ".join(group))
    groups = _uniq(groups)
    if not groups:
        return []
    if len(groups) == 1:
        return [groups[0]]
    return [f"any of: {' | '.join(groups)}"]


def _describe(iclass: str, forms: list[insns.Form], max_forms: int) -> list[str]:
    lines = [f"{iclass}: {len(forms)} encoding form(s)"]
    lines.append("category: " + ", ".join(_uniq([f["category"] for f in forms])))
    lines.append("ISA set: " + ", ".join(_uniq([f["isa_set"] for f in forms]))
                 + " (extension " + ", ".join(_uniq([f["extension"] for f in forms])) + ")")
    cpuid = _cpuid_lines(forms)
    lines.append("CPUID: " + (cpuid[0] if cpuid else "XED records no CPUID requirement for this ISA set "
                                                     "(baseline instruction)"))
    cpls = sorted({f["cpl"] for f in forms})
    lines.append("privilege: " + ("CPL 0 only" if cpls == [0] else "any CPL" if cpls == [3]
                                  else "varies by form (CPL 0 for some)"))
    modes = insns.valid_modes(forms)
    restricted = _uniq([f["mode"] for f in forms])
    line = "valid in: " + ", ".join(modes) + " mode"
    if restricted:
        line += f" (some forms: {'; '.join(restricted)})"
    lines.append(line)
    attrs = _uniq([a for f in forms for a in f["attributes"]])
    notable = [a for a in attrs if a in ("LOCKABLE", "RING0", "REP", "REPNE", "REPE", "FAR_XFER",
                                         "PROTECTED_MODE", "NOTSX", "MXCSR", "X87_MMX_STATE_W",
                                         "SERIALIZING", "BYTEOP", "KMASK", "MASKOP", "UNDOCUMENTED")]
    if notable:
        lines.append("attributes: " + " ".join(notable))
    if any(f["undocumented"] for f in forms):
        lines.append("note: XED marks some forms as undocumented")
    lines.append("flags:")
    lines += ["  " + s for s in insns.flag_summary(forms)]
    for note in excmod.NOTES.get(iclass, []):
        lines.append("note: " + note)
    lines.append("forms:")
    for f in forms[:max_forms]:
        lines.append(f"  {f['iform']}: {insns.render_operands(f['operands'])}")
    if len(forms) > max_forms:
        lines.append(f"  ... {len(forms) - max_forms} more (raise max_forms to see them)")
    rel = insns.related(iclass)
    if rel:
        lines.append("related classes: " + ", ".join(rel))
    return lines


@tool
def x86_insn(mnemonic: str, max_forms: int = 8) -> str:
    """Look up an x86 instruction: ISA set, CPUID requirement, privilege level,
    valid modes, flags read/written, and its encoding forms with operands.

    mnemonic accepts XED names (CMOVZ, REP_MOVSB, MOV_CR) and the usual
    spellings (cmove, je, sal, ret, movabs, "rep movsb"); the result says how
    the name was mapped. Data: Intel XED (Apache-2.0).
    """
    if not 1 <= max_forms <= 200:
        raise ValueError("max_forms must be between 1 and 200")
    res = insns.resolve(mnemonic)
    out = [f"({res.note})"] if res.note else []
    for iclass in res.iclasses[:6]:
        out += _describe(iclass, insns.dataset()[iclass], max_forms)
        out.append("")
    if len(res.iclasses) > 6:
        out.append(f"... and {len(res.iclasses) - 6} more classes: {', '.join(res.iclasses[6:])}")
    out.append(insns.WIDTH_LEGEND)
    return "\n".join(out).strip()


@tool
def x86_flags(mnemonic: str) -> str:
    """Which RFLAGS bits an instruction reads, writes, sets, clears or leaves
    undefined - including count-dependent behaviour of shifts/rotates."""
    res = insns.resolve(mnemonic)
    out = [f"({res.note})"] if res.note else []
    for iclass in res.iclasses:
        out.append(f"{iclass}:")
        out += ["  " + s for s in insns.flag_summary(insns.dataset()[iclass])]
    return "\n".join(out)


@tool
def x86_exceptions(mnemonic: str) -> str:
    """Which exceptions an instruction can raise, and under what condition.

    Every line is tagged with its source: [XED] (the SDM exception class XED
    records for SIMD instructions), [derived] (general rules applied to XED's
    data, e.g. a memory operand means #PF is possible), or [curated]
    (instruction-specific facts written for this tool). Not exhaustive.
    """
    res = insns.resolve(mnemonic)
    out = [f"({res.note})"] if res.note else []
    for iclass in res.iclasses:
        lines = excmod.explain(iclass, insns.dataset()[iclass])
        out.append(f"{iclass}:")
        out += ["  " + ln for ln in lines] if lines else ["  nothing recorded - this list is not exhaustive"]
    out.append("Not exhaustive: the SDM's per-instruction exception tables are authoritative.")
    return "\n".join(out)


_CS_MODES = {16: capstone.CS_MODE_16, 32: capstone.CS_MODE_32, 64: capstone.CS_MODE_64}
_LEGACY_PREFIXES = {0x66, 0x67, 0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65}


def _decoded_iclasses(mnemonic: str, op_str: str) -> list[str]:
    """Map a capstone instruction to XED classes, using operands where XED
    splits one mnemonic into several classes (MOV to/from CRn is MOV_CR)."""
    if mnemonic == "mov":
        if re.search(r"\bcr\d+\b", op_str):
            return ["MOV_CR"]
        if re.search(r"\bdr\d+\b", op_str):
            return ["MOV_DR"]
    return insns.resolve(mnemonic).iclasses


def _is_apx_encoding(raw: bytes, mode: int) -> bool:
    """APX instructions only exist in 64-bit mode, as EVEX (0x62) or REX2 (0xD5)."""
    if mode != 64:
        return False
    i = 0
    while i < len(raw) and raw[i] in _LEGACY_PREFIXES:
        i += 1
    return i < len(raw) and raw[i] in (0x62, 0xD5)


@tool
def x86_decode(hex_bytes: str, mode: int = 64, address: int = 0) -> str:
    """Decode raw machine code (e.g. "48 01 d8 0f 0b") into instructions, each
    annotated with its ISA set, privilege, and flags written. mode is 16, 32
    or 64 (the CPU mode the bytes run in)."""
    if mode not in _CS_MODES:
        raise ValueError("mode must be 16, 32 or 64")
    try:
        code = bytes.fromhex(hex_bytes.replace(" ", "").replace("0x", "").replace(",", ""))
    except ValueError:
        raise ValueError(f"not a hex byte string: {hex_bytes!r}") from None
    if not code:
        raise ValueError("no bytes to decode")
    md = capstone.Cs(capstone.CS_ARCH_X86, _CS_MODES[mode])
    out: list[str] = []
    end = address
    for insn in md.disasm(code, address):
        end = insn.address + insn.size
        text = f"{insn.mnemonic} {insn.op_str}".strip()
        out.append(f"{insn.address:#06x}  {insn.bytes.hex(' '):<24} {text}")
        name = insn.mnemonic
        if name.startswith(("rep ", "repe ", "repne ", "lock ")):
            prefix, _, rest = name.partition(" ")
            name = f"{prefix} {rest}" if prefix != "lock" else rest
        try:
            iclasses = _decoded_iclasses(name, insn.op_str)
        except KeyError:
            out.append("        (no XED class matched this mnemonic)")
            continue
        apx = _is_apx_encoding(bytes(insn.bytes), mode)
        forms = [f for c in iclasses for f in insns.dataset()[c]
                 if f["isa_set"].startswith("APX") == apx] or                 [f for c in iclasses for f in insns.dataset()[c]]
        cpl = "CPL0" if all(f["cpl"] == 0 for f in forms) else "any CPL"
        written = sorted({fl for f in forms for e in insns.parse_flags(f["flags"])
                          for act, fls in e.actions.items() if act != "read" for fl in fls})
        read = sorted({fl for f in forms for e in insns.parse_flags(f["flags"])
                       for fl in e.actions.get("read", [])})
        isa = ",".join(_uniq([f["isa_set"] for f in forms]))
        info = f"        {'/'.join(iclasses)} | {isa} | {cpl}"
        if read:
            info += f" | reads {' '.join(read)}"
        if written:
            info += f" | writes {' '.join(written)}"
        out.append(info)
    decoded = end - address
    if decoded < len(code):
        out.append(f"(stopped at byte {decoded}: {code[decoded:decoded + 8].hex(' ')} is not a valid "
                   f"{mode}-bit instruction)")
    if not out:
        raise ValueError(f"no valid {mode}-bit instruction at the start of {hex_bytes!r}")
    return "\n".join(out)


@tool
def x86_register(name: str, value: str | None = None) -> str:
    """Bit layout of a control/system register, decoding a value if given.

    name: rflags, cr0, cr3, cr4, efer, dr7, xcr0, selector, pte (page-table
    entry), pf_error (page-fault error code), apic_base. value: e.g.
    "0x80000011". Set bits are named; bits this table doesn't define are
    reported, not hidden.
    """
    reg = arch.find_register(name)
    out = [f"{reg.name} - {reg.summary}"]
    if value is None:
        out.append("bit(s)  field            meaning")
        out += arch.layout(reg)
    else:
        try:
            v = int(value.replace("_", ""), 0)
        except ValueError:
            raise ValueError(f"not a number: {value!r} (use 0x... for hex)") from None
        decoded = arch.decode(reg, v)
        out.append(f"{v:#x}:" + ("" if decoded else " no bits set"))
        out += ["  " + d for d in decoded]
    if reg.notes:
        out.append("note: " + reg.notes)
    return "\n".join(out)


@tool
def x86_msr(query: str, value: str | None = None) -> str:
    """Look up a model-specific register by number (0xC0000080) or name
    (EFER, LSTAR, "apic base"). Covers common architectural MSRs; with value,
    decodes it where a bit layout is known."""
    hits = arch.find_msrs(query)
    out = []
    for m in hits:
        out.append(f"{m.number:#x}  {m.name}: {m.meaning}")
        if m.register:
            reg = arch.REGISTERS[m.register]
            if value is not None:
                v = int(value.replace("_", ""), 0)
                out += ["    " + d for d in arch.decode(reg, v)] or ["    no bits set"]
            else:
                out += ["    " + row for row in arch.layout(reg)]
    return "\n".join(out)


@tool
def x86_vector(vector: str) -> str:
    """Describe an exception vector by number (14, 0xe) or mnemonic (#PF):
    name, fault/trap/abort, and whether it pushes an error code."""
    q = vector.strip().upper()
    try:
        num = int(q, 0)
    except ValueError:
        num = next((n for n, v in arch.VECTORS.items() if v[0] == q or v[0] == "#" + q), -1)
    if num not in arch.VECTORS:
        if 32 <= num <= 255:
            return f"vector {num:#x}: not a CPU exception (32-255 are free for IRQs and software INT n)"
        raise KeyError(f"no CPU exception {vector!r}. Vectors 0-21 are architectural "
                       f"(9, 15 and 22-31 are reserved).")
    mn, name, kind, err = arch.VECTORS[num]
    return (f"vector {num} ({num:#04x}) {mn}: {name} - {kind}; "
            f"{'pushes an error code' if err else 'no error code'}")


@tool
def x86_search(query: str, limit: int = 40) -> str:
    """Find instructions by name fragment, ISA set, extension or category -
    e.g. "AES", "AVX512", "SYSTEM", "CMOV", "XSAVE"."""
    if not 1 <= limit <= 200:
        raise ValueError("limit must be between 1 and 200")
    hits = insns.search(query, limit)
    if not hits:
        return f"no instructions match {query!r}"
    return "\n".join(f"{iclass:<24} {f['isa_set']:<20} {f['category']}" for iclass, f in hits)


@tool
def x86_about() -> str:
    """Where this server's data comes from, and its licenses."""
    p = insns.provenance()
    return (f"Instructions: Intel XED {p['source']} @ {p['xed_commit'][:12]} "
            f"({p['iclasses']} instruction classes, {p['forms']} forms), Apache-2.0, extracted "
            f"with XED's own generator and reader on {p['built']}. Register, MSR and exception "
            f"tables plus [curated] notes: hand-written for this project (MIT). No Intel SDM text "
            f"is included.")


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
