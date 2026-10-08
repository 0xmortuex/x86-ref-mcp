"""Which exceptions an instruction can raise, and why.

The SDM gives each instruction a hand-written exception table; nothing open
and machine-readable reproduces it for the legacy ISA. So this module is
explicit about where every line comes from:

  [XED]      the exception *class* XED records for SIMD/AVX/AVX-512/APX
             instructions (e.g. "avx-type-2"), which names the SDM's
             exception-class table for that instruction
  [derived]  general architectural rules applied to XED's data: CPL 0 means
             #GP(0) at CPL > 0; a memory operand means #GP/#SS/#PF/#AC are
             possible; a non-LOCKABLE instruction raises #UD with a LOCK prefix
  [curated]  short, instruction-specific facts written for this project
             (DIV raises #DE, RDTSC honours CR4.TSD, SYSCALL needs EFER.SCE)

It is not exhaustive. Missing from a list is not proof an exception can't occur.
"""

from __future__ import annotations

from .insns import Form, valid_modes

# iclass -> [(exception, condition)]; also used for x86_insn's notes.
CURATED: dict[str, list[tuple[str, str]]] = {
    "DIV": [("#DE", "divisor is 0, or the quotient doesn't fit the destination")],
    "IDIV": [("#DE", "divisor is 0, or the quotient doesn't fit (e.g. INT_MIN / -1)")],
    "AAM": [("#DE", "immediate base is 0")],
    "INT3": [("#BP", "always - this is the breakpoint instruction")],
    "INT1": [("#DB", "always")],
    "INTO": [("#OF", "if EFLAGS.OF = 1")],
    "BOUND": [("#BR", "index outside the bounds"), ("#UD", "second operand is a register")],
    "UD0": [("#UD", "always - reserved undefined opcode")],
    "UD1": [("#UD", "always - reserved undefined opcode")],
    "UD2": [("#UD", "always - reserved undefined opcode")],
    "INT": [("#GP", "the IDT gate's DPL < CPL (software INT n checks gate DPL)"),
            ("#NP", "the gate is not present"), ("#GP", "vector beyond the IDT limit")],
    "RDTSC": [("#GP(0)", "CR4.TSD = 1 and CPL > 0")],
    "RDTSCP": [("#GP(0)", "CR4.TSD = 1 and CPL > 0")],
    "RDPMC": [("#GP(0)", "CR4.PCE = 0 and CPL > 0, or ECX names an invalid counter")],
    "RDMSR": [("#GP(0)", "ECX names a reserved or unimplemented MSR")],
    "WRMSR": [("#GP(0)", "ECX names a reserved/unimplemented MSR, or a reserved bit is set "
                          "(or a non-canonical address is written to an address MSR)")],
    "SYSCALL": [("#UD", "EFER.SCE = 0, or not in 64-bit mode (Intel)")],
    "SYSRET": [("#UD", "EFER.SCE = 0"), ("#GP(0)", "CPL > 0, or RCX is non-canonical (64-bit return)")],
    "CPUID": [("#GP(0)", "CPUID faulting is enabled and CPL > 0")],
    "CLI": [("#GP(0)", "protected mode and CPL > IOPL (unless CR4.PVI/VME virtualise IF)")],
    "STI": [("#GP(0)", "protected mode and CPL > IOPL (unless CR4.PVI/VME virtualise IF)")],
    "IN": [("#GP(0)", "protected mode, CPL > IOPL, and the TSS I/O bitmap denies the port")],
    "OUT": [("#GP(0)", "protected mode, CPL > IOPL, and the TSS I/O bitmap denies the port")],
    "SGDT": [("#GP(0)", "CR4.UMIP = 1 and CPL > 0")],
    "SIDT": [("#GP(0)", "CR4.UMIP = 1 and CPL > 0")],
    "SLDT": [("#GP(0)", "CR4.UMIP = 1 and CPL > 0")],
    "SMSW": [("#GP(0)", "CR4.UMIP = 1 and CPL > 0")],
    "STR": [("#GP(0)", "CR4.UMIP = 1 and CPL > 0")],
    "RDFSBASE": [("#UD", "CR4.FSGSBASE = 0, or not in 64-bit mode")],
    "RDGSBASE": [("#UD", "CR4.FSGSBASE = 0, or not in 64-bit mode")],
    "WRFSBASE": [("#UD", "CR4.FSGSBASE = 0, or not in 64-bit mode"), ("#GP(0)", "non-canonical address")],
    "WRGSBASE": [("#UD", "CR4.FSGSBASE = 0, or not in 64-bit mode"), ("#GP(0)", "non-canonical address")],
    "MOV_CR": [("#GP(0)", "writing a reserved bit or an invalid combination (e.g. CR0.PG=1 with PE=0)"),
               ("#UD", "the control register doesn't exist (e.g. CR1, CR5-7)")],
    "MOV_DR": [("#UD", "DR4/DR5 with CR4.DE = 1"), ("#DB", "DR7.GD = 1 (general-detect)")],
    "XSETBV": [("#GP(0)", "invalid XCR0 value (e.g. bit 0 clear, or AVX without SSE)")],
    "LGDT": [("#GP(0)", "in 64-bit mode, a non-canonical base")],
    "LIDT": [("#GP(0)", "in 64-bit mode, a non-canonical base")],
    "SWAPGS": [("#UD", "not in 64-bit mode")],
}

# iclass -> notes that aren't exceptions (privilege, CPUID facts XED models differently).
NOTES: dict[str, list[str]] = {
    "RDTSC": ["Feature flag: CPUID.(EAX=1H):EDX[4] (TSC). XED files it under ISA set PENTIUMREAL "
              "with no CPUID record.", "CR4.TSD makes it CPL0-only."],
    "RDTSCP": ["CR4.TSD makes it CPL0-only; ECX receives IA32_TSC_AUX."],
    "SYSCALL": ["XED files SYSCALL under ISA set LONGMODE and records the long-mode CPUID bit. "
                "The SYSCALL/SYSRET feature bit itself is CPUID.(EAX=80000001H):EDX[11].",
                "Needs EFER.SCE = 1; entry point from IA32_LSTAR, selectors from IA32_STAR, "
                "RFLAGS masked by IA32_FMASK."],
    "RDPMC": ["CR4.PCE = 1 allows it at any CPL."],
    "CLI": ["Allowed when CPL <= IOPL. XED's CPL field is 3 because the check is IOPL-based."],
    "STI": ["Allowed when CPL <= IOPL. Interrupts stay blocked until after the next instruction."],
    "IN": ["Allowed when CPL <= IOPL, or when the TSS I/O permission bitmap grants the port."],
    "OUT": ["Allowed when CPL <= IOPL, or when the TSS I/O permission bitmap grants the port."],
    "SGDT": ["CR4.UMIP = 1 restricts it to CPL0."],
    "SIDT": ["CR4.UMIP = 1 restricts it to CPL0."],
    "SWAPGS": ["Exchanges GS base with IA32_KERNEL_GS_BASE; 64-bit mode, CPL0."],
}

_MEM_PREFIXES = ("MEM0", "MEM1")


def _has_memory(form: Form) -> bool:
    return any(op.split(":")[0].split("=")[0] in _MEM_PREFIXES for op in form["operands"])


def _uses_stack(form: Form) -> bool:
    return any("STACKPUSH" in op or "STACKPOP" in op for op in form["operands"])


def explain(iclass: str, forms: list[Form]) -> list[str]:
    lines: list[str] = []
    seen: set[str] = set()

    def add(source: str, exc: str, why: str) -> None:
        line = f"{exc:<7} [{source}] {why}"
        if line not in seen:
            seen.add(line)
            lines.append(line)

    for exc, why in CURATED.get(iclass, []):
        add("curated", exc, why)

    def scope(subset: list[Form]) -> str:
        """' (only ISA sets X, Y)' when a rule covers some forms, not all."""
        if len(subset) == len(forms):
            return ""
        sets = sorted({f["isa_set"] for f in subset})
        return f" (only forms in ISA set{'s' if len(sets) > 1 else ''} {', '.join(sets)})"

    classes = sorted({f["exceptions"] for f in forms if f["exceptions"]})
    for c in classes:
        subset = [f for f in forms if f["exceptions"] == c]
        add("XED", "class", f"SIMD exception class {c}: the SDM's exception-class table "
                            f"of that name lists the exact #UD/#NM/#GP/#SS/#PF/#AC/#XM "
                            f"conditions{scope(subset)}")

    if any(f["cpl"] == 0 for f in forms):
        add("derived", "#GP(0)", "executed at CPL > 0 (XED: CPL 0 required)")
    modes = valid_modes(forms)
    if len(modes) < 3:
        add("derived", "#UD", f"executed outside {' / '.join(modes)} mode")
    with_cpuid = [f for f in forms if f["cpuid"]]
    if with_cpuid:
        add("derived", "#UD", f"the CPU lacks the required CPUID feature (see x86_insn)"
                              f"{scope(with_cpuid)}")
    if not all("LOCKABLE" in f["attributes"] for f in forms):
        which = "any form" if not any("LOCKABLE" in f["attributes"] for f in forms) else "non-lockable forms"
        add("derived", "#UD", f"used with a LOCK prefix ({which}; LOCK is only valid on "
                              f"lockable read-modify-write forms with a memory destination)")
    if any(_has_memory(f) for f in forms):
        add("derived", "#GP(0)", "memory operand outside the segment limit, or non-canonical in 64-bit mode")
        add("derived", "#SS(0)", "memory operand addressed through SS is out of limit / non-canonical")
        add("derived", "#PF", "memory operand hits a not-present or protected page (paging on)")
        if any(f["cpl"] == 3 for f in forms):
            add("derived", "#AC(0)", "unaligned memory operand at CPL 3 with CR0.AM = 1 and EFLAGS.AC = 1")
    if any(_uses_stack(f) for f in forms):
        add("derived", "#SS(0)", "implicit stack access out of limit / non-canonical")
        add("derived", "#PF", "implicit stack access hits a not-present or protected page")
    exts = {f["extension"] for f in forms}
    if "X87" in exts:
        add("derived", "#NM", "CR0.EM = 1 or CR0.TS = 1 (x87 instruction)")
        add("derived", "#MF", "an unmasked x87 exception is pending (with CR0.NE = 1)")
    if any("MXCSR" in f["attributes"] for f in forms):
        add("derived", "#XM", "an unmasked SIMD floating-point exception "
                              "(#UD instead when CR4.OSXMMEXCPT = 0)")
    return lines
