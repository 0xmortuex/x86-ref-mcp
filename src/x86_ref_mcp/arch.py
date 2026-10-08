"""Hand-written architectural tables: register bit layouts, MSRs, exceptions.

These are not from XED (which describes instructions, not registers). They
are terse statements of architectural facts - bit positions and names - kept
deliberately small; no manual prose is reproduced. Where a layout depends on
CPU features (MAXPHYADDR, CR4.PCIDE, 4- vs 5-level paging) the description
says so instead of guessing.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Field:
    name: str
    lo: int
    hi: int
    meaning: str

    @property
    def width(self) -> int:
        return self.hi - self.lo + 1


@dataclass(frozen=True)
class Register:
    name: str
    bits: int
    summary: str
    fields: tuple[Field, ...]
    reserved_ok: tuple[int, ...] = ()  # bits that are reserved but read as 1 (e.g. RFLAGS bit 1)
    notes: str = ""


def F(name: str, lo: int, hi: int | None = None, meaning: str = "") -> Field:
    return Field(name, lo, lo if hi is None else hi, meaning)


REGISTERS: dict[str, Register] = {
    "rflags": Register("RFLAGS", 64, "status and control flags", (
        F("CF", 0, meaning="carry"), F("PF", 2, meaning="parity (low byte has even number of 1s)"),
        F("AF", 4, meaning="auxiliary carry (BCD)"), F("ZF", 6, meaning="zero"),
        F("SF", 7, meaning="sign"), F("TF", 8, meaning="trap: single-step, #DB after each instruction"),
        F("IF", 9, meaning="maskable interrupts enabled"), F("DF", 10, meaning="string ops decrement"),
        F("OF", 11, meaning="signed overflow"), F("IOPL", 12, 13, meaning="I/O privilege level"),
        F("NT", 14, meaning="nested task"), F("RF", 16, meaning="resume: suppress instruction #DB once"),
        F("VM", 17, meaning="virtual-8086 mode"), F("AC", 18, meaning="alignment check (CPL3, with CR0.AM) / SMAP override"),
        F("VIF", 19, meaning="virtual IF"), F("VIP", 20, meaning="virtual interrupt pending"),
        F("ID", 21, meaning="CPUID available if this bit can be toggled"),
    ), reserved_ok=(1,), notes="Bit 1 is reserved and always reads 1, so a 'clean' value is 0x2."),
    "cr0": Register("CR0", 64, "basic operating mode", (
        F("PE", 0, meaning="protected mode enable"), F("MP", 1, meaning="monitor coprocessor (WAIT/FWAIT honour TS)"),
        F("EM", 2, meaning="no x87: x87 instructions raise #NM (and MMX/SSE raise #UD)"),
        F("TS", 3, meaning="task switched: next x87/SIMD use raises #NM (lazy FPU switching)"),
        F("ET", 4, meaning="extension type (hardwired 1 on modern CPUs)"),
        F("NE", 5, meaning="native x87 error reporting (#MF) instead of IRQ13"),
        F("WP", 16, meaning="write protect: CPL0 honours read-only pages"),
        F("AM", 18, meaning="alignment mask: enables #AC with EFLAGS.AC at CPL3"),
        F("NW", 29, meaning="not write-through (cache control)"), F("CD", 30, meaning="cache disable"),
        F("PG", 31, meaning="paging enable (requires PE)"),
    )),
    "cr3": Register("CR3", 64, "page-table root", (
        F("PWT", 3, meaning="page-level write-through for the top-level table (ignored when CR4.PCIDE=1)"),
        F("PCD", 4, meaning="page-level cache disable for the top-level table (ignored when CR4.PCIDE=1)"),
        F("PML4/PML5 base", 12, 51, meaning="physical address of the top-level table (upper bound is MAXPHYADDR-1)"),
        F("LAM_U57", 61, meaning="linear address masking, user, 57-bit"),
        F("LAM_U48", 62, meaning="linear address masking, user, 48-bit"),
    ), notes=("With CR4.PCIDE=1, bits 11:0 hold the PCID, and bit 63 on a MOV to CR3 means "
              "'don't flush this PCID' (it is not stored). In 32-bit non-PAE paging the base is bits 31:12.")),
    "cr4": Register("CR4", 64, "architectural extensions", (
        F("VME", 0, meaning="virtual-8086 mode extensions"), F("PVI", 1, meaning="protected-mode virtual interrupts"),
        F("TSD", 2, meaning="RDTSC/RDTSCP only at CPL0"), F("DE", 3, meaning="debugging extensions (I/O breakpoints)"),
        F("PSE", 4, meaning="4 MiB pages in 32-bit paging"), F("PAE", 5, meaning="physical address extension (required for long mode)"),
        F("MCE", 6, meaning="machine-check exception enable"), F("PGE", 7, meaning="global pages"),
        F("PCE", 8, meaning="RDPMC at any CPL"), F("OSFXSR", 9, meaning="OS supports FXSAVE/FXRSTOR (SSE enabled)"),
        F("OSXMMEXCPT", 10, meaning="OS handles #XM (else SIMD FP exceptions raise #UD)"),
        F("UMIP", 11, meaning="SGDT/SIDT/SLDT/SMSW/STR only at CPL0"), F("LA57", 12, meaning="5-level paging"),
        F("VMXE", 13, meaning="VMX enable"), F("SMXE", 14, meaning="SMX enable"),
        F("FSGSBASE", 16, meaning="RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE enabled"),
        F("PCIDE", 17, meaning="process-context identifiers"), F("OSXSAVE", 18, meaning="XSAVE and XGETBV/XSETBV enabled"),
        F("KL", 19, meaning="Key Locker"), F("SMEP", 20, meaning="supervisor-mode execution prevention"),
        F("SMAP", 21, meaning="supervisor-mode access prevention"), F("PKE", 22, meaning="protection keys, user pages"),
        F("CET", 23, meaning="control-flow enforcement"), F("PKS", 24, meaning="protection keys, supervisor pages"),
        F("UINTR", 25, meaning="user interrupts"), F("LAM_SUP", 28, meaning="linear address masking, supervisor"),
    )),
    "efer": Register("IA32_EFER (MSR 0xC0000080)", 64, "extended feature enables", (
        F("SCE", 0, meaning="SYSCALL/SYSRET enable"), F("LME", 8, meaning="long mode enable (takes effect when paging is turned on)"),
        F("LMA", 10, meaning="long mode active (read-only status)"), F("NXE", 11, meaning="no-execute bit (bit 63 of page entries) enabled"),
        F("SVME", 12, meaning="AMD SVM enable"), F("LMSLE", 13, meaning="AMD long-mode segment limit enable"),
        F("FFXSR", 14, meaning="AMD fast FXSAVE/FXRSTOR"), F("TCE", 15, meaning="AMD translation cache extension"),
    )),
    "dr7": Register("DR7", 64, "debug breakpoint control", (
        F("L0", 0), F("G0", 1), F("L1", 2), F("G1", 3), F("L2", 4), F("G2", 5), F("L3", 6), F("G3", 7),
        F("LE", 8, meaning="exact local breakpoints"), F("GE", 9, meaning="exact global breakpoints"),
        F("RTM", 11, meaning="RTM debugging"), F("GD", 13, meaning="general detect: #DB on MOV to/from DRx"),
        F("R/W0", 16, 17, meaning="0=exec 1=write 2=I/O 3=read/write"), F("LEN0", 18, 19, meaning="0=1B 1=2B 2=8B 3=4B"),
        F("R/W1", 20, 21), F("LEN1", 22, 23), F("R/W2", 24, 25), F("LEN2", 26, 27), F("R/W3", 28, 29), F("LEN3", 30, 31),
    ), reserved_ok=(10,), notes="Bit 10 is reserved and reads 1, so the reset value is 0x400. Ln/Gn enable breakpoint n locally/globally."),
    "xcr0": Register("XCR0", 64, "XSAVE state components the OS enabled (XSETBV ECX=0)", (
        F("x87", 0, meaning="always 1"), F("SSE", 1, meaning="XMM registers + MXCSR"), F("AVX", 2, meaning="upper halves of YMM"),
        F("BNDREG", 3, meaning="MPX bounds registers"), F("BNDCSR", 4, meaning="MPX config/status"),
        F("opmask", 5, meaning="AVX-512 k0-k7"), F("ZMM_Hi256", 6, meaning="upper halves of ZMM0-15"),
        F("Hi16_ZMM", 7, meaning="ZMM16-31"), F("PKRU", 9, meaning="protection-key rights"),
        F("TILECFG", 17, meaning="AMX tile config"), F("TILEDATA", 18, meaning="AMX tile data"),
    )),
    "selector": Register("segment selector", 16, "value loaded into CS/DS/ES/FS/GS/SS", (
        F("RPL", 0, 1, meaning="requested privilege level"), F("TI", 2, meaning="table: 0=GDT 1=LDT"),
        F("index", 3, 15, meaning="descriptor index (byte offset = index * 8)"),
    )),
    "pte": Register("x86-64 page-table entry (4 KiB PTE; PDE/PDPTE share most bits)", 64, "one paging-structure entry", (
        F("P", 0, meaning="present"), F("R/W", 1, meaning="writable"), F("U/S", 2, meaning="user-accessible"),
        F("PWT", 3, meaning="write-through"), F("PCD", 4, meaning="cache disable"), F("A", 5, meaning="accessed"),
        F("D", 6, meaning="dirty (leaf entries)"), F("PAT/PS", 7, meaning="PAT bit in a 4 KiB PTE; page-size (huge page) bit in a PDE/PDPTE"),
        F("G", 8, meaning="global (leaf entries, with CR4.PGE)"), F("address", 12, 51, meaning="physical frame (upper bound is MAXPHYADDR-1)"),
        F("PK", 59, 62, meaning="protection key (with CR4.PKE/PKS)"), F("XD/NX", 63, meaning="no-execute (with EFER.NXE)"),
    ), notes="In a 2 MiB/1 GiB leaf (PS=1) the PAT bit moves to bit 12 and the address starts at bit 21/30."),
    "pf_error": Register("#PF error code", 32, "pushed with a page fault (faulting address is in CR2)", (
        F("P", 0, meaning="0=page not present, 1=protection violation"), F("W/R", 1, meaning="write access"),
        F("U/S", 2, meaning="access from CPL3"), F("RSVD", 3, meaning="reserved bit set in a paging entry"),
        F("I/D", 4, meaning="instruction fetch"), F("PK", 5, meaning="protection-key violation"),
        F("SS", 6, meaning="shadow-stack access"), F("SGX", 15, meaning="SGX access-control violation"),
    )),
    "apic_base": Register("IA32_APIC_BASE (MSR 0x1B)", 64, "local APIC location and enable", (
        F("BSP", 8, meaning="this CPU is the bootstrap processor"), F("EXTD", 10, meaning="x2APIC mode enabled"),
        F("EN", 11, meaning="xAPIC global enable"), F("base", 12, 51, meaning="APIC MMIO physical base (default 0xFEE00000)"),
    )),
}

ALIASES = {"eflags": "rflags", "flags": "rflags", "ia32_efer": "efer", "msr_efer": "efer",
           "pde": "pte", "pdpte": "pte", "pml4e": "pte", "page_fault": "pf_error", "pf": "pf_error",
           "ia32_apic_base": "apic_base", "sel": "selector"}


def find_register(name: str) -> Register:
    key = name.strip().lower().replace(" ", "_")
    key = ALIASES.get(key, key)
    if key not in REGISTERS:
        raise KeyError(f"no layout for {name!r}. Known: {', '.join(sorted(REGISTERS))} "
                       f"(aliases: {', '.join(sorted(ALIASES))})")
    return REGISTERS[key]


def decode(reg: Register, value: int) -> list[str]:
    if value < 0 or value >= 1 << reg.bits:
        raise ValueError(f"{value:#x} does not fit in {reg.bits}-bit {reg.name}")
    out: list[str] = []
    covered = 0
    for f in reg.fields:
        mask = ((1 << f.width) - 1) << f.lo
        covered |= mask
        v = (value & mask) >> f.lo
        if f.width == 1:
            if v:
                out.append(f"{f.name} (bit {f.lo})" + (f" - {f.meaning}" if f.meaning else ""))
        elif v:
            # Wide fields are addresses (page frames, table bases): show them in
            # place, as the address they denote. Narrow ones are small numbers.
            shown = f"{v << f.lo:#x}" if f.width >= 20 else f"{v}"
            out.append(f"{f.name} (bits {f.hi}:{f.lo}) = {shown}" + (f" - {f.meaning}" if f.meaning else ""))
    stray = value & ~covered
    for bit in range(reg.bits):
        if stray >> bit & 1:
            if bit in reg.reserved_ok:
                out.append(f"bit {bit}: reserved, always reads 1")
            else:
                out.append(f"bit {bit}: not a defined field in this table (reserved, or a feature not listed)")
    return out


def layout(reg: Register) -> list[str]:
    rows = []
    for f in reg.fields:
        bits = f"{f.lo}" if f.width == 1 else f"{f.hi}:{f.lo}"
        rows.append(f"{bits:>6}  {f.name:<16} {f.meaning}".rstrip())
    return rows


# -- MSRs --------------------------------------------------------------------

@dataclass(frozen=True)
class MSR:
    number: int
    name: str
    meaning: str
    register: str | None = None  # key into REGISTERS for a bit layout


MSRS: tuple[MSR, ...] = (
    MSR(0x10, "IA32_TIME_STAMP_COUNTER", "the TSC that RDTSC reads"),
    MSR(0x1B, "IA32_APIC_BASE", "local APIC base address and enable", "apic_base"),
    MSR(0x3A, "IA32_FEATURE_CONTROL", "lock bit and VMX enable outside/inside SMX"),
    MSR(0x3B, "IA32_TSC_ADJUST", "per-CPU TSC offset"),
    MSR(0x48, "IA32_SPEC_CTRL", "speculation controls (IBRS, STIBP, SSBD)"),
    MSR(0x49, "IA32_PRED_CMD", "write-only: IBPB barrier"),
    MSR(0xFE, "IA32_MTRRCAP", "MTRR capabilities"),
    MSR(0x174, "IA32_SYSENTER_CS", "SYSENTER target code segment"),
    MSR(0x175, "IA32_SYSENTER_ESP", "SYSENTER stack pointer"),
    MSR(0x176, "IA32_SYSENTER_EIP", "SYSENTER entry point"),
    MSR(0x179, "IA32_MCG_CAP", "machine-check capabilities"),
    MSR(0x1A0, "IA32_MISC_ENABLE", "assorted Intel feature enables"),
    MSR(0x277, "IA32_PAT", "page attribute table: 8 entries, one per byte (types: 0=UC 1=WC 4=WT 5=WP 6=WB 7=UC-)"),
    MSR(0x2FF, "IA32_MTRR_DEF_TYPE", "default memory type and MTRR enable"),
    MSR(0x6E0, "IA32_TSC_DEADLINE", "LAPIC timer deadline (TSC-deadline mode)"),
    MSR(0x802, "x2APIC ID", "local APIC ID (x2APIC mode)"),
    MSR(0x803, "x2APIC VERSION", "local APIC version"),
    MSR(0x808, "x2APIC TPR", "task priority"),
    MSR(0x80B, "x2APIC EOI", "write 0 to signal end of interrupt"),
    MSR(0x80F, "x2APIC SIVR", "spurious vector; bit 8 = APIC software enable"),
    MSR(0x830, "x2APIC ICR", "interrupt command register (64-bit, single MSR in x2APIC mode)"),
    MSR(0x832, "x2APIC LVT TIMER", "timer vector and mode"),
    MSR(0x838, "x2APIC TIMER INITIAL COUNT", "timer initial count"),
    MSR(0x839, "x2APIC TIMER CURRENT COUNT", "timer current count"),
    MSR(0x83E, "x2APIC TIMER DIVIDE", "timer divide configuration"),
    MSR(0xDA0, "IA32_XSS", "supervisor state components for XSAVES"),
    MSR(0xC0000080, "IA32_EFER", "extended feature enables (SCE, LME, LMA, NXE)", "efer"),
    MSR(0xC0000081, "IA32_STAR", "SYSCALL/SYSRET selectors: bits 47:32 SYSCALL CS (SS=CS+8), bits 63:48 SYSRET base"),
    MSR(0xC0000082, "IA32_LSTAR", "SYSCALL entry point in 64-bit mode"),
    MSR(0xC0000083, "IA32_CSTAR", "SYSCALL entry point in compatibility mode (AMD)"),
    MSR(0xC0000084, "IA32_FMASK", "RFLAGS bits cleared on SYSCALL"),
    MSR(0xC0000100, "IA32_FS_BASE", "FS segment base"),
    MSR(0xC0000101, "IA32_GS_BASE", "GS segment base"),
    MSR(0xC0000102, "IA32_KERNEL_GS_BASE", "value SWAPGS exchanges with GS base"),
    MSR(0xC0000103, "IA32_TSC_AUX", "value RDTSCP/RDPID return in ECX"),
)


def find_msrs(query: str) -> list[MSR]:
    q = query.strip()
    try:
        number = int(q, 0)
    except ValueError:
        number = None
    if number is not None:
        hits = [m for m in MSRS if m.number == number]
    else:
        key = q.upper().replace(" ", "_")
        hits = [m for m in MSRS if m.name.upper() == key or m.name.upper() == "IA32_" + key]
        if not hits:
            hits = [m for m in MSRS if key in m.name.upper().replace(" ", "_")
                    or q.lower() in m.meaning.lower()]
    if not hits:
        raise KeyError(f"no MSR matching {query!r} in this table ({len(MSRS)} common architectural "
                       f"MSRs). Model-specific MSRs are not covered.")
    return hits


# -- exception vectors ----------------------------------------------------------

# (mnemonic, name, class, pushes error code)
VECTORS: dict[int, tuple[str, str, str, bool]] = {
    0x00: ("#DE", "divide error", "fault", False),
    0x01: ("#DB", "debug", "fault or trap", False),
    0x02: ("NMI", "non-maskable interrupt", "interrupt", False),
    0x03: ("#BP", "breakpoint (INT3)", "trap", False),
    0x04: ("#OF", "overflow (INTO)", "trap", False),
    0x05: ("#BR", "bound range exceeded", "fault", False),
    0x06: ("#UD", "invalid opcode", "fault", False),
    0x07: ("#NM", "device not available", "fault", False),
    0x08: ("#DF", "double fault", "abort", True),
    0x0A: ("#TS", "invalid TSS", "fault", True),
    0x0B: ("#NP", "segment not present", "fault", True),
    0x0C: ("#SS", "stack-segment fault", "fault", True),
    0x0D: ("#GP", "general protection", "fault", True),
    0x0E: ("#PF", "page fault", "fault", True),
    0x10: ("#MF", "x87 floating-point error", "fault", False),
    0x11: ("#AC", "alignment check", "fault", True),
    0x12: ("#MC", "machine check", "abort", False),
    0x13: ("#XM", "SIMD floating-point exception", "fault", False),
    0x14: ("#VE", "virtualization exception", "fault", False),
    0x15: ("#CP", "control protection", "fault", True),
}
