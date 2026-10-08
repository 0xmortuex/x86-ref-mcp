# x86-ref-mcp

**x86 facts for AI agents, from Intel's own machine-readable ISA database instead of the model's memory.**

<!-- mcp-name: io.github.0xmortuex/x86-ref-mcp -->

Ask a model which flags `SHL` leaves undefined, whether `RDTSC` works at CPL 3, which CPUID bit
`CMOV` needs, or what `CR4 = 0x3606e0` means, and you often get a confident, wrong answer.
x86-ref-mcp is an [MCP](https://modelcontextprotocol.io) server that answers these questions
from data:

- **Instructions:** [Intel XED](https://github.com/intelxed/xed)'s ISA database (Apache-2.0),
  covering 1,987 instruction classes and 10,994 encoding forms. It includes flags read and
  written, ISA set, CPUID requirements, required privilege level, valid modes, operands, and
  exception classes.
- **Registers, MSRs and exception vectors:** compact hand-written tables (bit positions and
  names).
- **Raw bytes:** a decoder (capstone) that annotates every instruction with the facts above.

It's built for OS and low-level developers, and pairs with
[gdbstub-mcp](https://github.com/0xmortuex/gdbstub-mcp) and
[qemu-mcp](https://github.com/0xmortuex/qemu-mcp).

## What it looks like

Real output:

```
> x86_decode("0f 20 c0 0d 01 00 00 80 0f 22 c0", mode=32)
0x0000  0f 20 c0                 mov eax, cr0
        MOV_CR | I86 | CPL0
0x0003  0d 01 00 00 80           or eax, 0x80000001
        OR | I86 | any CPL | writes AF CF OF PF SF ZF
0x0008  0f 22 c0                 mov cr0, eax
        MOV_CR | I86 | CPL0

> x86_flags("shl")
SHL:
  8 form(s) (SHL_MEMb_IMMb_C0r4, SHL_GPR8_IMMb_C0r4, SHL_MEMb_IMMb_C0r6 +5 more):
    when count == 1: written: OF SF ZF PF CF; undefined: AF
    when count > 1: undefined: OF AF; written: SF ZF PF CF
  ...

> x86_register("cr4", "0x3606e0")
CR4 - architectural extensions
0x3606e0:
  PAE (bit 5) - physical address extension (required for long mode)
  MCE (bit 6) - machine-check exception enable
  PGE (bit 7) - global pages
  OSFXSR (bit 9) - OS supports FXSAVE/FXRSTOR (SSE enabled)
  OSXMMEXCPT (bit 10) - OS handles #XM (else SIMD FP exceptions raise #UD)
  PCIDE (bit 17) - process-context identifiers
  OSXSAVE (bit 18) - XSAVE and XGETBV/XSETBV enabled
  SMEP (bit 20) - supervisor-mode execution prevention
  SMAP (bit 21) - supervisor-mode access prevention

> x86_exceptions("div")
DIV:
  #DE     [curated] divisor is 0, or the quotient doesn't fit the destination
  class   [XED] SIMD exception class APX-EVEX-INT: ... (only forms in ISA sets APX_F, APX_F_N3)
  #UD     [derived] used with a LOCK prefix (any form; ...)
  #GP(0)  [derived] memory operand outside the segment limit, or non-canonical in 64-bit mode
  #SS(0)  [derived] memory operand addressed through SS is out of limit / non-canonical
  #PF     [derived] memory operand hits a not-present or protected page (paging on)
  #AC(0)  [derived] unaligned memory operand at CPL 3 with CR0.AM = 1 and EFLAGS.AC = 1
Not exhaustive: the SDM's per-instruction exception tables are authoritative.
```

## Install

```bash
pip install x86-ref-mcp
claude mcp add x86-ref -- x86-ref-mcp
```

Any MCP client works: run `x86-ref-mcp` as a stdio server. Python 3.10+. All data ships
in the package, so it needs no network and no XED checkout.

## Tools

| Tool | What it does |
|------|--------------|
| `x86_insn` | ISA set, CPUID requirement, privilege, valid modes, flags, notable attributes, and encoding forms with operands. Accepts XED names (`CMOVZ`, `REP_MOVSB`) and common spellings (`cmove`, `je`, `sal`, `ret`, `rep movsb`), and says how it mapped the name. |
| `x86_flags` | Flags read, written, set, cleared, undefined, or loaded from the stack, including count-dependent shift/rotate behaviour. |
| `x86_exceptions` | Exceptions an instruction can raise and under what condition. Every line is tagged with its source (see below). |
| `x86_decode` | Disassemble hex bytes in 16-, 32- or 64-bit mode, annotating each instruction's XED class, ISA set, privilege and flags. It knows that `mov eax, cr0` is the privileged `MOV_CR`. |
| `x86_register` | Bit layout or value decode for RFLAGS, CR0, CR3, CR4, EFER, DR7, XCR0, segment selectors, page-table entries, the #PF error code, and IA32_APIC_BASE. Bits the table doesn't define are reported, not hidden. |
| `x86_msr` | Common architectural MSRs by number or name, decoding the value where a layout is known. |
| `x86_vector` | An exception vector by number or mnemonic: fault, trap or abort, and whether it pushes an error code. |
| `x86_search` | Find instructions by name fragment, ISA set, extension or category (`AES`, `AVX512`, `SYSTEM`). |
| `x86_about` | Data provenance and licenses. |

## Where every answer comes from

| Source | Covers | How it's made |
|---|---|---|
| **Intel XED** | everything about instructions | `tools/build_data.py` runs XED's own generator (`mfile.py just-prep`) and its own reader (`pysrc/read_xed_db.py`) at a pinned commit, and keeps a subset of each record. CI rebuilds it and requires a byte-identical result. |
| **[XED] in `x86_exceptions`** | SIMD/AVX/AVX-512/APX exception classes | XED's `EXCEPTIONS` field. It names the SDM exception-class table, which this tool doesn't reproduce. |
| **[derived]** | general exception rules | Architectural rules applied to XED fields: CPL 0 → #GP(0) at CPL > 0; memory operand → #GP/#SS/#PF/#AC; not LOCKABLE → #UD with LOCK; outside its valid modes → #UD. |
| **[curated]** | instruction-specific facts XED doesn't encode | Short notes written for this project, such as DIV → #DE, CR4.TSD for RDTSC, and EFER.SCE for SYSCALL. |
| **hand-written tables** | registers, MSRs, vectors | Bit positions and names only. |

XED has a few quirks, and the tool reports them rather than hiding them. For example, XED
files `SYSCALL` under the LONGMODE ISA set with the long-mode CPUID bit, while the SYSCALL
feature bit itself is CPUID.80000001H:EDX[11]. Both appear, each with its source.

### Licenses

- **The code** is MIT.
- **The instruction dataset** (`src/x86_ref_mcp/data/xed-insns.json.gz`) is derived from Intel
  XED, Copyright Intel Corporation, under Apache-2.0. The license text ships inside the package
  as `data/LICENSE-XED.txt`, and [NOTICE](NOTICE) describes exactly what was extracted and
  changed.
- **No Intel SDM text is included.** The manual is copyrighted and isn't redistributed here,
  and neither is any site derived from it.
- **uops.info data is not used**, because its XML has no stated license.

## Limits

- **`x86_exceptions` is not the SDM's per-instruction table.** For legacy instructions it
  applies general rules plus a curated list, and it says so on every call.
- **The MSR table covers about 35 common architectural MSRs**, not model-specific ones.
- **Register layouts that depend on CPU features are noted, not modelled.** Examples are
  MAXPHYADDR, PCIDE and 5-level paging.
- **Latency and throughput aren't included.** The open datasets that have them (uops.info)
  aren't licensed for redistribution.

## Tests

```bash
pip install ".[test]" "ruff==0.16.0" "mypy==2.3.0"
ruff check src tests tools && mypy --strict src
pytest tests
```

The tests check real facts against the data:
- ADD writes the six arithmetic flags, and CMOVcc reads flags but writes none.
- SHL leaves OF undefined only when the count is above 1.
- LGDT requires CPL 0 but is valid in every mode, and VADDPS needs CPUID.1:ECX[28].
- `mov eax, cr0` decodes as the CPL0 `MOV_CR`, and CR0 = 0x80000011 decodes to PG, ET and PE.

The over-stdio test also checks that error messages reach the agent.

Rebuild the dataset with `python tools/build_data.py`. It clones XED and mbuild at the pinned
commits.

## License

MIT for the code, Apache-2.0 for the XED-derived dataset. See [NOTICE](NOTICE).
