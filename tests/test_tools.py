"""The MCP tools, called directly."""

import pytest

from x86_ref_mcp import server as S


def test_insn_reports_alias_cpuid_privilege():
    out = S.x86_insn("cmove", max_forms=2)
    assert out.startswith("('cmove' is a synonym of CMOVZ)")
    assert "CPUID.(EAX=1H,ECX=0):EDX[15] (CMOV)" in out
    assert "privilege: any CPL" in out
    lgdt = S.x86_insn("lgdt")
    assert "privilege: CPL 0 only" in lgdt
    assert "valid in: 16-bit, 32-bit, 64-bit mode" in lgdt


def test_insn_curated_notes():
    out = S.x86_insn("rdtsc")
    assert "CPUID.(EAX=1H):EDX[4] (TSC)" in out and "CR4.TSD" in out
    assert "EDX[11]" in S.x86_insn("syscall")


def test_flags_tool():
    out = S.x86_flags("shl")
    assert "when count == 1: written: OF SF ZF PF CF; undefined: AF" in out
    assert "when count > 1: undefined: OF AF" in out


def test_exceptions_are_sourced():
    div = S.x86_exceptions("div")
    assert "#DE     [curated]" in div
    lgdt = S.x86_exceptions("lgdt")
    assert "#GP(0)  [derived] executed at CPL > 0" in lgdt
    assert "#AC" not in lgdt  # alignment checks only happen at CPL 3
    assert "executed outside" not in lgdt  # valid in every mode across its forms
    assert "[XED] SIMD exception class avx-type-2" in S.x86_exceptions("vaddps")
    # ADD's memory-destination forms are lockable, its register forms are not.
    assert "LOCK prefix (non-lockable forms" in S.x86_exceptions("add")
    mov = S.x86_exceptions("mov")
    assert "used with a LOCK prefix (any form" in mov
    assert "Not exhaustive" in mov


def test_decode_annotates():
    out = S.x86_decode("48 01 d8 f0 48 0f c1 07 0f 0b cc", 64).splitlines()
    assert out[0].endswith("add rax, rbx") and "writes AF CF OF PF SF ZF" in out[1]
    assert "lock xadd" in out[2] and out[3].strip().startswith("XADD")
    assert out[4].endswith("ud2") and "INT3" in out[7]


def test_decode_modes_and_errors():
    assert "mov ax, 0x1234" in S.x86_decode("b8 34 12", 16)
    assert "stopped at byte 1" in S.x86_decode("90 ff ff", 64)
    with pytest.raises(ValueError, match="mode must be"):
        S.x86_decode("90", 8)
    with pytest.raises(ValueError, match="not a hex"):
        S.x86_decode("zz", 64)


def test_register_and_msr_tools():
    out = S.x86_register("cr0", "0x80000011")
    assert "PE (bit 0)" in out and "PG (bit 31)" in out
    assert "TSD" in S.x86_register("cr4")
    msr = S.x86_msr("0xc0000080", "0xd01")
    assert "IA32_EFER" in msr and "LMA (bit 10)" in msr


def test_vector_tool():
    assert S.x86_vector("#PF") == "vector 14 (0x0e) #PF: page fault - fault; pushes an error code"
    assert S.x86_vector("0x8").endswith("abort; pushes an error code")
    assert "not a CPU exception" in S.x86_vector("0x80")
    with pytest.raises(KeyError):
        S.x86_vector("#XX")


def test_about_names_xed_and_license():
    out = S.x86_about()
    assert "Apache-2.0" in out and "0bcb6237345c" in out and "No Intel SDM text" in out


def test_decode_control_register_moves_are_privileged():
    """capstone says `mov` for MOV to/from CRn/DRn; XED's classes for those are
    MOV_CR/MOV_DR and need CPL0. A plain MOV lookup would say "any CPL"."""
    out = S.x86_decode("0f 20 c0 0f 22 c0 0f 21 f8 8e d8", 32).splitlines()
    assert out[1].strip() == "MOV_CR | I86 | CPL0"
    assert out[3].strip() == "MOV_CR | I86 | CPL0"
    assert out[5].strip() == "MOV_DR | I86 | CPL0"
    assert out[7].strip() == "MOV | I86 | any CPL"  # segment register load


def test_decode_ignores_apx_forms_for_legacy_bytes():
    out = S.x86_decode("0d 01 00 00 80", 32).splitlines()
    assert "| I86 |" in out[1] and "APX" not in out[1]


def test_exception_rules_are_scoped_to_the_forms_they_cover():
    div = S.x86_exceptions("div")
    apx_class = next(ln for ln in div.splitlines() if "APX-EVEX-INT" in ln)
    assert "(only forms in ISA set" in apx_class and "APX" in apx_class.split("(only")[1]
    cpuid = next(ln for ln in div.splitlines() if "CPUID feature" in ln)
    assert "(only forms in ISA set" in cpuid
    vaddps = next(ln for ln in S.x86_exceptions("vaddps").splitlines() if "CPUID feature" in ln)
    assert "(only" not in vaddps  # every VADDPS form needs AVX or AVX-512
