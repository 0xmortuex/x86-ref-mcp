import pytest

from x86_ref_mcp import arch


def names(reg, value):
    return [line.split(" ")[0] for line in arch.decode(arch.find_register(reg), value)]


def test_cr0_decode():
    assert names("cr0", 0x80000011) == ["PE", "ET", "PG"]
    assert names("cr0", 0x60000010) == ["ET", "NW", "CD"]  # x86 reset value


def test_rflags_reserved_bit_one_explained():
    out = arch.decode(arch.find_register("eflags"), 0x202)
    assert out[0].startswith("IF (bit 9)")
    assert "bit 1: reserved, always reads 1" in out


def test_multi_bit_fields():
    out = arch.decode(arch.find_register("rflags"), 0x3002)
    assert any(line.startswith("IOPL (bits 13:12) = 3") for line in out)
    sel = arch.decode(arch.find_register("selector"), 0x2B)
    assert sel[0].startswith("RPL (bits 1:0) = 3")
    assert sel[1].startswith("index (bits 15:3) = 5")


def test_efer_and_pte():
    assert names("efer", 0xD01) == ["SCE", "LME", "LMA", "NXE"]
    pte = arch.decode(arch.find_register("pte"), 0x8000000000123003)
    assert pte[0].startswith("P (bit 0)") and pte[1].startswith("R/W (bit 1)")
    assert any("address (bits 51:12) = 0x123000" in line for line in pte)
    assert pte[-1].startswith("XD/NX (bit 63)")


def test_undefined_bits_are_reported_not_hidden():
    out = arch.decode(arch.find_register("cr0"), 1 << 7)
    assert out == ["bit 7: not a defined field in this table (reserved, or a feature not listed)"]


def test_value_range_and_unknown_register():
    with pytest.raises(ValueError, match="does not fit"):
        arch.decode(arch.find_register("selector"), 0x10000)
    with pytest.raises(KeyError, match="no layout for 'cr9'"):
        arch.find_register("cr9")


def test_msr_lookup():
    (m,) = arch.find_msrs("0xC0000080")
    assert m.name == "IA32_EFER" and m.register == "efer"
    assert arch.find_msrs("lstar")[0].number == 0xC0000082
    assert arch.find_msrs("IA32_APIC_BASE")[0].number == 0x1B
    with pytest.raises(KeyError, match="no MSR"):
        arch.find_msrs("0x12345")


def test_vectors():
    assert arch.VECTORS[14][:2] == ("#PF", "page fault")
    assert arch.VECTORS[8][2:] == ("abort", True)
    assert arch.VECTORS[3][2:] == ("trap", False)
