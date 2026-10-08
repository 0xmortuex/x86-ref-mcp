"""Facts about real instructions, checked against the XED-derived dataset."""

import pytest

from x86_ref_mcp import insns


def _effects(mnemonic):
    res = insns.resolve(mnemonic)
    return [e for c in res.iclasses for f in insns.dataset()[c] for e in insns.parse_flags(f["flags"])]


def _legacy(iclass):
    """Forms without APX encodings - the classic instruction."""
    return [f for f in insns.dataset()[iclass] if not f["isa_set"].startswith("APX")]


def test_dataset_size_and_provenance():
    data = insns.dataset()
    assert len(data) > 1500
    p = insns.provenance()
    assert p["xed_commit"].startswith("0bcb6237")
    assert p["iclasses"] == len(data)


def test_add_writes_the_six_arithmetic_flags():
    f = _legacy("ADD")[0]
    (e,) = insns.parse_flags(f["flags"])
    assert e.certainty == "always"
    assert sorted(e.actions["written"]) == ["AF", "CF", "OF", "PF", "SF", "ZF"]
    assert "read" not in e.actions


def test_cmovcc_reads_flags_writes_none():
    for f in _legacy("CMOVZ"):
        (e,) = insns.parse_flags(f["flags"])
        assert e.actions == {"read": ["ZF"]}


def test_shift_flags_depend_on_count():
    f = next(x for x in _legacy("SHL") if "IMMb" in x["iform"])
    effects = {e.condition: e for e in insns.parse_flags(f["flags"])}
    assert "OF" in effects["count == 1"].actions["written"]
    assert "OF" in effects["count > 1"].actions["undefined"]


def test_rep_movsb_reads_df():
    (e,) = insns.parse_flags(insns.dataset()["REP_MOVSB"][0]["flags"])
    assert e.actions["read"] == ["DF"]


def test_div_leaves_flags_undefined():
    (e,) = insns.parse_flags(_legacy("DIV")[0]["flags"])
    assert sorted(e.actions["undefined"]) == ["AF", "CF", "OF", "PF", "SF", "ZF"]


def test_privileged_instructions_are_cpl0():
    for name in ("LGDT", "LIDT", "HLT", "WRMSR", "RDMSR", "INVLPG", "MOV_CR"):
        assert all(f["cpl"] == 0 for f in insns.dataset()[name]), name
    assert all(f["cpl"] == 3 for f in insns.dataset()["CPUID"])


def test_cpuid_requirements():
    assert insns.dataset()["CMOVZ"][0]["cpuid"] == [["CPUID.(EAX=1H,ECX=0):EDX[15] (CMOV)"]]
    vaddps = [f for f in insns.dataset()["VADDPS"] if f["isa_set"] == "AVX"][0]
    assert vaddps["cpuid"] == [["CPUID.(EAX=1H,ECX=0):ECX[28] (AVX)"]]
    assert vaddps["exceptions"] == "avx-type-2"
    assert insns.dataset()["RDTSC"][0]["isa_set"] == "PENTIUMREAL"


def test_mode_restrictions():
    assert insns.valid_modes(insns.dataset()["SYSCALL"]) == ["64-bit"]
    assert insns.valid_modes(insns.dataset()["LGDT"]) == ["16-bit", "32-bit", "64-bit"]
    assert "64-bit" not in insns.valid_modes(insns.dataset()["AAA"])


@pytest.mark.parametrize("given, expected", [
    ("je", ["JZ"]), ("JNE", ["JNZ"]), ("cmove", ["CMOVZ"]), ("setnae", ["SETB"]),
    ("sal", ["SHL"]), ("ret", ["RET_NEAR"]), ("movabs", ["MOV"]), ("rep movsb", ["REP_MOVSB"]),
    ("add", ["ADD"]), ("int 3", ["INT3"]),
])
def test_resolve_aliases(given, expected):
    assert insns.resolve(given).iclasses == expected


def test_resolve_family_and_errors():
    assert "MOV_CR" in insns.related("MOV")
    with pytest.raises(KeyError, match="no x86 instruction 'frobnicate'"):
        insns.resolve("frobnicate")
    with pytest.raises(ValueError):
        insns.resolve("  ")


def test_render_operands_separates_implicit():
    f = insns.dataset()["LGDT"][0]
    assert insns.render_operands(f["operands"]) == "MEM0 (read, s64); implicit: GDTR (write)"


def test_search():
    names = [n for n, _ in insns.search("AES", 50)]
    assert "AESENC" in names
    assert insns.search("AESENC", 5)[0][0] == "AESENC"


def test_unknown_flag_spec_is_an_error():
    with pytest.raises(ValueError, match="unrecognised"):
        insns.parse_flags("SOMETIMES [ cf-mod ]")
