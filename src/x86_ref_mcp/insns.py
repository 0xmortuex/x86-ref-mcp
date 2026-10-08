"""Instruction lookup over the XED-derived dataset.

XED names instructions by "iclass" (ADD, JZ, CMOVZ, REP_MOVSB, MOV_CR...).
People and disassemblers use other spellings (je, cmove, sal, ret, movabs,
"rep movsb"), so lookups go through `resolve`, which always says how it
mapped the name.
"""

from __future__ import annotations

import functools
import gzip
import json
import re
from dataclasses import dataclass
from importlib import resources
from typing import Any

Form = dict[str, Any]

# Condition-code synonyms -> XED's canonical spelling, for Jcc/CMOVcc/SETcc.
_CC = {"E": "Z", "NE": "NZ", "C": "B", "NAE": "B", "NC": "NB", "AE": "NB", "NA": "BE",
       "A": "NBE", "NGE": "L", "GE": "NL", "NG": "LE", "G": "NLE", "PE": "P", "PO": "NP"}
_ALIASES = {"SAL": "SHL", "RET": "RET_NEAR", "RETN": "RET_NEAR", "RETF": "RET_FAR",
            "LRET": "RET_FAR", "CALL": "CALL_NEAR", "LCALL": "CALL_FAR", "LJMP": "JMP_FAR",
            "MOVABS": "MOV", "INT 3": "INT3", "IRET": "IRET", "XLATB": "XLAT", "WAIT": "FWAIT",
            "INT1": "INT1", "ICEBP": "INT1"}

FLAG_NAMES = ("cf", "pf", "af", "zf", "sf", "tf", "if", "df", "of", "iopl", "nt", "rf", "vm",
              "ac", "vif", "vip", "id")


@functools.lru_cache(maxsize=1)
def dataset() -> dict[str, list[Form]]:
    raw = resources.files("x86_ref_mcp").joinpath("data").joinpath("xed-insns.json.gz").read_bytes()
    data: dict[str, list[Form]] = json.loads(gzip.decompress(raw))
    return data


@functools.lru_cache(maxsize=1)
def provenance() -> dict[str, Any]:
    text = resources.files("x86_ref_mcp").joinpath("data").joinpath("provenance.json").read_text("utf-8")
    prov: dict[str, Any] = json.loads(text)
    return prov


@functools.lru_cache(maxsize=1)
def _names_index() -> dict[str, list[str]]:
    """Lower-case disassembly names XED records (movsb, movsd...) -> iclasses."""
    idx: dict[str, set[str]] = {}
    for iclass, forms in dataset().items():
        for f in forms:
            for n in f["names"]:
                idx.setdefault(n, set()).add(iclass)
    return {k: sorted(v) for k, v in idx.items()}


@dataclass
class Resolution:
    iclasses: list[str]
    note: str | None


def resolve(mnemonic: str) -> Resolution:
    data = dataset()
    raw = " ".join(mnemonic.strip().split())
    if not raw:
        raise ValueError("empty mnemonic")
    key = raw.upper()
    if key in _ALIASES and _ALIASES[key] in data:
        target = _ALIASES[key]
        return Resolution([target], None if target == key else f"{raw!r} is XED's {target}")
    under = key.replace(" ", "_")
    if under in data:
        return Resolution([under], None)
    for prefix in ("CMOV", "SET", "J"):
        if under.startswith(prefix) and _CC.get(under[len(prefix):]):
            target = prefix + _CC[under[len(prefix):]]
            if target in data:
                return Resolution([target], f"{raw!r} is a synonym of {target}")
    named = _names_index().get(raw.lower())
    if named:
        return Resolution(named, f"{raw!r} is how XED disassembles {', '.join(named)}")
    family = sorted(k for k in data if k.startswith(under + "_"))
    if family:
        return Resolution(family, f"{raw!r} covers several XED instruction classes: {', '.join(family)}")
    close = sorted(k for k in data if under in k)[:12]
    hint = f" Similar: {', '.join(close)}" if close else " Try x86_search."
    raise KeyError(f"no x86 instruction {raw!r} in the XED database.{hint}")


def related(iclass: str) -> list[str]:
    """Other classes in the same family (MOV -> MOV_CR, MOV_DR...)."""
    return sorted(k for k in dataset() if k.startswith(iclass + "_"))


# -- flags ---------------------------------------------------------------------

_ACTION = {"tst": "read", "mod": "written", "0": "cleared", "1": "set",
           "u": "undefined", "pop": "loaded from stack", "ah": "loaded from AH"}


@dataclass
class FlagEffect:
    condition: str  # "" or e.g. "count == 1", "count > 1"
    certainty: str  # "always" | "may"
    actions: dict[str, list[str]]  # action -> flag names


def parse_flags(spec: str | None) -> list[FlagEffect]:
    """XED: `MUST [ of-mod cf-mod ]`, `READONLY [ zf-tst ]`, `MAY [ ... ]`,
    `IMM1 MUST [ ... ], IMMx MUST [ ... ]` (shift/rotate count 1 vs other)."""
    if not spec:
        return []
    effects = []
    for part in spec.split(","):
        m = re.match(r"\s*(IMM1|IMM0|IMMx)?\s*(MUST|MAY|READONLY)\s*\[([^\]]*)\]", part)
        if not m:
            raise ValueError(f"unrecognised XED flag spec {part!r}")
        cond = {"IMM1": "count == 1", "IMM0": "count == 0", "IMMx": "count > 1"}.get(m.group(1) or "", "")
        actions: dict[str, list[str]] = {}
        for tok in m.group(3).split():
            flag, _, act = tok.lower().partition("-")
            # A flag can be both tested and modified (e.g. vm-tst vm-mod); keep both.
            actions.setdefault(_ACTION.get(act, act), []).append(flag.upper())
        effects.append(FlagEffect(cond, "may" if m.group(2) == "MAY" else "always", actions))
    return effects


def flag_summary(forms: list[Form]) -> list[str]:
    """Merge flag behaviour across forms; when forms differ, group them."""
    specs: dict[str, list[str]] = {}
    for f in forms:
        specs.setdefault(f["flags"] or "", []).append(f["iform"])
    lines: list[str] = []
    for spec, iforms in specs.items():
        indent = ""
        if len(specs) > 1:
            names = list(dict.fromkeys(iforms))
            shown = ", ".join(names[:3]) + (f" +{len(names) - 3} more" if len(names) > 3 else "")
            lines.append(f"{len(iforms)} form(s) ({shown}):")
            indent = "  "
        effects = parse_flags(spec or None)
        if not effects:
            lines.append(indent + "no flags read or written")
            continue
        for e in effects:
            head = indent + (f"when {e.condition}: " if e.condition else "")
            if e.certainty == "may":
                head += "(conditional - not every execution does this, e.g. a zero count) "
            lines.append(head + "; ".join(f"{act}: {' '.join(fl)}" for act, fl in e.actions.items()))
    return lines


MODES_ALL = ("16-bit", "32-bit", "64-bit")
_RESTRICT = {"16-bit only": {"16-bit"}, "32-bit only": {"32-bit"}, "64-bit only": {"64-bit"},
             "invalid in 64-bit mode": {"16-bit", "32-bit"}}


def valid_modes(forms: list[Form]) -> list[str]:
    """CPU modes in which at least one form of the instruction is valid."""
    ok: set[str] = set()
    for f in forms:
        ok |= _RESTRICT.get(f["mode"], set(MODES_ALL)) if f["mode"] else set(MODES_ALL)
    return [m for m in MODES_ALL if m in ok]


# -- operands ------------------------------------------------------------------

_ACCESS = {"r": "read", "w": "write", "rw": "read/write", "cr": "cond. read", "cw": "cond. write",
           "rcw": "read, cond. write", "crw": "cond. read, write"}


def render_operands(ops: list[str]) -> str:
    explicit: list[str] = []
    implicit: list[str] = []
    for op in ops:
        parts = op.split(":")
        name = parts[0]
        if "=" in name:
            name = name.split("=", 1)[1]
        name = name.replace("XED_REG_", "").replace("()", "")
        access = _ACCESS.get(parts[1], parts[1]) if len(parts) > 1 else ""
        width = next((p for p in parts[2:] if p not in ("SUPP", "IMPL", "EXPL", "ECOND")
                      and not p.startswith(("TXT=", "MULTISOURCE"))), "")
        text = f"{name} ({access}{', ' + width if width else ''})"
        (implicit if ("SUPP" in parts or "IMPL" in parts) else explicit).append(text)
    out = ", ".join(explicit) or "none"
    if implicit:
        out += "; implicit: " + ", ".join(implicit)
    return out


WIDTH_LEGEND = ("widths: b=8 w=16 d=32 q=64 bit; v=operand size (16/32/64); z=16/32; "
                "y=32/64; s=pseudo-descriptor (6 or 10 bytes); ps/pd/ss/sd=packed/scalar single/double")


def search(query: str, limit: int = 40) -> list[tuple[str, Form]]:
    q = query.strip().upper()
    if not q:
        raise ValueError("empty query")
    hits: list[tuple[int, str, Form]] = []
    for iclass, forms in dataset().items():
        f = forms[0]
        hay = {iclass, f["isa_set"], f["extension"], f["category"]}
        if q == iclass:
            score = 0
        elif iclass.startswith(q):
            score = 1
        elif q in hay:
            score = 2
        elif any(q in h for h in hay):
            score = 3
        else:
            continue
        hits.append((score, iclass, f))
    hits.sort(key=lambda h: (h[0], h[1]))
    return [(i, f) for _, i, f in hits[:limit]]
