"""Build x86-ref-mcp's instruction dataset from Intel XED.

XED (https://github.com/intelxed/xed, Apache-2.0) keeps its ISA in
`datafiles/`, spread over many patch files. Its own generator merges them
(`mfile.py just-prep` writes obj/dgen/all-*.txt) and its own reader
(`pysrc/read_xed_db.py`) parses the result. This script runs both at pinned
commits and writes a compact, attributed dataset into the package:

    src/x86_ref_mcp/data/xed-insns.json.gz
    src/x86_ref_mcp/data/provenance.json

Usage:
    python tools/build_data.py                 # clone XED + mbuild at the pinned commits
    python tools/build_data.py --xed DIR       # use an existing XED checkout
                                               # (mbuild must be its sibling)
"""

from __future__ import annotations

import argparse
import datetime
import gzip
import json
import os
import subprocess
import sys
import tempfile

XED_REPO = "https://github.com/intelxed/xed"
MBUILD_REPO = "https://github.com/intelxed/mbuild"
XED_COMMIT = "0bcb6237345c5066726dcc08b3d87928df3b5b26"
MBUILD_COMMIT = "1b437e409221a2b5703b4d8896baa20d43e4ba1a"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "src", "x86_ref_mcp", "data")

MODES = {0: "16-bit only", 1: "32-bit only", 2: "64-bit only", "not64": "invalid in 64-bit mode"}


def run(cmd: list[str], cwd: str) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, cwd=cwd, check=True)


def clone(url: str, commit: str, dest: str) -> None:
    run(["git", "init", "-q", dest], cwd=os.path.dirname(dest))
    run(["git", "fetch", "-q", "--depth", "1", url, commit], cwd=dest)
    run(["git", "checkout", "-q", "FETCH_HEAD"], cwd=dest)


def head(repo: str) -> str:
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True,
                          capture_output=True, text=True).stdout.strip()


def prep(xed: str) -> str:
    # The prep step only runs XED's Python generator; no C compiler is
    # invoked. Naming a compiler stops mbuild probing for MSVC on Windows.
    run([sys.executable, "mfile.py", "just-prep", "--compiler=clang"], cwd=xed)
    return os.path.join(xed, "obj", "dgen")


def cpuid_strings(groups: list[object]) -> list[list[str]]:
    """XED groups: any one group satisfied enables the ISA set (OR); every
    record within a group must hold (AND). Returned as [[record, ...], ...]."""
    out: list[list[str]] = []
    for group in groups:
        recs = []
        for r in group.records:  # type: ignore[attr-defined]
            bits = r.bit_start if r.bit_start == r.bit_end or not r.bit_end else f"{r.bit_end}:{r.bit_start}"
            value = f"={r.value}" if r.value not in ("", "1") else ""
            recs.append(f"CPUID.(EAX={r.leaf.upper()}H,ECX={r.s_leaf}):{r.reg.upper()}[{bits}]{value} ({r.fname})")
        if recs:
            out.append(recs)
    return out


def extract(xed: str, mbuild: str, dgen: str) -> dict[str, list[dict[str, object]]]:
    # XED's reader imports mbuild, which it otherwise looks for by walking up
    # from the current directory.
    sys.path[:0] = [os.path.join(xed, "pysrc"), mbuild]
    import read_xed_db  # type: ignore[import-not-found]

    def p(name: str) -> str:
        return os.path.join(dgen, name)

    db = read_xed_db.xed_reader_t(
        p("all-state.txt"), p("all-dec-instructions.txt"), p("all-widths.txt"),
        p("all-extra-widths.txt"), p("all-element-types.txt"), p("all-cpuid.txt"),
        p("all-map-descriptions.txt"),
    )
    by_iclass: dict[str, list[dict[str, object]]] = {}
    for r in db.recs:
        form: dict[str, object] = {
            "iform": r.iform,
            "operands": r.operands.split() if r.operands else [],
            "isa_set": r.isa_set,
            "extension": r.extension,
            "category": r.category,
            "cpl": int(r.cpl),
            "attributes": sorted(r.attributes.split()) if r.attributes else [],
            "flags": getattr(r, "flags", None),
            "exceptions": (getattr(r, "exceptions", None) or "").strip() or None,
            "cpuid": cpuid_strings(r.cpuid_groups),
            "mode": MODES.get(r.mode_restriction),
            "undocumented": bool(r.undocumented),
            "names": sorted({n.lower() for n in (getattr(r, "disasm", None),
                                                  getattr(r, "disasm_intel", None)) if n}),
        }
        by_iclass.setdefault(r.iclass, []).append(form)
    return by_iclass


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--xed", help="existing XED checkout (mbuild must be its sibling)")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        if args.xed:
            xed = os.path.abspath(args.xed)
            mbuild = os.path.join(os.path.dirname(xed), "mbuild")
        else:
            xed, mbuild = os.path.join(tmp, "xed"), os.path.join(tmp, "mbuild")
            clone(XED_REPO, XED_COMMIT, xed)
            clone(MBUILD_REPO, MBUILD_COMMIT, mbuild)
        data = extract(xed, mbuild, prep(xed))
        provenance = {
            "source": XED_REPO,
            "xed_commit": head(xed),
            "mbuild_commit": head(mbuild),
            "license": "Apache-2.0 (XED datafiles); derived dataset, see NOTICE",
            "built": datetime.date.today().isoformat(),
            "iclasses": len(data),
            "forms": sum(len(v) for v in data.values()),
        }

    os.makedirs(OUT_DIR, exist_ok=True)
    blob = json.dumps(data, separators=(",", ":"), sort_keys=True).encode()
    # mtime=0 keeps the gzip byte-identical across rebuilds of the same data.
    with open(os.path.join(OUT_DIR, "xed-insns.json.gz"), "wb") as fh:
        with gzip.GzipFile(fileobj=fh, mode="wb", mtime=0) as gz:
            gz.write(blob)
    with open(os.path.join(OUT_DIR, "provenance.json"), "w", encoding="utf-8") as fh:
        json.dump(provenance, fh, indent=2)
        fh.write("\n")
    print(f"wrote {provenance['iclasses']} instruction classes, {provenance['forms']} forms")
    return 0


if __name__ == "__main__":
    sys.exit(main())
