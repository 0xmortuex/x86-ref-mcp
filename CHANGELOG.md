# Changelog

## 0.1.0 - 2026-10-08

First release.

- Instruction data from Intel XED @ 0bcb6237 (1,987 classes, 10,994 forms), extracted with
  XED's own generator and reader; the build is reproducible byte-for-byte and CI checks it.
- Tools: x86_insn, x86_flags, x86_exceptions, x86_decode, x86_register, x86_msr, x86_vector,
  x86_search, x86_about.
- Exceptions are tagged by source ([XED], [derived], [curated]) and scoped to the forms they
  apply to (e.g. APX-only rules are labelled as such).
- x86_decode maps `mov` to/from CRn/DRn to XED's privileged MOV_CR/MOV_DR, and ignores APX
  forms for bytes that aren't APX-encoded.
