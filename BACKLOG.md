# Backlog

Real, finishable improvements - pick ONE, ship it end-to-end with tests.

## Features
- [ ] `x86_encode`: assemble a line (keystone or XED's encoder) and show which iform it chose.
- [ ] Operand widths per mode: resolve XED width codes (v/z/y) to concrete sizes for 16/32/64-bit operand size.
- [ ] More [curated] exception facts for system instructions: LTR, LLDT, INVPCID, VMX instructions.
- [ ] More register layouts: segment descriptor (8/16 bytes), IDT gate, TSS, MSR_IA32_PAT decode, MTRRs.
- [ ] `x86_cpuid(leaf, subleaf, reg, value)`: decode a raw CPUID result into feature names (from XED's cpuid table).
- [ ] Chip filter: which instructions a given CPU (XED chip models, e.g. SKYLAKE, ZEN4) supports.

## Quality
- [ ] Map more capstone spellings to XED classes in x86_decode (string ops with operand-size suffixes, `fwait`, AT&T-style names).
- [ ] Track XED releases: a scheduled job that rebuilds data at XED's latest tag and opens a PR if it changes.
