---
name: kcd2-native-research
description: Evidence-driven native analysis for Kingdom Come Deliverance II combat, animation, KCSE, WHGame.dll, Ghidra, PyGhidra, x64dbg, RVAs, object layouts, hooks, crashes, and runtime state transitions. Use for KCD2 reverse engineering, native debugging, version-locked C++ work, or deciding whether data, Lua, Ghidra, or x64dbg is the correct layer.
---

# KCD2 Native Research

Use the user's canonical, version-controlled KCD2 native-research workspace.
Before acting, locate and read its `AGENTS.md`, `CURRENT_STATE.md`, and
`WORKSPACE_RULES.md` completely. Treat that workspace as authoritative over
historical downloads, backups, scratch directories, and quarantine material.

## Establish scope

1. Classify the question as data routing, runtime selection, native ownership,
   crash diagnosis, or implementation.
2. Start read-only unless the user explicitly requests a change.
3. Preserve the boundary that the user performs all gameplay and playtesting.
4. Check the live `WHGame.dll` hash against `CURRENT_STATE.md` before using an
   RVA, prototype, object offset, hook, or debugger breakpoint.
5. Search canonical research and the vanilla path catalog before requesting
   new data.

## Choose the smallest evidence-producing layer

- Use ADB and combat tables for fragments, tags, synchronized pairs, timing,
  procedural layers, and action routing.
- Use item/RPG/AI/XGen sources for identity, conditions, eligibility, and
  behavior-state ownership.
- Use Ghidra for static ownership, xrefs, RTTI, `.pdata` function boundaries,
  decompilation, vtables, and persistent analysis.
- Use PyGhidra or `analyzeHeadless` for repeatable scripted queries and
  exports. Never write to the persistent Ghidra project while its GUI is open.
- Use x64dbg Automate for live identity, call routing, object lifetime,
  registers, stacks, bounded memory reads, and state-transition confirmation.
- Use C++/KCSE only when runtime-object selection or a native hook is proven
  necessary.

Read `research/GHIDRA_ACCESS.md` before Ghidra or PyGhidra work. Read
`research/X64DBG_AUTOMATE_ACCESS.md` before live debugging.

## Evidence discipline

Separate facts from inference. For every native conclusion, record:

- game and `WHGame.dll` fingerprint;
- source type and exact source path;
- module-relative RVA rather than an ASLR-dependent absolute address;
- function boundary source, callers/xrefs, and relevant decompilation;
- runtime confirmation, if any;
- confidence and unresolved alternatives;
- artifact or log path that makes the result reproducible.

Add reusable conclusions to
`research/evidence_registry/native_xgen_evidence.csv`. Use one row per atomic
claim and run its validator before committing.

Do not promote a guessed function signature, vtable slot, member offset, or
state transition to confirmed status from one suggestive decompilation alone.
Require multiple static references or one static result plus targeted runtime
evidence.

## Safe dynamic workflow

1. Let the user launch and load KCD2.
2. Attach to the existing process; do not automate gameplay.
3. Recalculate addresses from the live module base plus validated RVA.
4. Set the smallest useful breakpoint set.
5. Synchronize resume, pause, and reads with debugger events.
6. Capture registers, stack, thread, nearby disassembly, and bounded object
   memory.
7. Clear temporary breakpoints and detach cleanly.

Default to observation. Treat memory/register writes, assembly, allocation,
thread manipulation, and runtime patching as separate scoped experiments with
original-byte validation and a restoration path.

## Handoff

Lead with the proven result, its confidence, and what it changes. If
playtesting is required, provide one compact run containing all compatible
observations: save/equipment/enemy prerequisites, exact user inputs, expected
signals, and when to pause or close.
