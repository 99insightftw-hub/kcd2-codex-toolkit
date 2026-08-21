---
name: capture-kcd2-native-probes
description: Plan, preflight, validate, and summarize bounded KCD2 native probes using reviewed static evidence, passive KCSE hooks, or the existing x64dbg provider. Use for KCD2 native runtime captures, entry-lock checks, record layouts, correlation/lifetime proof, gameplay-readiness decisions, probe-result validity, or cleanup of a bounded probe session.
---

# Capture KCD2 Native Probes

Keep source, static, runtime, user-confirmed, and causal evidence separate. Prefer the plugin's
read-only tools before proposing a new capture.

## Establish authority and identity

1. Read the canonical workspace instructions and the smallest relevant state capsule.
2. Confirm whether the request is read-only analysis, a staged build, or a separately approved
   live operation. Never treat analysis or build approval as install/runtime approval.
3. Bind reusable native locations to the active module SHA-256 plus RVA. Reject saved RVAs when
   the module identity is unavailable or different.
4. Use reviewed static evidence to establish function boundaries, prototypes, raw entry bytes,
   record-family layouts, and caller/owner constraints. Do not invent any of them.

## Choose the narrowest carrier

- Use passive KCSE hooks for repeated bounded events only after prototype and trampoline safety
  are established.
- Use x64dbg for one-shot register, stack, call-stack, object-lifetime, or correlation proof that
  static analysis and passive events cannot establish.
- Use a hybrid only when a bounded passive event selects one narrow debugger observation.
- Keep incident-specific action IDs, GUIDs, RVAs, paths, and filters in profiles or fixtures.

## Run the gates

1. Call `native_capability_preflight` with the active environment-profile v2 path. Explicit tool
   paths are observations only and cannot make a native route eligible without launch,
   provider/API-connectivity, version/hash, Ghidra/Java, and exact WHGame-profile proof.
2. Call `entry_lock_preflight` against the raw PE and generated header before compilation or
   installation.
3. Call `record_layout_lint` for every family-specific layout used by a filter.
4. Require a proven correlation strategy; same-thread or TLS coincidence is insufficient.
5. Call `probe_playtest_readiness` before asking the user to enter gameplay.
6. After a bounded capture, call `validate_probe_result` and retain its exact validity verdict.

An invalid filter, layout, correlation contract, deployment binding, or completeness check yields
`capture_inconclusive`. It never supports an elimination or `row_not_enumerated` claim.

## Protect runtime handoff

For x64dbg captures, resume and recheck the process after every stop. Hand gameplay back only when
the delayed debugger status explicitly reports debugging and running. For KCSE-only captures,
verify that no debugger remains attached and that BOOT/INSTALL_OK identity is complete.

Keep event families hard-bounded. Record dropped, truncated, malformed, or saturated events. Do
not expose raw runtime pointers in sanitized summaries.

## Close the session

Clear temporary breakpoints and detach, or remove a temporary KCSE probe only after the game is
closed and separate live-write approval exists. Preserve the exact deployment binding at capture
start and close. Report every cleanup action, whether the game is responsive, whether a debugger
is attached or paused, and every claim that remains unproven.

<!-- BEGIN GENERATED PUBLIC TOOLS: API-004 -->

## Generated public tool catalog

- `native_capability_preflight` — `capability_id` (required), `regular_ghidra_gui` (optional), `regular_ghidra_headless` (optional), `current_interpreter` (optional), `isolated_pyghidra_interpreters` (optional), `plugin_interpreter` (optional), `pyghidra_required` (optional), `x64dbg_path` (optional), `kcse_path` (optional), `compiler_paths` (optional), `index_mcp_tools` (optional), `game_binary_paths` (optional), `reviewed_static_evidence` (optional), `environment_profile_path` (optional)

- `entry_lock_preflight` — `manifest_path` (required), `module_path` (required), `generated_header_path` (required)

- `record_layout_lint` — `input_path` (required), `max_diagnostics` (optional)

- `probe_playtest_readiness` — `input_path` (required)

- `validate_probe_result` — `input_path` (required)

<!-- END GENERATED PUBLIC TOOLS: API-004 -->
