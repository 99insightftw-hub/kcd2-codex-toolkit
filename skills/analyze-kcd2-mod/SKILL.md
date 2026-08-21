---
name: analyze-kcd2-mod
description: Perform bounded read-only KCD2 mod package, provider, winner, scope, route, lifecycle, and boot-evidence analysis without requiring the KCD2 Index plugin. Use for non-mutating inspection and validation before any build or deployment decision.
---

# Analyze KCD2 Mod

Keep this workflow read-only. It requires no write approval and remains usable without the Index
plugin. Use only explicit user-supplied or workspace-governed paths; never discover installed game
or mod roots recursively.

## Inspect the narrowest evidence

1. Read the governing workspace instructions and smallest task-relevant state capsule.
2. Classify provider completeness before making winner or absence claims.
3. Call the direct read-only tools as needed:
   - `provider_inventory_inspect` for bounded provider coverage.
   - `effective_path_resolve` for a qualified exact internal-path winner.
   - `candidate_parent_diff` for declared candidate-versus-parent changes.
   - `candidate_package_inspect` for static package readiness.
   - `compare_variants` for bounded semantic, provider, and runtime differences.
4. Use the bundled runtime's additional read-only library analyzers only when the request requires
   scope, route, lifecycle, packaging-profile, weapon-scope, or latest-boot evidence.
5. Preserve static, runtime, user-confirmed, and causal evidence as separate layers.

Incomplete provider coverage, invalid filters, unknown resolution semantics, or incomplete boot
evidence must remain `capture_inconclusive` or an explicit refusal. Read-only analysis never grants
permission to build, install, refresh, or rollback.

<!-- BEGIN GENERATED PUBLIC TOOLS: API-004 -->

## Generated public tool catalog

- `candidate_parent_diff` — `build_spec_path` (required), `parent_pak_path` (required), `candidate_pak_path` (required), `clean_parent_pak_path` (optional), `expected_clean_parent_sha256` (optional), `max_entries` (optional)

- `candidate_package_inspect` — `build_spec_path` (required), `package_path` (required), `game_build` (required), `whgame_sha256` (optional)

- `provider_inventory_inspect` — `inventory_path` (required)

- `effective_path_resolve` — `request_path` (required)

- `plan_candidate_audit` — `request_path` (required)

- `compare_variants` — `request_path` (required), `max_differences` (optional)

<!-- END GENERATED PUBLIC TOOLS: API-004 -->
