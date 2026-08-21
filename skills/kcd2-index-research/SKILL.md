---
name: kcd2-index-research
description: Read-only research over the private KCD2 fast source, semantic XGEN, adjacent UI/GFx, and generic resolution/provenance indexes. Use for Kingdom Come Deliverance II identity and name resolution, source lookup, GUID/WUID discovery, XGEN behaviors and traces, UI/GFx/DDS semantic evidence, active-mod PAK reads, mod inspection or validation, index freshness, and bounded support reports without recursive filesystem scans.
---

# KCD2 Index Research

Use the bundled KCD2 tools directly. Do not ask the user to type CLI or
PowerShell commands.

## Required sequence

1. Call `kcd2_index_status` first.
2. Use `kcd2_source_search` before filesystem search.
3. Read selected evidence with `kcd2_source_read` or `kcd2_archive_read`.
4. Use `kcd2_xgen_search` and `kcd2_xgen_trace` for semantic XGEN questions.
5. Use `kcd2_ui_search`, `kcd2_ui_inspect`, and `kcd2_ui_trace` for UI semantics;
   use the GFx/DDS tools for indexed structure and metadata only.
6. Use `kcd2_resolve` before domain-specific searching when a public, localized,
   internal, technical, alias, GUID, WUID, table-key, role, occupation, or runtime
   name must be mapped to a canonical identity. Inspect the selected identity and
   verify important source spans through the exact read route.
7. State whether evidence is source text, semantic index data, inference, or
   runtime proof.

If coverage is partial or unresolved, never claim absence. Preserve exact path
casing and the lowercase retail `mods` root. Never edit installed content,
either database, `mod_order.txt`, saves, retail KCD2, or KCD2Mod.

Use targeted PowerShell only when a requested binary format is unsupported and
exact raw verification is necessary. Never begin with a broad recursive scan.

## Tool selection

- `kcd2_index_status`: readiness, freshness, exclusions, hashes, and coverage.
- `kcd2_source_search`: raw XML, Lua, HTML, ADB text, paths, identifiers, and
  active-mod entries.
- `kcd2_source_read`: exact verified evidence from a search result.
- `kcd2_archive_read`: one exact indexed archive entry.
- `kcd2_inspect_mod`: manifest, archive layout, compression, load order,
  conflicts, and overrides.
- `kcd2_validate_mod`: machine diagnostics and plain package validity.
- `kcd2_xgen_search`: semantic trees, nodes, smart entities, symbols,
  fragments, paths, GUIDs, and WUIDs.
- `kcd2_xgen_trace`: bounded upstream/downstream semantic references.
- `kcd2_ui_status` / `kcd2_ui_coverage`: adjacent candidate identity and coverage.
- `kcd2_ui_search` / `kcd2_ui_inspect` / `kcd2_ui_trace`: bounded semantic UI evidence.
- `kcd2_ui_conflicts`: active-mod UI/GFx override conflicts recorded by the candidate.
- `kcd2_gfx_inspect` / `kcd2_gfx_diff`: indexed GFx structure and diagnostics, never movie bytes.
- `kcd2_texture_inspect`: DDS header metadata only, never decoded or embedded texture payloads.
- `kcd2_query`: bounded generic queries across names, identifiers, paths, symbols, and records.
- `kcd2_resolve`: ranked generic candidates with explainable confidence and serious alternatives.
- `kcd2_trace`: bounded direct and inferred provenance edges.
- `kcd2_read`: exact bounded line, record, node, symbol, JSON-pointer, GFx-offset, DDS-header, or archive-entry evidence.
- `kcd2_coverage`: separate catalog, parser, and query-completeness coverage.
- `kcd2_export_evidence`: bounded five-file evidence-directory export without ZIPs or proprietary payloads.
- `kcd2_export_report`: selected, sanitized Markdown and JSON evidence only.

Treat a source hit as discovery, not gameplay proof. Verify exact text before
concluding. Treat a semantic link as indexed structure, not proof of runtime
execution. Resolution candidates are indexed identity evidence, not proof that a
dynamic runtime entity exists in a particular save or session. Prefer persistent
identities for stable authoring references and report dynamic or mixed lifetime
classification explicitly.

## Examples

Find a joined-animation definition:

1. Call `kcd2_index_status`.
2. Call `kcd2_source_search` with query `JoinedAnimationAction`, extensions
   `xml,lua,html`, and a bounded limit.
3. Read the highest-value file ID with `kcd2_source_read`, passing a bounded
   line range around the returned match line.

Trace `so_crime_extraGuards`:

1. Search it with `kcd2_xgen_search`.
2. Trace the best exact semantic subject with `kcd2_xgen_trace`, direction
   `both`, bounded depth, and bounded records.
3. Verify important source paths using source search/read.

Inspect `factions_authority`:

1. Search source text for the exact name.
2. Search the semantic index for the symbol or path.
3. Separate table/source evidence from XGEN references and runtime inference.

Read an active-mod PAK entry:

1. Search with `active_mods_only: true`.
2. Pass the returned indexed file ID to `kcd2_archive_read`.
3. Confirm the returned computed SHA-256 evidence and stale state.

Find a GUID:

1. Pass the exact GUID to `kcd2_source_search`.
2. Use `kcd2_xgen_search` when semantic ownership is relevant.
3. Read only the selected source identity.

Check freshness by calling `kcd2_index_status`; do not run deep verification or
an index update automatically.
