# Public release rules

## Scope

These rules apply to the complete repository and every generated release.

## Required safety action

Before committing or publishing, run the release-safety tests. Keep source, schemas, synthetic fixtures, and generalized documentation only.

Never add KCD2/WHGame binaries, extracted archives or assets, `.i64`/IDA/Ghidra projects, private indexes, decompiled payloads, saves, logs, crash dumps, credentials, personal absolute paths, or analyst/license metadata. A filename or hash is not permission to redistribute its underlying artifact.

Native claims must bind the exact module fingerprint and use module-relative RVAs. A mismatched game build makes prior addresses historical leads only. Index misses under partial coverage are not absence claims.

Build, install, rollback, process control, debugger mutation, and approval consumption are distinct operations. Do not infer authority from the presence of a tool or receipt.

If a safety test or provenance check fails, stop publication and remove or generalize the offending material; do not weaken the check to admit it.
