---
name: build-kcd2-mod
description: Build deterministic KCD2 mod candidates in bounded clean staging after explicit approval, with packaging-profile preservation, parent-diff validation, and reproducibility receipts. Use only when the user asks to create build outputs.
---

# Build KCD2 Mod

Treat a candidate build as a write. Analysis approval is insufficient, and build approval does not
authorize installation.

## Gate and build

1. Read workspace authority and validate the declarative build spec, exact parent identity,
   allowed changes, output root, packaging profile, and hard limits.
2. Derive the exact targets with `build_candidate_approval_targets` or
   `build_candidate_twice_approval_targets`.
3. Obtain separate explicit approval for operation `build_candidate`. Require a current,
   content-bound, one-time approval record accepted by `ApprovalVerifier`; prose acknowledgement
   or a Boolean is not approval.
4. Call `build_candidate_guarded` or `build_candidate_twice_guarded` only with that approval and
   verifier. Build inside bounded clean staging, never in an installed mod or game directory.
5. Validate parent diff, package structure, XML/TBL rules, packaging profile, deterministic hashes,
   and absence of cache/build debris before reporting success.

Return the build receipt and exact artifact hashes. Stop before installation and request a new,
separate install approval if the user later asks to deploy the candidate.
