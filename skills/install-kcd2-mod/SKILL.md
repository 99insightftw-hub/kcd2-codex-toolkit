---
name: install-kcd2-mod
description: Install one validated KCD2 candidate through the atomic deployment gate after separate explicit approval. Use for exact-target installation only after package, conflict, game-closed, identity, and fresh-snapshot gates pass.
---

# Install KCD2 Mod

Installation is a live write. Never infer it from analysis or build approval, and never combine it
with rollback authority.

## Gate and install

1. Require the exact built candidate, registry record, deployment node, provider/conflict report,
   mods root, transaction root, fresh active snapshot, closed-game confirmation, and the accepted
   hash-bound build-attestation bundle. The bundle must identify the guarded build, parent diff,
   package validation, XML/TBL validation, and packaging-profile receipts.
2. Derive exact targets with `plan_install_candidate_approval_targets` immediately before approval.
3. Obtain separate explicit approval for operation `install_candidate`. Require a current,
   content-bound, one-time approval record accepted by `ApprovalVerifier`; prose acknowledgement
   or a Boolean is not approval.
4. Recheck hashes, target paths, provider state, game-closed state, snapshot freshness, and every
   build-attestation receipt hash. Preserve the strongest accepted XML/TBL result; never replace an
   accepted `CLEAR` result with a newly constructed `NOT_APPLICABLE` package report.
5. Call `install_candidate_atomic` with the exact approval and verifier. Do not directly copy a mod
   folder or edit `mod_order.txt` outside the atomic transaction.
6. Verify the installed tree, exact single load-order entry, receipt hashes, accepted build-
   attestation bundle digest, and latest complete boot evidence without promoting static evidence
   into runtime proof.

Return the install receipt and rollback unit. Any later rollback needs its own separate approval.
