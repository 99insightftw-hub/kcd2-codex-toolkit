---
name: rollback-kcd2-mod
description: Restore the exact KCD2 mod folder and order bytes from one verified install receipt after separate explicit approval. Use when reverting a guarded candidate installation.
---

# Rollback KCD2 Mod

Rollback is a live write. Install approval does not authorize rollback, and a receipt path alone is
not authority.

## Gate and restore

1. Require the completed install receipt and its exact installed tree, backup tree, order bytes,
   mods root, transaction root, target identity, and closed-game confirmation.
2. Derive exact targets with `rollback_install_approval_targets` immediately before approval.
3. Obtain separate explicit approval for operation `rollback`. Require a current, content-bound,
   one-time approval record accepted by `ApprovalVerifier`; prose acknowledgement or a Boolean is
   not approval.
4. Recheck receipt identity, installed-target drift, mod-order drift, target containment, and
   game-closed state.
5. Call `rollback_install_atomic` with the exact approval and verifier. Never reconstruct rollback
   intent manually or restore from an unbound backup.
6. Verify exact prior folder and `mod_order.txt` bytes and preserve the rollback receipt.

If identity or drift validation fails, stop without mutation and report the unresolved gate.
