# Feature: HSM Member Re-entry — a retired pool device rejoins after a reset and a fresh `provision`

> Status: **spec, operator decisions recorded 2026-11-09, awaiting go-ahead to implement** (T478, S116). Nothing here is
> implemented. Written 2026-11-09 against `95455565`. Extends
> [HSM Pool HA](hsm-pool-ha.md) (S114), whose rules apply unchanged unless a
> section below says otherwise and why. Touches the seal record (a persisted
> format) and pool membership semantics: AGENTS.md §7 and L4 apply (review the
> spec first; `make test-release` before merge).

## Summary

A YubiHSM 2 provisioned before the device-log drain has a `bv-admin` that
cannot delegate `get-log-entries`, and a key's capabilities cannot be changed
in place (`docs/hsm.md`, "Give an existing pool the drain's bv-admin"). The
only way to upgrade a device is to reset it and run `provision` again. Today
that device can never rejoin its pool, so upgrading a two-device pool needs
**two spare devices**.

This feature lets a **retired** member's physical device, after a reset and a
fresh `provision`, rejoin the same pool under the same serial through an
explicit, sudo-gated, audited ceremony (`member reenter`). The reset original
is treated as a **new incarnation** of the member: attested again through the
pinned Yubico chain, its new keys pinned, and nothing of the old incarnation
(wrap copies, node credentials, attested keys, fingerprints) trusted for it.
The upgrade then needs **no spare device**: one member at a time, the pool
unseals on the other throughout.

## What blocks it today (evidence)

| Fact | Where |
|---|---|
| A member is keyed by `HsmId` = `<backend>:<serial>`; the key is the device's serial and nothing else | `crates/bv-core/src/hsm/blob.rs:87-111`, `crates/bv-core/src/seal/hsm/record.rs:99-146` (`members: BTreeMap<HsmId, HsmMember>`) |
| `member add` refuses any `hsm_id` already in the record, retired included | `crates/bv-core/src/seal/hsm/pool_admin.rs:909-914` |
| `member add` also refuses a duplicate *name* | `pool_admin.rs:905-907` |
| A retired member counts against nothing: only non-retired members are counted against the two-device cap | `pool_admin.rs:917-927` |
| Retire sets `state = Retired` and nothing else; the entry is never removed, and `revoke_node` skips retired members | `pool_admin.rs:1090-1093`, `pool_admin.rs:813-815` |
| Repair removes a retired member's copies from every set (never a set's last copy) | `crates/bv-core/src/hsm/repair.rs:40-53`, `pool_admin.rs:1184-1185` |
| Retiring an *active* member needs another active member, `min_wrap_copies` of them, a copy of every set on one of them, and (pool of one) a recovery key or the acknowledgement | `pool_admin.rs:1043-1087`, `crates/bv-core/src/seal/hsm.rs:568-585` |
| Blob copies, node enrollments (`auth_keys`, `signatures`), credential deliveries and promotion transcripts are all keyed by `HsmId`, so a second life of the same serial would collide with the first | `crates/bv-core/src/hsm/blobset.rs`, `hsm/ceremony.rs:178-193`, `hsm/node_creds.rs:93-103`, `hsm/ceremony.rs:363-404` |

## Identity: same device or a different one

A reset YubiHSM 2 keeps its **serial** and its factory attestation key, and
loses every object BastionVault created. So "same device" is true of the
hardware and false of everything the record trusts. The record therefore
tracks an **incarnation** of a member, not just its serial.

**What distinguishes incarnations.** Each incarnation has its own three
attested public keys (`bv-identity`, `bv-authz`, `bv-seed-ecdh`), generated on
the device at `provision`, non-exportable, and bound to the serial by the
Yubico attestation (`hsm/ceremony.rs:119-166`). A reset device that is
provisioned again generates **new** keys; a device that was *not* reset can
only present the **same** keys (`provision` refuses a device that is not in
factory state unless `--adopt`, and `--adopt` keeps the existing keys). So the
public keys *are* the incarnation, and comparing them is the proof that a reset
happened.

**Decision: supersede in place, keep the old incarnation as history.**

| Option | What it is | Verdict |
|---|---|---|
| A. Reuse the retired entry | Flip `state` back to `joining`, overwrite the keys | **Rejected.** The old incarnation's keys, fingerprints and pending revocations vanish from the record, so a retired-because-compromised device is indistinguishable from a new one and the replay check has nothing to compare against. |
| B. A second record under a new key (`serial#2`) | A new map entry | **Rejected.** `HsmId` is `<backend>:<serial>`, charset-checked, equal to what the device reports (`open_admin_sessions` refuses a session whose `hsm_id` differs, `pool_admin.rs:121-125`). Every consumer (blob AAD, set copies, enrollments, deliveries, node credential files, metrics labels) keys by it. Changing it ripples through all of them and every persisted format. |
| **C. Supersede in place** | Same `HsmId` key, the member gets `incarnation = n+1` and the superseded one moves to a `previous` list; an append-only tombstone is also written outside the record | **Chosen.** One `HsmId` per device, so nothing downstream changes key; the old incarnation stays auditable and checkable. |

**What the record gains** (all optional, read-old/write-new, **no version bump**):

```text
HsmMember {
  ... existing fields ...
  incarnation: u32            // serde(default = 1); 1 for every record written so far
  retire_reason: Option<RetireReason>   // serde(default); None for every record written so far
  previous: Vec<SupersededIncarnation>  // serde(default, skip_serializing_if = empty)
}
SupersededIncarnation {
  incarnation: u32, name: String,
  identity_pub, authz_pub, seed_ecdh_pub, attestation_fps,
  unapplied_revocations: Vec<String>,   // the old pending_revocations
  retired_with: Option<RetireReason>, superseded_at: u64, superseded_by: String,
}
RetireReason = replaced | lost | compromised   // kebab-case
```

An append-only tombstone is written **before** the record, outside it, like the
promotion transcripts (`core/hsm/promotions/…`, `hsm/ceremony.rs:28`,
`:400-404`): `core/hsm/incarnations/<hsm_id with ':'→'_'>-<n>` holding the
superseded incarnation's keys and fingerprints. It is idempotent (the key
embeds `n`), so a crash between the tombstone and the record write is retried
safely.

### Persisted-format rules (AGENTS.md §7)

| Concern | Position |
|---|---|
| Old record, new build | `incarnation` defaults to 1, `retire_reason` to `None`, `previous` to empty. `HsmMember` has no `deny_unknown_fields`, so nothing else changes. Covered by a fixture captured from the current code (see Tests). |
| New record, old build | Unknown fields are ignored; the re-entered member is an ordinary member with its new keys, so the old build **unseals normally**. Its `member retire` / `repair` rewrite the record without `previous`; the history is then lost from the record but **survives in the tombstones**, which an old build never touches. The replay check reads both, so the guard holds. |
| Rollback surprise | None for unseal. Unlike `rotate-epoch` (a rolled-back build would use the wrong wrap-key ids and fail to unseal, `hsm-pool-ha.md` § Persisted formats), a rolled-back build only loses *record* history. The docs say so; no "do not roll back" rule is needed. |
| Struct-literal sites | `HsmMember` is built in `pool_admin.rs:972`, `recovery_ceremony.rs:353`, `seal/hsm.rs:898` and `:1687`; all get the new fields. |

## Security

**R1. Explicit ceremony, never implicit.** `member add` keeps refusing a
retired id, with a message that names `member reenter`. `member reenter`
refuses an id that is not in the record, not `retired`, or retired without a
recorded `retire_reason` (Decision 4). It is
sudo-gated like every `hsm/members/*` route (`system/mod.rs:1696`, root paths
`hsm/members/*`), needs the device's `bv-admin` credential (as `add` does,
`pool_admin.rs:929`), and raises a distinct audit event, `hsm.member_reentered`
(a new `PoolEventKind`, `hsm/pool.rs:73-108`), carrying the old and new
fingerprints, the incarnations and the actor.

**R2. Fresh attestation through the pinned chain.** Re-entry runs the same
`verify_member` as `add` (`hsm/ceremony.rs:119-166`): the three attestations
verify against the operator's pinned Yubico trust file
(`attestation_roots_file`, `hsm/attestation.rs`), serial, label and object id
match, every key is non-exportable, the key on the device is the attested
key, `bv-identity` answers a fresh challenge in the same session, and the
layout is exact. Nothing from the old incarnation is consulted to *accept* the
device.

**R3. The old bundle can never be replayed.** After `verify_member`, re-entry
requires that the new `identity_pub`, `authz_pub` and `seed_ecdh_pub` and every
attestation fingerprint differ from **every** recorded incarnation (current
retired entry, `previous`, tombstones). A device that was not reset presents
the same keys and is refused with a message saying so. This is the replay
defence; it costs one comparison.

**R4. Nothing of the old incarnation is trusted for the new one.**

- *Wrap copies.* `copy_for(hsm_id)` would otherwise report a stale copy as
  held (`repair.rs:41`), so a set would look replicated onto a device that
  cannot open it. Re-entry **refuses while any set (the KEK or a custody key)
  still holds a copy for that `hsm_id`** ("run `repair --run` first"). It scans
  the custody store with the unsealed barrier, as retire does
  (`pool_admin.rs:1065-1075`), so it needs an unsealed node. The blob AAD also
  binds `authz_fp` (`blob.rs:184-193`), so a stale blob could not authenticate
  against the new `bv-authz` even if it slipped through; the precondition makes
  that a second line of defence rather than the first.
- *Node credentials.* Before the new credentials are created, the old
  incarnation's entries are removed for **every** enrollment, revoked ones
  included: `auth_keys[hsm_id]`, `signatures[hsm_id]`
  (`hsm/ceremony.rs:184-190`) and `credentials[hsm_id]` in every pending
  delivery (`hsm/node_creds.rs`). Then the existing loop
  (`pool_admin.rs:954-971`) creates a fresh `bv-node-<id>` key per non-revoked
  node on the new device, seals it to the node's transport key and has the new
  `bv-identity` sign the enrollment. A node's store `merge`s by `hsm_id`
  (`node_creds.rs:286-312`), so pickup replaces the old credential (tested).
- *Fingerprints and keys.* Replaced wholesale by the verified ones.

**R5. History stays auditable.** The retired entry's keys, fingerprints,
reason and unapplied revocations move to `previous` and to the tombstone; the
promotion transcripts of the earlier incarnation stay in storage untouched
(`core/hsm/promotions/<serial>-<at>`); the audit log keeps the original
`hsm.member_added`, `hsm.member_promoted`, `hsm.member_retired` events.

**R6. Pending revocations of the old incarnation are closed, not applied.**
They name auth-key ids that died with the reset, and `revoke_node` already
skips retired members (`pool_admin.rs:813-815`), so a retired device keeps its
node credentials until reset. R3 is what makes closing them safe: new keys
prove a reset, and a reset deletes every auth key. They are copied to
`unapplied_revocations` and into the audit event, never silently dropped.

**R7. Reasons, and what is tombstoned.** Retire gains `--reason replaced|lost|
compromised` (route field `reason`, default `replaced`; recorded as
`retire_reason`). The reason is **required evidence of a deliberate retire
under this build and is otherwise informational**: every reason may re-enter
(Decision 1), because the device is not the problem, its old keys are. What is
tombstoned is the **old incarnation's keys and fingerprints** (R3), forever:
a `compromised` device that is reset comes back with new keys and is a new
incarnation; the old keys can never be accepted again. A record retired before
this feature has no reason and **cannot re-enter** (Decision 4); `recover`
(`recovery_ceremony.rs:513-514`) sets `lost` on the members it retires.

**R8. Failure to attest leaves nothing behind.** The existing rollback in
`add_member_on` deletes node auth keys it created when any later step fails
(`pool_admin.rs:999-1007`); re-entry reuses that path and adds one thing: the
record is only superseded in the same `store_record` call that inserts the new
member, after the tombstone exists.

## Epoch and wrap copies

- **Wrap keys.** The fresh device only holds the config's default ids after
  `provision`. `ensure_wrap_keys` creates the **current epoch's** pair, and
  `rotating_to`'s pair if a rotation is in flight, with the exact capability
  mask and refuses a pre-existing key whose capabilities differ
  (`pool_admin.rs:944-949`, `:480-499`). This is what `add` already does for a
  device provisioned after a rotation; re-entry changes nothing here.
- **Copies.** The member enters `joining`. Repair's `plan` sees it as a target
  with no copy and adds one to the KEK and every custody set, paced by
  `repair_rate` (`repair.rs:41`, `pool_admin.rs:1177-1260`); the recovery copy
  is sealed to `recovery_pub`, not to a device, so it is untouched.
- **Promotion.** Joining → active when it holds every set and every set was
  scanned, by an admin-credentialed repair with a witness active member's
  credential; both identities sign a transcript (`pool_admin.rs:1310-1327`,
  `:1450-1505`). `rotate-epoch` is refused while a member is joining
  (`pool_admin.rs:548-549`); the swap sequence below finishes promotion first.
- **`min_wrap_copies = 2` and the pool of one.** Retiring an active member is
  refused when fewer than `min_wrap_copies` others would remain
  (`pool_admin.rs:1053-1059`). A swap runs on one device between the retire
  and the promotion, so with `min_wrap_copies = 2` and no recovery key the
  operator either sets `min_wrap_copies = 1` on every node first, as
  `docs/hsm.md` says today, or (Decision 2) passes `member retire
  --allow-below-min-copies`: sudo, audited, and scoped to that one retire. It
  bypasses **only** the `min_wrap_copies` check at `pool_admin.rs:1053-1059`;
  the last-active-member, stranded-set and pool-of-one-acknowledgement guards
  (`seal/hsm.rs:568-585`, a per-node config value) stay. The retire event
  records `below_min_copies=true`. While the pool runs on one device, nodes
  still configured with `min_wrap_copies = 2` cannot create **new** custody
  keys (a wrap must reach two copies); unseal and reads are unaffected.

### Rolling procedure: retire, reset, re-enter — chosen

Two shapes were weighed:

| Shape | Verdict |
|---|---|
| **Retire A → reset → `member reenter` A → repair → promote → repeat for B** | **Chosen.** No new limit, no new state, one new command. The pool has a live active member (B) at every instant, so it stays unsealable. |
| Add the re-provisioned device back **before** retiring the other (three live members) | **Rejected.** A and A′ are the *same* `HsmId`, so "add A′ while A is still a member" is not a third member but the same key twice; the two-live-member cap (`MAX_POOL_MEMBERS = 2`, `hsm/mod.rs:282`; R3 of the pool-of-one decision) would have to be lifted to give no benefit, because A is physically gone the moment it is reset. |
| A dedicated `member reprovision` that retires and re-enters in one call | **Rejected.** The reset is a physical step between the two halves and cannot be made atomic with them; a single call would either hold a ceremony open across a hardware reset or hide the pool-of-one window. Two explicit commands keep the window visible in status and audit. |

Per member, never both at once (`hsm-a` first, then `hsm-b` from `hsm-a`'s
promoted incarnation):

```text
0. once: acknowledgement on every node if recovery = "none"; repair --run;
   under_replicated = 0; both members active
1. member retire hsm-a --reason replaced --allow-below-min-copies   (refused if any set lacks a copy on hsm-b)
2. repair --run                              (drops hsm-a's copies)
3. physically reset hsm-a; provision with this build; start its gateway
4. member reenter hsm-a --bundle a2.json --gateway https://… --admin hsm-a
5. repair --run; repair --run --admin hsm-a --admin hsm-b   (copies, then promotion)
6. verify: hsm-a active, incarnation 2, admin_capabilities clean, under_replicated 0
7. repeat 1–6 for hsm-b, with hsm-a as the witness
```

## The pool stays unsealable; failure and rollback

During steps 1–5, hsm-b is `active` and holds a copy of every set (retire
checks this, `pool_admin.rs:1060-1087`); every node unseals through it. The
only moment the pool depends on one device is the whole window, so:

| Failure | State | Way out |
|---|---|---|
| `retire` refused | nothing changed | fix what it names (run repair, lower `min_wrap_copies`) |
| Reset device never comes back (dead, lost, wrong firmware) | hsm-a retired, pool of one on hsm-b, `hsm.pool_not_redundant` and `bv_hsm_pool_redundancy{level="none"}` raised | the retired entry does not count toward the cap (`pool_admin.rs:917`): add a **different** device with the ordinary `member add`. Or leave the pool of one. If hsm-b also fails: `recover` needs the recovery key, which can only be chosen at init, so a `recovery = "none"` pool has **no** way back — the existing, loudly stated pool-of-one risk |
| Operator changes mind after the retire, device not reset | hsm-a retired, keys unchanged | `member reenter` refuses (R3: same keys). Reset and re-provision it, or `add` another device. There is deliberately no "un-retire" (Decision 3) |
| `reenter` fails midway (attestation, device error, storage) | tombstone may exist; record unchanged; auth keys created on the device are deleted (R8) | fix the cause and re-run; idempotent |
| `reenter` succeeded but repair cannot fill (hsm-b unreachable) | hsm-a `joining`, holds no copy; hsm-b still the only copy holder | restore hsm-b's link; repair resumes (5-minute tick, member-up trigger, `hsm-pool-ha.md` § Degraded operation) |
| hsm-b fails during the window | pool lost unless a recovery key exists | the same risk as any pool of one; the runbook says to check the recovery copy before step 1 |

Never reset a device **before** its `retire` succeeded: retire's guards are what
prove hsm-b holds every copy.

## Operator surface

- **Route (`v2` only; `v1` is frozen).** `POST v2/sys/hsm/members/{name}/reenter`,
  sudo (covered by the existing root path `hsm/members/*`,
  `system/mod.rs:1696`), body `bundle`, `gateway`, `admin_credentials`, same
  field shapes as `members/{name}`. A dedicated path rather than a flag on
  `members/{name}`, so a policy can allow `add` without `reenter` and a typo
  cannot turn one into the other. `members/{name}/retire` gains optional
  `reason`. `GET v2/sys/hsm/members` and `v2/sys/hsm/status` add per member
  `incarnation`, `retire_reason`, and `previous` (keys' fingerprints, never
  secrets), at `seal/hsm.rs:1150-1169`.
- **CLI.** `bvault operator hsm member reenter <name> --bundle <file>
  --gateway <url> --admin <name>` (the same flags as `member add`), and
  `member retire <name> [--reason replaced|lost|compromised] [--allow-below-min-copies]`.
- **GUI** (`gui/src/routes/HsmStatusPage.tsx`, `PoolMembersCard`, `:102-135`):
  read-only. An **Incarnation** column, a *re-entered* note and the previous
  incarnations under a member, and for a retired member whose reason allows
  it a hint with the CLI command (the page has no mutating controls today and
  gains none, as the admin credential never belongs in the browser).
- **Docs.** `docs/api.md` (the `members/{name}/reenter` route, the `reason`
  and `incarnation` fields); `docs/cli-reference.md` (`member reenter`, the
  `--reason` flag); `docs/hsm.md`, rewrite "Give an existing pool the drain's
  bv-admin" (`:564-614`): drop "a device that was ever a member cannot rejoin"
  and the two-spare-devices requirement, keep the `min_wrap_copies` and
  acknowledgement paragraph, give the rolling procedure above and keep the
  spare-device route as the alternative when no downtime window for a
  pool of one is acceptable; `features/hsm-pool-ha.md` (§ Pool membership,
  § Persisted formats, § Failure modes, a one-line pointer here).

## Test plan (mock, `cargo nextest run -p bv-core --lib --features hsm_mock,hsm_yubihsm2`)

Happy path and ordering:

1. Retire → repair → reset the mock device (the mock's factory reset, same
   serial) → `provision` → `member reenter` → repair → promote: member active
   with `incarnation = 2`, every set holds a copy opened by the *new* keys,
   the old copy is gone, the pool unseals on a node that only knows the new
   credential.
2. Both members swapped one after the other; at every step a fresh node
   unseals through the other member.
3. A rotation epoch with non-default wrap ids: the re-entered device gets the
   current epoch's ids; `rotating_to` in flight is refused or handled as
   `add` does.
4. Node credentials: pickup replaces the old `hsm_id` credential; a revoked
   node's stale `auth_keys[hsm_id]` and `signatures[hsm_id]` are gone; a node
   revoked before re-entry gets no key on the new device.

Refusals (each asserts the record, enrollments and deliveries are unchanged):

5. `member add` of a retired id still refuses and names `reenter`.
6. `reenter` of: an unknown id, an `active` or `joining` member, a member
   retired before this feature (no reason); a `compromised`-retired device
   with fresh keys is **accepted**, and its old keys are refused afterwards.
7. **Replay:** the old bundle and the same device un-reset (same keys): refused
   by R3; a bundle whose attestation does not verify, whose serial differs from
   the device reached, or whose challenge fails: refused.
8. A set that still holds a copy for the id (repair not run): refused;
   barrier sealed or absent: refused.
9. Retire guards unchanged: last active member, `min_wrap_copies`, stranded
   set, unacknowledged pool of one; `--allow-below-min-copies` bypasses only
   the `min_wrap_copies` one, is audited, and a nonsudo caller is refused.
10. Failure injection in `add_member_on` after the device keys are created:
    auth keys rolled back, record not superseded, tombstone idempotent on
    retry.

Persisted-format and malformed-input:

11. **Old-record fixture** captured from the current code: a v2 record with a
    retired member decodes with `incarnation = 1`, `retire_reason = None`,
    `previous = []`, encodes back byte-for-byte when nothing changed.
12. New record read by a copy of the current decoder (struct without the new
    fields): decodes and unseals; a rewrite drops only the history, and the
    tombstones still make the replay check refuse.
13. Malformed: `incarnation = 0`, `previous` entry with a repeated incarnation
    or a number above the current one, duplicate `previous` keys, empty key
    material, a tombstone for a missing record: all refused by `validate`.
14. Audit: `hsm.member_reentered` carries the old and new fingerprints, the
    incarnations and the actor, and no key material or credential
    (`pool_status_reports_members_and_never_secrets` extended).
15. Retire's `reason` round-trips; `recover` sets `lost`.

GUI: a `HsmStatusPage` vitest for the incarnation column and the previous
list (`cd gui && npx tsc --noEmit && npx vitest run src/routes/HsmStatusPage.test.tsx`).

Gates: `cargo fmt -p bv-core`; `make check-hsm` (the change is under
`crates/bv-core/src/hsm/` and the seal); `make test-changed`; `make
test-release` before merge (persisted format and seal).

## What stays unverified on hardware

Nothing is run against a device in this work. The operator validates in
production, and these are the claims that need a real YubiHSM 2:

1. That a physical factory reset followed by `provision` yields **new**
   `bv-identity`, `bv-authz` and `bv-seed-ecdh` keys, and so new attestation
   fingerprints, for the same serial (R3 rests on it).
2. That the device's factory attestation key survives the reset, so the pinned
   Yubico chain verifies the new attestations.
3. That a reset removes every `bv-node-*` authentication key (R6 rests on it).
4. That the connector, gateway and node sessions pick up the new incarnation
   (the nodes' SCP03 sessions to the old one fail and re-open) without a node
   restart, and what an in-flight session to the reset device does.
5. Timing of repair filling a re-entered device under `repair_rate`.
6. The retire guard refusing at `min_wrap_copies = 2` on the two-device pool.

## Decisions by the operator (2026-11-09)

1. **Every reason may re-enter.** The serial is never tombstoned; the old
   incarnation's keys and fingerprints are (R3, R7).
2. **`member retire --allow-below-min-copies`** is added: sudo, audited,
   scoped to that retire, bypassing only the `min_wrap_copies` check.
3. **No un-retire.** A retired device that was never reset needs a reset first
   (R3 refuses its unchanged keys).
4. **A record retired before this feature cannot re-enter** (no recorded
   reason). The first swap therefore retires with this build.
   *Reading to confirm:* this is taken as "refuse legacy-retired records",
   compatible with Decision 1 because reasons gate nothing else.
5. **Same name only.**

## Tracking text (to land with the implementation, not before)

`ROADMAP.md` T478 stays `[ ]` until the work is delivered. When it ships,
`CHANGELOG.md` `[Unreleased]` → `### Added`, under
`#### HSM pool: re-enter a reset device`:

```markdown
- **Rejoin a retired HSM pool member after a reset and a fresh `provision`, under the same serial** (T478, S116, S114)
  -- `bvault operator hsm member reenter <name>` (`POST v2/sys/hsm/members/<name>/reenter`, sudo, the device's bv-admin credential) adds a retired member's reset device back as a new incarnation: it is attested again through the pinned Yubico chain, its new keys are pinned, its wrap copies and node credentials are made afresh and none of the old incarnation's are trusted, and the old incarnation's keys, fingerprints and pending revocations stay in the record and in an append-only tombstone. A device that was not reset (same keys) is refused. `member retire` takes `--reason replaced|lost|compromised`; every reason may re-enter, the old incarnation's keys never again, and `--allow-below-min-copies` retires below `min_wrap_copies` for one audited ceremony. `member add` still refuses a retired serial. The seal record gains optional `incarnation`, `retire_reason` and `previous` fields (read-old/write-new, no version bump). A two-device pool can now be moved to a `bv-admin` that delegates `get-log-entries` one member at a time with no spare device; the pool runs on one device between the retire and the promotion. Verified with the mock only.
```
