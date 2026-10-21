# SQL policy capabilities (T124, subsystem 1) implementation plan

> For agents: use `subagent-driven-development` (recommended) or `executing-plans` to
> implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the eleven probe-only SQL capabilities to the policy kernel, widen the share
capability type to hold them, and prove with the existing Kani and differential suites that
deny supremacy, fail-closed default and qualifier soundness still hold.

**Architecture:** The SQL bits sit beside the existing `connect` bit in the single
`Capability` enum, so `deny` and fail-closed logic stay in one evaluator. They map to no
`Op`, so `check` never accepts them for a read, write, list or delete. The share type
`ShareCap` moves from `u8` to `u16` to hold the same names. Nothing here changes how a
request is routed; the resolver, `PolicyGate::sql_privileges`, the ABI and the GUI are
later subsystems.

**Tech stack:** Rust, `strum` (enum string mapping), `serde`, Kani (`bv-policy-core`
proofs), the differential suite in `crates/bv-kernel/src/modules/policy/differential`.

**Spec:** [features/sql-browser.md](../../features/sql-browser.md) §3.1, §9.1 and the Phase 0
appendix (decisions D1 and D4). Executors read both.

## Global constraints

- Eleven variants, `sql_select` … `sql_script`, bits `1 << 10` … `1 << 20`, spelled as in
  §9.1; `Capability` stays a `u32` bitmap (`crates/bv-kernel/src/modules/policy/policy.rs:181`).
- Probe-only: no `Op` maps to an SQL bit; no SQL bit is implied by any other bit (§3.1).
- `deny` wins over every SQL bit on enforcement (§3.1, T119 `t1_deny_wins_on_enforcement`).
- Deny supremacy, fail-closed default and qualifier soundness hold for the new bits
  unchanged (§9.1).
- Share capabilities widen from `u8` to `u16`; all existing share names keep their values.
- D4: a policy naming `sql_*` is refused on write until the cluster gate exists. This plan
  does not add the gate; subsystem 4 does. Until then, nothing from this plan is released
  alone (see Review focus 1).
- Kani and the differential suite run over the new bits before the plan is complete.

## Review focus

1. **A policy with `sql_*` on an old node.** An unknown name makes `hcl::from_body` fail and
   refuses the whole policy (`policy.rs:327`, field `policy.rs:141`). Expected: an old node
   refuses the policy with a clear error, never grants partially. Test: Task 1 parses a
   policy with `sql_select` and asserts the error names the capability, and Task 4 asserts
   that the rest of the policy is not loaded.
2. **Bit collision.** A new bit that equals an existing `CAP_*` value would grant the wrong
   right. Test: Task 1 asserts all eleven SQL bits are distinct, lie in `1 << 10 ..= 1 << 20`,
   and do not overlap any `CAP_*` in `bv-policy-core/src/lib.rs:64-82`.
3. **SQL-only grant allows a plain read.** Expected: a grant of `sql_select` alone does not
   allow `Op::Read` on the same path. Test: Task 3, `decide` over a `sql_select` rule
   returns `Deny` for a read.
4. **Persisted shares.** Share records are stored as name lists (`share_store.rs:857`,
   `ALLOWED`), not as bitmaps, so widening `ShareCap` should not change stored data. Expected:
   an existing share record with `read` or `connect` loads unchanged. Test: Task 2 round-trips
   a fixture of the four existing names.
5. **Deny on a SQL path.** Expected: `deny` on `resources/resources/<r>/sql/*` blocks
   `sql_select` on any object under it, even when a narrower grant exists. Test: Task 3.

## Task 1: SQL capability variants and bits

**Tier:** complex (architect) — authorization vocabulary, §7 high-risk area.

**Files:**
- Modify: `crates/bv-kernel/src/modules/policy/policy.rs:181-202` (the `Capability` enum)
- Modify: `crates/bv-policy-core/src/lib.rs:64-82` (new `CAP_SQL_*` constants)
- Test: `crates/bv-kernel/src/modules/policy/policy.rs` (in-file `#[cfg(test)]` module)

**Interfaces:**
- Consumes: the existing `Capability` derives (`EnumString`, `EnumIter`, `Serialize`,
  `Deserialize`, `#[repr(u32)]`) and `rename_all = "lowercase"`.
- Produces: `Capability::SqlSelect = 1 << 10`, `SqlInsert = 1 << 11`, `SqlUpdate = 1 << 12`,
  `SqlDelete = 1 << 13`, `SqlAlter = 1 << 14`, `SqlCreate = 1 << 15`, `SqlDrop = 1 << 16`,
  `SqlExecute = 1 << 17`, `SqlAdmin = 1 << 18`, `SqlExport = 1 << 19`, `SqlScript = 1 << 20`;
  `bv_policy_core::CAP_SQL_SELECT … CAP_SQL_SCRIPT: u32` with the same values.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn sql_capabilities_have_spec_names_and_disjoint_bits() {
    assert_eq!(Capability::from_str("sql_select").unwrap(), Capability::SqlSelect);
    assert_eq!(Capability::SqlSelect.to_bits(), 1 << 10);
    assert_eq!(Capability::SqlScript.to_bits(), 1 << 20);
    let all: Vec<u32> = [
        Capability::SqlSelect, Capability::SqlInsert, Capability::SqlUpdate,
        Capability::SqlDelete, Capability::SqlAlter, Capability::SqlCreate,
        Capability::SqlDrop, Capability::SqlExecute, Capability::SqlAdmin,
        Capability::SqlExport, Capability::SqlScript,
    ].iter().map(|c| c.to_bits()).collect();
    let mut seen = 0u32;
    for bit in &all {
        assert_eq!(bit.count_ones(), 1);
        assert_eq!(seen & bit, 0);
        seen |= bit;
    }
    assert_eq!(bv_policy_core::CAP_SQL_SELECT, 1 << 10);
    assert_eq!(bv_policy_core::CAP_CONNECT & seen, 0);
}
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `cargo nextest run -p bastion_vault --lib sql_capabilities_have_spec_names`
Expected: FAIL, `no variant named SqlSelect`. (Run from the repository root; this is the
root crate's lib test. `cargo nextest run -p bv-policy-core --lib` covers the constants.)

- [ ] **Step 3: Add the eleven variants and the matching `CAP_SQL_*` constants**

Add the variants in §3.1 order after `Connect = 1 << 9`, each with
`#[strum(to_string = "sql_select")]` etc. Add the constants to `bv-policy-core/src/lib.rs`
after `CAP_CONNECT`, each with a doc line naming the spec section. The enum stays
`#[repr(u32)]`; no `Op` mapping is added. Keep `Capability::to_bits` unchanged.

- [ ] **Step 4: Run the test and confirm it passes**

Run: `cargo nextest run -p bastion_vault --lib sql_capabilities_have_spec_names`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/bv-kernel/src/modules/policy/policy.rs crates/bv-policy-core/src/lib.rs
git commit -m "feat(policy): add the eleven SQL capabilities as probe-only bits"
```

## Task 2: widen `ShareCap` to `u16`

**Tier:** complex (architect) — share evaluation is authorization, and the Kani harnesses
are over the old width.

**Files:**
- Modify: `crates/bv-policy-core/src/model.rs:275-293` (`ModelCaller.shares`, `share_bit`)
- Modify: `crates/bv-policy-core/src/gate.rs:44-72` (`ShareCap`, `share_capability`)
- Modify: `crates/bv-policy-core/src/proofs.rs:430` (`target: u8` → `u16`)
- Test: `crates/bv-policy-core/src/gate.rs` (in-file tests) and a fixture test in
  `crates/bv-kernel/src/modules/identity/share_store.rs`

**Interfaces:**
- Consumes: `ShareCap` as declared (`Read`, `List`, `Update`, `Delete`).
- Produces: `pub const fn share_bit(cap: ShareCap) -> u16`; `ModelCaller.shares: u16`;
  `ShareCap` gains the eleven variants `SqlSelect` … `SqlScript`, so 15 in total. The
  existing four keep `1 << 0` … `1 << 3`; the new ones take `1 << 4` … `1 << 14`. The mapping
  is fixed by a test, not by arithmetic in two places. Open finding, not in this plan:
  `share_store.rs:857` already accepts `create` and `connect` in `ALLOWED`, but `ShareCap`
  models neither. Resolving that is a separate decision.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn share_bits_fit_u16_and_keep_existing_values() {
    assert_eq!(share_bit(ShareCap::Read), 1 << 0);
    assert_eq!(share_bit(ShareCap::Delete), 1 << 3);
    let max = [ShareCap::SqlScript].iter().map(|c| share_bit(*c)).max().unwrap();
    assert!(max <= 1 << 14);
}

#[test]
fn existing_share_record_round_trips_unchanged() {
    // fixture: the name list the share store writes today
    let names = ["read", "list", "update", "delete"];
    let caps = ShareCap::from_names(&names).unwrap();
    assert_eq!(caps.to_names(), names.to_vec());
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `cargo nextest run -p bv-policy-core --lib share_bits_fit_u16`
Expected: FAIL, `no variant named SqlScript`, and `from_names` not defined.

- [ ] **Step 3: Implement**

Widen the field and the function to `u16`, add the variants and `from_names`/`to_names` (the
inverse of the share store's name list). Update `proofs.rs:430` to `u16`. Do not change how
the share store serializes; names stay strings.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `cargo nextest run -p bv-policy-core --lib`
Expected: PASS for the new tests and every existing test in the crate.

- [ ] **Step 5: Run the Kani harnesses over the widened type**

Run: `make verify-kani`
Expected: every harness reports success. Any failure is a finding, not a test to relax.

- [ ] **Step 6: Commit**

```bash
git add crates/bv-policy-core crates/bv-kernel/src/modules/identity/share_store.rs
git commit -m "feat(policy-core): widen ShareCap to u16 for the SQL share names"
```

## Task 3: SQL bits never grant a plain operation, and deny wins on SQL paths

**Tier:** complex (architect) — evaluation semantics.

**Files:**
- Test: `crates/bv-policy-core/src/decide.rs` (in-file tests) and
  `crates/bv-kernel/src/modules/policy/differential/mod.rs:440` (mapping table entries)

**Interfaces:**
- Consumes: `decide`, `Op`, `CAP_SQL_*` from Task 1 and `ShareCap` from Task 2.
- Produces: nothing new. This task adds tests and the differential mapping rows.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn sql_select_alone_does_not_grant_read() {
    let d = decide_for(rule_caps(CAP_SQL_SELECT), Op::Read);
    assert_eq!(d, Decision::Deny);
}

#[test]
fn deny_on_sql_path_wins_over_a_narrower_grant() {
    // deny on resources/resources/r/sql/*; sql_select on .../sql/objects/def/s/t
    let d = decide_sql(
        "resources/resources/r/sql/*", CAP_DENY,
        "resources/resources/r/sql/objects/def/s/t", CAP_SQL_SELECT,
        "resources/resources/r/sql/objects/def/s/t",
    );
    assert_eq!(d, Decision::Deny);
}
```

(`decide_for` and `decide_sql` are test helpers the implementer adds next to the existing
`decide` tests, built from the existing `Query` and layer fixtures. They construct a single
rule; they do not change production code.)

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `cargo nextest run -p bv-policy-core --lib sql_select_alone`
Expected: FAIL to compile on the helpers, then, once they exist, PASS only if the existing
logic already holds. A failure here means a real defect in `check` or `decide` for the new
bits, and it is fixed in that function, not in the test.

- [ ] **Step 3: Add the differential mapping rows**

In `differential/mod.rs:440`, add one `(Capability::SqlX, bv_policy_core::CAP_SQL_X)` row per
variant, next to the `Connect` row.

- [ ] **Step 4: Run the differential suite**

Run: `make verify-differential`
Expected: the million-case differential passes with the eleven new rows. A disagreement
between the two evaluators is a bug in one of them, and must be explained before the task
closes.

- [ ] **Step 5: Commit**

```bash
git add crates/bv-policy-core crates/bv-kernel/src/modules/policy/differential/mod.rs
git commit -m "test(policy): prove SQL bits never grant plain ops and deny wins on SQL paths"
```

## Task 4: parser refusal and listing behavior

**Tier:** complex (architect) — fail-closed parsing of authorization input.

**Files:**
- Test: `crates/bv-kernel/src/modules/policy/policy.rs` (in-file tests)

**Interfaces:**
- Consumes: `Policy::from_str` (`policy.rs:251`) and `to_granting_capabilities`
  (`policy.rs` listing helper, used at `policy.rs:749-754`).
- Produces: nothing new.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn unknown_sql_like_name_refuses_the_whole_policy() {
    let hcl = r#"path "resources/resources/r/sql/*" { capabilities = ["sql_selekt"] }
                 path "secret/*" { capabilities = ["read"] }"#;
    assert!(Policy::from_str(hcl).is_err());
}

#[test]
fn sql_names_list_only_when_their_bits_are_granted() {
    let names = to_granting_capabilities(CAP_SQL_SELECT);
    assert_eq!(names, vec!["sql_select".to_string()]);
}
```

- [ ] **Step 2: Run the tests and confirm they fail or pass as specified**

Run: `cargo nextest run -p bastion_vault --lib unknown_sql_like_name`
Expected: PASS (the refusal already holds through `policy.rs:327`), and `sql_names_list…`
PASS once Task 1 exists. If the first test passes only by accident, add a second assertion
that a valid `sql_select` policy parses.

- [ ] **Step 3: Commit**

```bash
git add crates/bv-kernel/src/modules/policy/policy.rs
git commit -m "test(policy): pin SQL capability parsing refusal and listing"
```

## Task 5: slice validation

**Tier:** routine (builder) — runs commands and reports; no code.

- [ ] **Step 1: Run the crate and kernel suites**

Run: `make test-changed PKG=bv-policy-core`
Expected: PASS. Then `make test-changed PKG=bv-kernel`, expected PASS.

- [ ] **Step 2: Run the Kani and differential gates**

Run: `make verify-kani` and `make verify-differential`
Expected: both PASS.

- [ ] **Step 3: Record the result in the spec**

Append the commands run and their outcome under "Phase 1, subsystem 1" in
`features/sql-browser.md`. Do not mark T124 done: subsystems 2 to 6 remain.

## Out of scope for this plan (later subsystems)

- Qualifier resolver for `resources/resources/<R>/sql/**` and `PolicyGate::sql_privileges`
  with denial records (subsystem 2).
- ABI 1.4 host calls, grants, actor-stamped audit, lifecycle messages, multiplexed
  invocations and the SDK runner (subsystem 3).
- Resource engine `sql` protocol, `v2/sql/privileges`, MFA for `sql` profiles (subsystem 4,
  which also adds the D4 cluster write gate).
- Policy builder chips and share presets in the GUI, and the GUI SQL profile editor
  (subsystems 5 and 6).
- Full `make test-release` and the T124 close.
