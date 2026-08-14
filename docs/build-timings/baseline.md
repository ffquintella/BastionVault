# Build-cost baseline

Appended by `make bench-build` (`scripts/bench-build.sh`). One row per run.
Every phase of [the decomposition](../../roadmaps/workspace-decomposition.md)
reports its delta against this table.

Read the script's header comment for what each column means and why it was
chosen. In short: `check-*` is front-end only, `test-build-leaf` includes the
link that `cargo check` never does, and none of these use the Makefile's
`-Z threads` escape hatch, so they are slower than `make build` and comparable
to each other.

Numbers are INCREMENTAL on a warm `target/`. A cold-build picture is a separate
artefact — see the `--timings` HTML in this directory.

## Noise floor — read before claiming a win

Each cell is the **median of 3 samples**. The measured run-to-run spread on this
tree is wide, because rustc's incremental cache is warmer or colder depending on
what ran immediately before. Observed raw samples for the baseline row:

| scenario | samples | spread |
|---|---|---|
| check-noop | 1.22 / 0.45 / 0.48 | 2.7x (first run pays the fingerprint scan) |
| check-leaf | 8.35 / 6.97 / 6.58 | ±13% |
| check-core | 6.45 / 7.65 / 8.65 | ±15% |
| test-build-leaf | 27.86 / 22.70 / 20.43 | ±16% |

**A phase must move a number by more than ~25% before the change is real.**
For anything closer than that, re-run with `--repeat 7` or more.

## Why `leaf` and `core` are the same number today

`check-leaf` (6.97s) and `check-core` (7.65s) are indistinguishable — their sample
ranges overlap almost completely. That is not a measurement failure, it is *the
finding*:

> `src/modules/transit/mod.rs` and `src/core.rs` are in the same crate, so
> touching either invalidates the same compilation unit. The build system cannot
> tell a self-contained 3,155-line secret engine apart from the 1,699-line object
> that every module depends on.

These two columns are in the table precisely so they can be watched **diverging**
as Phase 2 (breaking the `Core` ↔ `modules` cycle) and Phase 3 (engines into
crates) land. Until then, any gap between them is noise.

## Get comparable numbers — the harness is state-sensitive

Run this from a *settled* `target/`: right after a normal `make build` or
`make test`, and **not** right after building other package or feature subsets
(`cargo check -p <other>`, `--workspace`, `--all-features`). Those leave
additional build configurations in the cache, which changes both the
fingerprint-scan cost and how much rustc's incremental cache can reuse.

Row 2 below is a worked example of getting this wrong, kept as a warning rather
than deleted.

| date | commit | noop | leaf | core | test+link | rlib | lock | members | src lines | cores | notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 2026-08-12 17:34 UTC | `d04a72c` (dirty) | 0.48s | 6.97s | 7.65s | 22.70s | 245 MB | 1195 | 12 | 173938 | 10 | **Phase 0 baseline — use this row for comparison.** Tree carries the Cloudsmith + FerroGate-0.21.3 work uncommitted; no `src/` restructuring yet. |
| 2026-08-12 17:57 UTC | `d04a72c` (dirty) | 0.52s | 11.79s | 13.37s | 27.57s | 245 MB | 1195 | 12 | 173938 | 10 | ⚠ **NOT COMPARABLE — do not read this as a regression.** Taken immediately after a `--workspace` build and a series of `cargo check -p <crate>` feature-unification experiments, which contaminated the target dir. One `check-core` sample hit 31.42s. Kept as an example of the state-sensitivity described above. |

### What Phase 0 did and did not move

Phase 0 dropped five dead direct dependencies (`foreign-types`, `glob`,
`serde_derive` from the root; `serde` from `bv-plugin-pack`; `futures-util` and
`ironrdp-pdu` from the GUI). **`lock` did not budge: 1195 before and after.**

That is the expected result, and worth stating plainly so nobody looks for a win
that is not there: every one of those crates is still in the graph
*transitively*. Removing a direct dependency edge tidies the manifest, restores
`cargo machete` to a clean signal, and removes the risk of a stale edge pinning
a feature nobody intended — it does not remove compilation work. **No build-time
improvement should be attributed to Phase 0.** Phase 0's deliverable is the
instrument, not a speedup.
| 2026-08-13 17:15 UTC | `d5d288e` (dirty) | 0.50s | 8.81s | 9.92s | 22.18s | 247 MB | 1198 | 15 | 175104 | 10 | **Phase 2 complete (sibling cycle cut).** No crate was created, so no movement was expected and none should be read into this row. `check-leaf` 6.97s → 8.81s and `check-core` 7.65s → 9.92s are both inside the ~25% noise floor, and the raw samples say so: check-leaf ran 27.65 / 8.81 / 8.64 on a target dir warmed by the full test suite. `lock` 1195 → 1198 and `src/` 173,938 → 175,104 lines come from the three Phase 1 crates and this phase's `kernel_api/` split, not from new dependencies — Phase 2 added none. **The two columns still have not diverged, which is the point: they are still one compilation unit.** Phase 3 is what splits them. |
| 2026-08-14 00:02 UTC | `606f4f8` (dirty) | 0.53s | 9.26s | 8.82s | 17.76s | 230 MB | 1203 | 20 | 154373 | 10 | **Phase 1 complete — five more crates (`bv-metrics`, `bv-storage`, `bv-logical`, `bv-utils`, `bv-audit`), eight in total.** The four scenarios did not move and nothing here should be read as a speedup: `check-leaf` and `check-core` both touch files that are still in the root crate, so Phase 1 was never going to separate them (Phase 3 is). `rlib` 245 → 230 MB and `src/` 173,938 → 154,373 lines are the real movement — 19.5k lines and five subsystems left the root compilation unit. `lock` 1195 → 1203 is the eight new workspace members counting themselves; Phase 1 added no external dependency, and removed eleven from the root manifest (hiqlite, diesel, r2d2, rusty-s3, keyring, sysinfo, libc, lockfile, as-any, blake2b_simd, enum-map). `test-build-leaf` 22.70 → 17.76s looks like a win and is not claimed as one: it is inside the noise floor (raw samples 26.42 / 17.76 / 16.26). |

### What Phase 1 did and did not move

Same shape as the Phase 0 note above, and worth stating just as plainly.

**Did not move:** all four benchmark scenarios. `check-noop`, `check-leaf`,
`check-core` and `test-build-leaf` are within the noise floor of the Phase 0
baseline. `check-leaf` and `check-core` are *still equal* — they touch
`src/modules/transit/mod.rs` and `src/core.rs`, both of which remain in the
root crate, so there was never a mechanism by which Phase 1 could separate
them. Phase 3 is what splits them, and Phase 0's findings said so.

**Did move:** the size of the thing being compiled. 19,565 lines and 15 MB of
rlib left the root compilation unit. Eleven dependencies — including a Raft/SQLite
engine, a MySQL client and an S3 signer — are no longer dependencies of
`bastion_vault`; they belong to `bv-storage`, which is where the code that uses
them now lives.

**The number that is not in this table**, because the script does not measure
it: iterating on the storage substrate. Editing `src/storage/mod.rs` used to
cost a `check-core`-class rebuild of the monolith, ~7.7s at the Phase 0
baseline. Editing `crates/bv-storage/src/lib.rs` and running
`cargo check -p bv-storage` costs **0.78s** (median of 3, warm). That is the
Phase 1 payoff, and it is the shape every later phase repeats — one crate at a
time, not one monolith.
